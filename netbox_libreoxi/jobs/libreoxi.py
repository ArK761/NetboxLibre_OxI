from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from pathlib import Path
from time import monotonic

from django.db import close_old_connections, connections
from django.utils import timezone
from netbox.jobs import JobRunner, system_job

from ..models import LibreOXISettings
from ..oxi import fetch_device, monitored_devices
from ..scheduler import latest_slot
from ..storage import append_log


MAX_CONCURRENT_CHECKS = 5
RUN_BUDGET_SECONDS = 240  # below NetBox's RQ_DEFAULT_TIMEOUT (300 s), so the job ends by itself
CATCH_UP_SECONDS = 1800


def _fetch_device_worker(settings, device):
    close_old_connections()
    try:
        return fetch_device(settings, device)
    finally:
        connections.close_all()  # this thread's own connections; they would otherwise outlive the thread


@system_job(interval=1)
class LibreOXIRefreshJob(JobRunner):
    class Meta:
        name = "LibreOXI configuration refresh"

    def run(self, *args, **kwargs):
        settings = LibreOXISettings.objects.first()
        if not settings or not settings.enabled or not settings.librenms_url or not settings.api_token_encrypted:
            return

        root = Path(settings.storage_root).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        marker = root / ".last_cron_slot"
        now = timezone.now()

        try:
            current_slot = latest_slot(now, settings.schedule_cron)
        except (TypeError, ValueError):
            return
        if current_slot is None:
            return

        current_slot_ts = current_slot.timestamp()
        # A slot that was missed (the job did not run in its minute, a run was killed) is still run later,
        # but only within CATCH_UP_SECONDS; an older one is dropped in favour of the next slot.
        if now.timestamp() - current_slot_ts > CATCH_UP_SECONDS:
            return
        try:
            last_slot = float(marker.read_text(encoding="ascii").strip())
        except (FileNotFoundError, ValueError, OSError):
            last_slot = None

        if last_slot is not None and last_slot >= current_slot_ts:
            return

        try:
            self._refresh(settings, current_slot)
        finally:
            # Written when the run ends (also after an error), not before it: a run that is killed
            # (e.g. netbox-rq restarted) leaves the slot open, so the next minute repeats it.
            try:
                marker.write_text(str(current_slot_ts), encoding="ascii")
            except OSError:
                pass

    def _refresh(self, settings, current_slot):
        devices = list(monitored_devices(settings))
        started_at = timezone.now()
        started_monotonic = monotonic()
        append_log(
            settings.storage_root,
            f"INFO scheduled refresh started run={started_at.isoformat(timespec='seconds')} "
            f"slot={current_slot.isoformat(timespec='minutes')} devices={len(devices)} "
            f"concurrency={MAX_CONCURRENT_CHECKS}",
        )

        counts = {"CHANGE": 0, "NOCHANGE": 0, "ERROR": 0}
        executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CHECKS, thread_name_prefix="libreoxi")
        try:
            futures = [executor.submit(_fetch_device_worker, settings, device) for device in devices]
            try:
                for future in as_completed(futures, timeout=RUN_BUDGET_SECONDS):
                    try:
                        result = future.result()
                        if result.get("ok"):
                            counts["CHANGE" if result.get("changed") else "NOCHANGE"] += 1
                        else:
                            counts["ERROR"] += 1
                    except Exception as exc:
                        counts["ERROR"] += 1
                        append_log(settings.storage_root, f"ERROR scheduled device check failed: {exc}")
            except FuturesTimeout:
                unfinished = [future for future in futures if not future.done()]
                counts["ERROR"] += len(unfinished)
                append_log(
                    settings.storage_root,
                    f"ERROR scheduled refresh exceeded {RUN_BUDGET_SECONDS}s, {len(unfinished)} device(s) skipped",
                )
        finally:
            # Never wait for a stuck device: queued checks are cancelled, running ones end by their own
            # request limits. A `with` block would wait here and could block the worker forever.
            executor.shutdown(wait=False, cancel_futures=True)

        finished_at = timezone.now()
        duration_seconds = max(0, int(round(monotonic() - started_monotonic)))
        append_log(
            settings.storage_root,
            "INFO scheduled refresh finished "
            f"run={started_at.isoformat(timespec='seconds')} "
            f"slot={current_slot.isoformat(timespec='minutes')} "
            f"started={started_at.isoformat(timespec='seconds')} "
            f"finished={finished_at.isoformat(timespec='seconds')} "
            f"devices={len(devices)} "
            f"change={counts['CHANGE']} "
            f"nochange={counts['NOCHANGE']} "
            f"error={counts['ERROR']} "
            f"duration={duration_seconds}",
        )


@system_job(interval=1)
class LibreOXIAuditMailJob(JobRunner):
    class Meta:
        name = "LibreOXI audit e-mail"

    def run(self, *args, **kwargs):
        from .. import audit

        settings = LibreOXISettings.objects.first()
        if not settings or not settings.audit_email_enabled or not audit.recipients(settings):
            return
        due = audit.scheduled_period(settings, timezone.now())
        if due is None:
            return
        slot, since, until, label = due
        # Log entries are always in English, whatever language is chosen for the audit.
        period = f"{since.isoformat(timespec='minutes')}..{until.isoformat(timespec='minutes')}"
        # Mark the slot first so that a slow or failing SMTP server does not
        # cause the same audit to be sent again every minute.
        audit.write_last_sent(settings, slot)
        try:
            result = audit.send_audit(settings, list(monitored_devices(settings)), since, until, label)
        except Exception as exc:
            append_log(settings.storage_root, f"ERROR audit e-mail failed period={period}: {exc}")
            return
        if result["sent"]:
            append_log(
                settings.storage_root,
                f"INFO audit e-mail sent period={period} changes={result['total']} "
                f"to={','.join(audit.recipients(settings))}",
            )
        else:
            append_log(settings.storage_root, f"INFO audit e-mail not sent period={period}: {result.get('reason_en', result['reason'])}")
