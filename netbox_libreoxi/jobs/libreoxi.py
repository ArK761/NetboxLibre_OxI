from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from time import monotonic

from django.db import close_old_connections
from django.utils import timezone
from netbox.jobs import JobRunner, system_job

from ..models import LibreOXISettings
from ..oxi import fetch_device, monitored_devices
from ..scheduler import schedule_matches
from ..storage import append_log


MAX_CONCURRENT_CHECKS = 5


def _fetch_device_worker(settings, device):
    close_old_connections()
    try:
        return fetch_device(settings, device)
    finally:
        close_old_connections()


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
            matched, current_slot = schedule_matches(now, settings.schedule_cron)
        except (TypeError, ValueError):
            return

        if not matched or current_slot is None:
            return

        current_slot_ts = current_slot.timestamp()
        try:
            last_slot = float(marker.read_text(encoding="ascii").strip())
        except (FileNotFoundError, ValueError, OSError):
            last_slot = None

        if last_slot is not None and last_slot >= current_slot_ts:
            return

        try:
            marker.write_text(str(current_slot_ts), encoding="ascii")
        except OSError:
            pass

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
        with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CHECKS, thread_name_prefix="libreoxi") as executor:
            futures = [executor.submit(_fetch_device_worker, settings, device) for device in devices]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result.get("ok"):
                        counts["CHANGE" if result.get("changed") else "NOCHANGE"] += 1
                    else:
                        counts["ERROR"] += 1
                except Exception as exc:
                    counts["ERROR"] += 1
                    append_log(settings.storage_root, f"ERROR scheduled device check failed: {exc}")

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
