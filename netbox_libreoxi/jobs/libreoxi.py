from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from django.db import close_old_connections
from django.utils import timezone
from netbox.jobs import JobRunner, system_job

from ..models import LibreOXISettings
from ..oxi import fetch_device, monitored_devices
from ..scheduler import schedule_slot
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
        marker = root / ".last_refresh"
        now = timezone.now()
        current_slot, _next_slot = schedule_slot(now, settings.check_interval_minutes)
        current_slot_ts = current_slot.timestamp()

        try:
            last_slot = float(marker.read_text(encoding="ascii").strip())
        except (FileNotFoundError, ValueError, OSError):
            # Behave like cron: do not run immediately just because NetBox was
            # restarted. The first scheduled run is the next wall-clock slot.
            try:
                marker.write_text(str(current_slot_ts), encoding="ascii")
            except OSError:
                pass
            return

        if last_slot >= current_slot_ts:
            return

        try:
            marker.write_text(str(current_slot_ts), encoding="ascii")
        except OSError:
            pass

        devices = list(monitored_devices(settings))
        append_log(
            settings.storage_root,
            f"INFO scheduled refresh started devices={len(devices)} concurrency={MAX_CONCURRENT_CHECKS}",
        )

        with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CHECKS, thread_name_prefix="libreoxi") as executor:
            futures = [executor.submit(_fetch_device_worker, settings, device) for device in devices]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    append_log(settings.storage_root, f"ERROR scheduled device check failed: {exc}")

        append_log(settings.storage_root, "INFO scheduled refresh finished")
