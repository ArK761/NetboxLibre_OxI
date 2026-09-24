from __future__ import annotations

import time

from netbox.jobs import JobRunner, system_job

from ..models import LibreOXISettings
from ..oxi import fetch_device, monitored_devices
from ..storage import append_log


@system_job(interval=1)
class LibreOXIRefreshJob(JobRunner):
    class Meta:
        name = "LibreOXI configuration refresh"

    def run(self, *args, **kwargs):
        settings = LibreOXISettings.objects.first()
        if not settings or not settings.enabled or not settings.librenms_url or not settings.api_token_encrypted:
            return

        marker = f"{settings.storage_root.rstrip('/')}/.last_refresh"
        now = time.time()
        try:
            last = float(open(marker, "r", encoding="ascii").read().strip())
        except (FileNotFoundError, ValueError, OSError):
            last = 0

        if now - last < settings.check_interval_minutes * 60:
            return

        try:
            with open(marker, "w", encoding="ascii") as handle:
                handle.write(str(now))
        except OSError:
            pass

        append_log(settings.storage_root, "INFO scheduled refresh started")
        for device in monitored_devices(settings).iterator():
            fetch_device(settings, device)
        append_log(settings.storage_root, "INFO scheduled refresh finished")
