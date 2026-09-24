from __future__ import annotations

import time
from pathlib import Path

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

        root = Path(settings.storage_root).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        marker = root / ".last_refresh"
        now = time.time()
        try:
            last = float(marker.read_text(encoding="ascii").strip())
        except (FileNotFoundError, ValueError, OSError):
            last = 0

        if now - last < settings.check_interval_minutes * 60:
            return

        try:
            marker.write_text(str(now), encoding="ascii")
        except OSError:
            pass

        append_log(settings.storage_root, "INFO scheduled refresh started")
        for device in monitored_devices(settings).iterator():
            fetch_device(settings, device)
        append_log(settings.storage_root, "INFO scheduled refresh finished")
