from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from django import template

register = template.Library()


@register.simple_tag
def next_check_info(settings):
    if not settings:
        return {"available": False}

    marker = Path(settings.storage_root).expanduser().resolve() / ".last_refresh"
    try:
        last = float(marker.read_text(encoding="ascii").strip())
    except (FileNotFoundError, ValueError, OSError):
        return {"available": False}

    interval = max(1, int(settings.check_interval_minutes)) * 60
    next_ts = last + interval
    remaining = max(0, int(next_ts - time.time()))
    next_dt = datetime.fromtimestamp(next_ts, tz=timezone.utc)

    try:
        display = next_dt.astimezone(timezone.utc).strftime(settings.datetime_format)
    except (TypeError, ValueError):
        display = next_dt.strftime("%d.%m.%Y %H:%M:%S")

    return {
        "available": True,
        "display": display,
        "iso": next_dt.isoformat(),
        "seconds": remaining,
    }
