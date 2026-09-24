from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from django import template
from django.utils import timezone as django_timezone

from ..scheduler import next_scheduled_check

register = template.Library()


@register.simple_tag
def next_check_info(settings):
    if not settings:
        return {"available": False}

    marker = Path(settings.storage_root).expanduser().resolve() / ".last_refresh"
    try:
        last_slot_ts = float(marker.read_text(encoding="ascii").strip())
    except (FileNotFoundError, ValueError, OSError):
        last_slot_ts = None

    try:
        next_dt = next_scheduled_check(django_timezone.now(), settings.check_interval_minutes)
    except (TypeError, ValueError):
        return {"available": False}

    # If the current scheduled slot has already been executed, next_scheduled_check()
    # returns the following slot. If the marker is from an older slot, the same
    # result is still the next wall-clock slot from now.
    now = django_timezone.now()
    if next_dt <= now:
        return {"available": False}

    remaining = max(0, int(next_dt.timestamp() - now.timestamp()))
    try:
        display = django_timezone.localtime(next_dt).strftime(settings.datetime_format)
    except (TypeError, ValueError):
        display = django_timezone.localtime(next_dt).strftime("%d.%m.%Y %H:%M:%S")

    return {
        "available": True,
        "display": display,
        "iso": next_dt.isoformat(),
        "seconds": remaining,
        "last_slot": last_slot_ts,
    }


@register.filter
def log_hash(value):
    if not value:
        return ""
    match = re.search(r"\bhash=([0-9a-fA-F]{64})\b", str(value))
    return match.group(1) if match else ""
