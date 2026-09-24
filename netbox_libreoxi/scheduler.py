from __future__ import annotations

from datetime import datetime, timedelta

from django.utils import timezone


# These values are deliberately cron-like: checks are aligned to fixed wall-clock
# boundaries rather than scheduled N minutes after the previous check finished.
SUPPORTED_INTERVALS = (5, 10, 15, 20, 30, 60, 90)


def schedule_slot(now: datetime | None, interval_minutes: int) -> tuple[datetime, datetime]:
    """Return the current and next fixed schedule slots in Django local time."""
    interval = int(interval_minutes)
    if interval not in SUPPORTED_INTERVALS:
        raise ValueError(f"Unsupported LibreOXI interval: {interval}")

    local_now = timezone.localtime(now or timezone.now())
    day_start = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    minutes_since_midnight = local_now.hour * 60 + local_now.minute
    slot_minutes = (minutes_since_midnight // interval) * interval
    slot = day_start + timedelta(minutes=slot_minutes)
    next_slot = slot + timedelta(minutes=interval)
    return slot, next_slot


def next_scheduled_check(now: datetime | None, interval_minutes: int) -> datetime:
    return schedule_slot(now, interval_minutes)[1]
