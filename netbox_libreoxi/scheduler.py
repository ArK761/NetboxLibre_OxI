from __future__ import annotations

from datetime import datetime, timedelta

from croniter import croniter
from django.utils import timezone


def cron_lines(schedule: str) -> list[str]:
    return [
        line.strip()
        for line in (schedule or "").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def validate_cron_schedule(schedule: str) -> str:
    lines = cron_lines(schedule)
    if not lines:
        raise ValueError("Cron schedule cannot be empty.")
    for line in lines:
        if not croniter.is_valid(line):
            raise ValueError(f"Invalid cron expression: {line}")
    return "\n".join(lines)


def schedule_matches(now: datetime | None, schedule: str) -> tuple[bool, datetime | None]:
    local_now = timezone.localtime(now or timezone.now()).replace(second=0, microsecond=0)
    for expression in cron_lines(schedule):
        if croniter.match(expression, local_now):
            return True, local_now
    return False, None


def latest_slot(now: datetime | None, schedule: str) -> datetime | None:
    """Most recent cron slot at or before `now` (minute precision), or None.

    Unlike schedule_matches() this does not need the job to run in exactly the minute of the slot:
    NetBox re-schedules a 1-minute job at "finished + 1 minute", so its run times drift against the
    wall clock and a whole minute is skipped from time to time.
    """
    local_now = timezone.localtime(now or timezone.now()).replace(second=0, microsecond=0)
    start = local_now + timedelta(minutes=1)  # get_prev() is exclusive, so a slot in this very minute is found
    slots = [croniter(expression, start).get_prev(datetime) for expression in cron_lines(schedule)]
    return max(slots) if slots else None


def next_scheduled_check(now: datetime | None, schedule: str) -> datetime:
    local_now = timezone.localtime(now or timezone.now())
    candidates = []
    for expression in cron_lines(schedule):
        candidates.append(croniter(expression, local_now).get_next(datetime))
    if not candidates:
        raise ValueError("Cron schedule cannot be empty.")
    return min(candidates)
