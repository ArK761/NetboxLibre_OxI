from __future__ import annotations

from datetime import datetime

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


def next_scheduled_check(now: datetime | None, schedule: str) -> datetime:
    local_now = timezone.localtime(now or timezone.now())
    candidates = []
    for expression in cron_lines(schedule):
        candidates.append(croniter(expression, local_now).get_next(datetime))
    if not candidates:
        raise ValueError("Cron schedule cannot be empty.")
    return min(candidates)
