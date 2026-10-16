"""Health of the background jobs: is the LibreOXI schedule running as it should, and can it be repaired from the web.

The plugin's jobs form a chain (every run schedules the next one). When a run hangs or its entry is lost,
the Job row stays "running" / "scheduled" and NetBox neither runs nor re-creates it. Deleting that row and
scheduling a new job is what repairs the chain (restarting netbox-rq alone does not).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

from django.utils import timezone

from .i18n import language_of, tr

MAX_SCHEDULED_AGE = 180  # seconds a "scheduled" / "pending" job may be overdue
MAX_RUNNING_AGE = 900  # a refresh run ends by itself after 240 s; the audit e-mail may take longer
NEW_JOB_GRACE = 30  # seconds before a new job is expected to exist in RQ

JOB_NAMES = ("LibreOXI configuration refresh", "LibreOXI audit e-mail")


def _job_classes():
    from .jobs.libreoxi import LibreOXIAuditMailJob, LibreOXIRefreshJob

    return (LibreOXIRefreshJob, LibreOXIAuditMailJob)


def worker_running() -> bool | None:
    """True / False when netbox-rq's workers are registered in Redis, None when that cannot be told."""
    try:
        import django_rq
        from rq import Worker

        return Worker.count(connection=django_rq.get_connection("default")) > 0
    except Exception:
        return None


def _enqueued(name):
    from core.choices import JobStatusChoices
    from core.models import Job

    return Job.objects.filter(name=name, object_id__isnull=True, status__in=JobStatusChoices.ENQUEUED_STATE_CHOICES)


def job_problems(now=None) -> list[dict]:
    """[{"name", "kind", "seconds"}]: jobs of the plugin that are stuck, lost or missing."""
    from core.choices import JobStatusChoices
    from core.models import Job

    now = now or timezone.now()
    problems = []
    for name in JOB_NAMES:
        jobs = list(_enqueued(name))
        if not jobs:
            last = Job.objects.filter(name=name).order_by("-id").first()
            since = (last.completed or last.created) if last else None
            # the successor is created when a run ends, so a short gap right after a run is normal
            if since is None or now - since > timedelta(seconds=MAX_SCHEDULED_AGE):
                problems.append({"name": name, "kind": "nosuccessor", "seconds": int((now - since).total_seconds()) if since else 0})
            continue
        for job in jobs:
            if job.status == JobStatusChoices.STATUS_RUNNING:
                age = (now - (job.started or job.created)).total_seconds()
                if age > MAX_RUNNING_AGE:
                    problems.append({"name": name, "kind": "running", "seconds": int(age)})
            elif job.status == JobStatusChoices.STATUS_SCHEDULED:
                overdue = (now - job.scheduled).total_seconds() if job.scheduled else 0
                if overdue > MAX_SCHEDULED_AGE:
                    problems.append({"name": name, "kind": "scheduled", "seconds": int(overdue)})
                elif (now - job.created).total_seconds() > NEW_JOB_GRACE and not _rq_entry_present(job):
                    problems.append({"name": name, "kind": "lost", "seconds": 0})
            else:  # pending
                age = (now - job.created).total_seconds()
                if age > MAX_SCHEDULED_AGE:
                    problems.append({"name": name, "kind": "pending", "seconds": int(age)})
    return problems


def _rq_entry_present(job) -> bool:
    try:
        return job._is_rq_job_present()
    except Exception:
        return True  # cannot tell: do not raise a false alarm


def last_scheduled_check(settings):
    """Time of the last completed scheduled refresh slot (from the marker of the refresh job), or None."""
    try:
        marker = Path(settings.storage_root).expanduser().resolve() / ".last_cron_slot"
        return timezone.localtime(datetime.fromtimestamp(float(marker.read_text(encoding="ascii").strip()), tz=dt_timezone.utc))
    except Exception:
        return None


def overview(settings) -> list[dict]:
    """[{"name", "text"}]: what every job of the plugin is doing now (for the details window)."""
    from core.choices import JobStatusChoices

    lang = language_of(settings)
    rows = []
    for name in JOB_NAMES:
        job = _enqueued(name).order_by("-id").first()
        if job is None:
            text = tr("health.s_none", lang)
        elif job.status == JobStatusChoices.STATUS_RUNNING:
            text = tr("health.s_running", lang, time=_clock(job.started or job.created))
        elif job.status == JobStatusChoices.STATUS_SCHEDULED:
            text = tr("health.s_scheduled", lang, time=_clock(job.scheduled))
        else:
            text = tr("health.s_pending", lang)
        rows.append({"name": name, "text": text})
    return rows


def _clock(value) -> str:
    return timezone.localtime(value).strftime("%H:%M:%S") if value else "-"


def status(settings) -> dict:
    """What the health bar shows.

    {"ok", "messages" (what is wrong), "advice" (what to do), "overview" (job by job), "worker" (True / False / None),
     "last" (last scheduled check), "can_repair" (Reload helps)}
    """
    lang = language_of(settings)
    messages, advice = [], []
    worker = worker_running()
    if worker is False:
        messages.append(tr("health.worker_down", lang))
        advice.append(tr("health.do_worker", lang))
    try:
        problems = job_problems()
        rows = overview(settings)
    except Exception as exc:
        problems, rows = [], []
        messages.append(tr("health.cannot_check", lang, error=exc.__class__.__name__))
        advice.append(tr("health.do_check", lang))
    for problem in problems:
        messages.append(tr(f"health.r_{problem['kind']}", lang, name=problem["name"], seconds=problem["seconds"]))
    if problems:
        advice.append(tr("health.do_reload", lang))
    return {
        "ok": not messages,
        "messages": messages,
        "advice": advice,
        "overview": rows,
        "worker": worker,
        "last": last_scheduled_check(settings) if settings else None,
        # Reload cannot start a worker that is not running; it repairs jobs only.
        "can_repair": bool(problems),
    }


def reload_jobs() -> dict:
    """Remove stuck / lost jobs of the plugin and schedule fresh ones. Returns {"removed": n, "created": n}."""
    removed = created = 0
    for name in JOB_NAMES:
        for job in list(_enqueued(name)):
            _stop_running(job)
            job.delete()  # also cancels the RQ entry
            removed += 1
    for cls in _job_classes():
        before = _enqueued(cls.name).count()
        cls.enqueue_once(interval=1)
        created += 1 if before == 0 and _enqueued(cls.name).exists() else 0
    return {"removed": removed, "created": created}


def _stop_running(job) -> None:
    """Ask netbox-rq to stop a running run of this job, if it is really still running (best effort)."""
    from core.choices import JobStatusChoices

    if job.status != JobStatusChoices.STATUS_RUNNING:
        return
    try:
        import django_rq
        from rq.command import send_stop_job_command

        send_stop_job_command(django_rq.get_connection(job.queue_name or "default"), str(job.job_id))
    except Exception:
        pass
