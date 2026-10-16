import uuid
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from core.choices import JobStatusChoices
from core.models import Job
from netbox_libreoxi import health
from users.models import User

REFRESH, MAIL = health.JOB_NAMES


def make_job(name, status, scheduled=None, started=None, age=0):
    job = Job.objects.create(name=name, status=status, scheduled=scheduled, started=started, interval=1,
                             job_id=uuid.uuid4(), queue_name="default")
    if age:
        Job.objects.filter(pk=job.pk).update(created=timezone.now() - timedelta(seconds=age))
    return job


class HealthBase(TestCase):
    def setUp(self):
        for patcher in (mock.patch.object(health, "worker_running", return_value=True),
                        mock.patch.object(Job, "_is_rq_job_present", return_value=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def healthy(self):
        now = timezone.now()
        for name in health.JOB_NAMES:
            make_job(name, JobStatusChoices.STATUS_SCHEDULED, scheduled=now + timedelta(seconds=40))

    def kinds(self):
        return sorted(problem["kind"] for problem in health.job_problems())


class JobProblemTests(HealthBase):
    def test_healthy(self):
        self.healthy()
        self.assertEqual(health.job_problems(), [])
        self.assertTrue(health.status(None)["ok"])

    def test_running_job_within_limit_is_fine(self):
        now = timezone.now()
        make_job(REFRESH, JobStatusChoices.STATUS_RUNNING, started=now - timedelta(seconds=100))
        make_job(MAIL, JobStatusChoices.STATUS_SCHEDULED, scheduled=now + timedelta(seconds=30))
        self.assertEqual(self.kinds(), [])

    def test_stuck_states(self):
        now = timezone.now()
        make_job(REFRESH, JobStatusChoices.STATUS_RUNNING, started=now - timedelta(seconds=2000), age=2000)
        make_job(MAIL, JobStatusChoices.STATUS_SCHEDULED, scheduled=now - timedelta(minutes=10), age=700)
        self.assertEqual(self.kinds(), ["running", "scheduled"])
        state = health.status(None)
        self.assertFalse(state["ok"])
        self.assertTrue(state["can_repair"])

    def test_pending_too_long(self):
        make_job(REFRESH, JobStatusChoices.STATUS_PENDING, age=400)
        make_job(MAIL, JobStatusChoices.STATUS_PENDING)
        self.assertEqual(self.kinds(), ["pending"])

    def test_no_jobs_at_all(self):
        self.assertEqual(self.kinds(), ["nosuccessor", "nosuccessor"])

    def test_lost_rq_entry(self):
        now = timezone.now()
        make_job(REFRESH, JobStatusChoices.STATUS_SCHEDULED, scheduled=now + timedelta(seconds=40), age=120)
        make_job(MAIL, JobStatusChoices.STATUS_SCHEDULED, scheduled=now + timedelta(seconds=40))
        with mock.patch.object(Job, "_is_rq_job_present", return_value=False):
            self.assertEqual(self.kinds(), ["lost"])  # the brand-new job is not reported yet

    def test_worker_down_is_reported_but_not_repairable(self):
        self.healthy()
        with mock.patch.object(health, "worker_running", return_value=False):
            state = health.status(None)
        self.assertFalse(state["ok"])
        self.assertFalse(state["can_repair"])
        self.assertIn("netbox-rq", state["messages"][0])


class ReloadTests(HealthBase):
    def test_reload_replaces_stuck_jobs(self):
        now = timezone.now()
        old = [make_job(REFRESH, JobStatusChoices.STATUS_RUNNING, started=now - timedelta(seconds=5000), age=5000),
               make_job(MAIL, JobStatusChoices.STATUS_SCHEDULED, scheduled=now - timedelta(hours=1), age=4000)]
        result = health.reload_jobs()
        self.assertEqual(result, {"removed": 2, "created": 2})
        self.assertFalse(Job.objects.filter(pk__in=[job.pk for job in old]).exists())
        for name in health.JOB_NAMES:
            self.assertEqual(health._enqueued(name).count(), 1)
        self.assertEqual(health.job_problems(), [])

    def test_reload_without_any_job_starts_the_chain(self):
        self.assertEqual(health.reload_jobs(), {"removed": 0, "created": 2})


class BannerViewTests(HealthBase):
    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_superuser(username="root", password="x", email="r@example.com")
        self.client.force_login(self.admin)
        self.url = reverse("plugins:netbox_libreoxi:logs")

    def test_green_when_all_is_well(self):
        self.healthy()
        response = self.client.get(self.url)
        self.assertContains(response, "lox-health")
        self.assertNotContains(response, "lox-health lox-bad")

    def test_red_with_reload_button_and_reload_fixes_it(self):
        make_job(REFRESH, JobStatusChoices.STATUS_RUNNING, started=timezone.now() - timedelta(hours=2), age=7200)
        make_job(MAIL, JobStatusChoices.STATUS_SCHEDULED, scheduled=timezone.now() + timedelta(seconds=30))
        response = self.client.get(self.url)
        self.assertContains(response, "lox-health lox-bad")
        self.assertContains(response, reverse("plugins:netbox_libreoxi:health_reload"))
        response = self.client.post(reverse("plugins:netbox_libreoxi:health_reload"), {"next": self.url})
        self.assertRedirects(response, self.url, fetch_redirect_response=False)
        self.assertNotContains(self.client.get(self.url), "lox-health lox-bad")

    def test_details_window_says_all_is_ok(self):
        self.healthy()
        html = self.client.get(self.url).content.decode()
        self.assertIn("lox-health-modal", html)
        self.assertIn("mdi-dots-vertical", html)
        self.assertIn("Everything is OK", html)
        self.assertIn("Nothing to do", html)
        self.assertNotIn("lox-health lox-bad", html)

    def test_details_window_tells_what_to_do(self):
        make_job(REFRESH, JobStatusChoices.STATUS_RUNNING, started=timezone.now() - timedelta(hours=2), age=7200)
        make_job(MAIL, JobStatusChoices.STATUS_SCHEDULED, scheduled=timezone.now() + timedelta(seconds=30))
        html = self.client.get(self.url).content.decode()
        self.assertIn("lox-health lox-bad", html)
        self.assertIn("Action needed", html)
        self.assertIn("Press Reload", html)
        self.assertIn(REFRESH, html)

    def test_worker_down_advice_is_not_reload(self):
        self.healthy()
        with mock.patch.object(health, "worker_running", return_value=False):
            html = self.client.get(self.url).content.decode()
        self.assertIn("Ask the server administrator", html)
        self.assertNotIn("Press Reload", html)
        self.assertNotIn(reverse("plugins:netbox_libreoxi:health_reload"), html)

    def test_foreign_redirect_target_is_ignored(self):
        response = self.client.post(reverse("plugins:netbox_libreoxi:health_reload"), {"next": "https://evil.example/"})
        self.assertEqual(response["Location"], self.url)

    def test_reload_needs_the_manage_permission_and_post(self):
        viewer = User.objects.create_user(username="viewer", password="x")
        self.client.force_login(viewer)
        self.assertEqual(self.client.post(reverse("plugins:netbox_libreoxi:health_reload")).status_code, 403)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(reverse("plugins:netbox_libreoxi:health_reload")).status_code, 405)

    def test_banner_on_every_page(self):
        from netbox_libreoxi.models import LibreOXISettings

        LibreOXISettings.objects.create(librenms_url="http://x", oxidized_path="/api", storage_root="/tmp/libreoxi-test")
        self.healthy()
        for name in ("settings", "audit", "email", "logs"):
            self.assertContains(self.client.get(reverse(f"plugins:netbox_libreoxi:{name}")), "lox-health", msg_prefix=name)


class EmailPageInfoTests(HealthBase):
    def test_email_page_shows_last_next_and_test(self):
        from netbox_libreoxi.models import LibreOXISettings

        admin = User.objects.create_superuser(username="root", password="x", email="r@example.com")
        self.client.force_login(admin)
        LibreOXISettings.objects.create(librenms_url="http://x", oxidized_path="/api", storage_root="/tmp/libreoxi-mail-test",
                                        audit_email_enabled=True, audit_email_recipients="a@example.com")
        html = self.client.get(reverse("plugins:netbox_libreoxi:email")).content.decode()
        self.assertIn("Automatic e-mail (cron): not sent yet", html)
        self.assertIn("Test e-mail: not sent yet", html)
        self.assertIn("Next e-mail:", html)
