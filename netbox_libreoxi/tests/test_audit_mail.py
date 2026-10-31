import tempfile
from datetime import datetime, timedelta, timezone as dt_timezone
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from netbox_libreoxi import audit
from netbox_libreoxi.jobs import libreoxi


class LastSentTests(SimpleTestCase):
    def test_actual_sending_time_is_stored_not_the_configured_slot(self):
        root = tempfile.mkdtemp()
        settings = SimpleNamespace(audit_email_enabled=True, storage_root=root)
        slot = datetime(2026, 10, 16, 7, 30, tzinfo=dt_timezone.utc)
        sent_at = datetime(2026, 10, 16, 7, 31, 42, tzinfo=dt_timezone.utc)
        with mock.patch.object(libreoxi.LibreOXISettings.objects, "first", return_value=settings), \
                mock.patch.object(audit, "recipients", return_value=["a@example.com"]), \
                mock.patch.object(audit, "scheduled_period", return_value=(slot, slot, slot, "x")), \
                mock.patch.object(audit, "send_audit", return_value={"sent": True, "total": 0, "reason": ""}), \
                mock.patch.object(libreoxi, "monitored_devices", return_value=[]), \
                mock.patch.object(libreoxi.timezone, "now", return_value=sent_at):
            libreoxi.LibreOXIAuditMailJob(job=None).run()
        self.assertEqual(audit.read_last_sent(settings), sent_at)
        self.assertGreaterEqual(audit.read_last_sent(settings), slot)  # the "already sent" check still holds


def utc(*args):
    return datetime(*args, tzinfo=dt_timezone.utc)


class NextSendTests(SimpleTestCase):
    def setUp(self):
        self.settings = SimpleNamespace(audit_email_enabled=True, storage_root=tempfile.mkdtemp(), audit_email_time="07:30",
                                        audit_email_frequency="daily", audit_email_weekday=0)
        patcher = mock.patch.object(audit, "recipients", return_value=["a@example.com"])
        patcher.start()
        self.addCleanup(patcher.stop)

    def next(self, now):
        return audit.next_scheduled_send(self.settings, now)

    def test_daily_later_today_and_tomorrow(self):
        self.assertEqual(self.next(utc(2026, 10, 16, 6, 0)), utc(2026, 10, 16, 7, 30))
        audit.write_last_sent(self.settings, utc(2026, 10, 16, 7, 30, 12))
        self.assertEqual(self.next(utc(2026, 10, 16, 16, 0)), utc(2026, 10, 17, 7, 30))

    def test_slot_passed_but_not_sent_is_due(self):
        self.assertEqual(self.next(utc(2026, 10, 16, 7, 40)), utc(2026, 10, 16, 7, 30))

    def test_weekly_uses_the_chosen_weekday(self):
        self.settings.audit_email_frequency, self.settings.audit_email_weekday = "weekly", 0  # Monday
        audit.write_last_sent(self.settings, utc(2026, 10, 12, 7, 30, 5))
        self.assertEqual(self.next(utc(2026, 10, 16, 16, 0)), utc(2026, 10, 19, 7, 30))

    def test_monthly_is_the_first_of_the_month(self):
        self.settings.audit_email_frequency = "monthly"
        audit.write_last_sent(self.settings, utc(2026, 10, 1, 7, 30, 5))
        self.assertEqual(self.next(utc(2026, 10, 16, 16, 0)), utc(2026, 11, 1, 7, 30))

    def test_off_without_recipients_or_when_disabled(self):
        self.settings.audit_email_enabled = False
        self.assertIsNone(self.next(utc(2026, 10, 16, 6, 0)))
        self.settings.audit_email_enabled = True
        with mock.patch.object(audit, "recipients", return_value=[]):
            self.assertIsNone(self.next(utc(2026, 10, 16, 6, 0)))

    def test_remaining_format(self):
        hours = lambda h, m=0: timedelta(hours=h, minutes=m)
        self.assertEqual(audit.format_remaining(hours(15, 32), "en"), "15 h 32 min")
        self.assertEqual(audit.format_remaining(timedelta(minutes=32), "en"), "32 min")
        self.assertEqual(audit.format_remaining(hours(24), "sk"), "1 deň 0 h")
        self.assertEqual(audit.format_remaining(hours(39, 40), "sk"), "1 deň 15 h")
        self.assertEqual(audit.format_remaining(hours(24 * 4 + 15), "sk"), "4 dni 15 h")
        self.assertEqual(audit.format_remaining(hours(24 * 6), "sk"), "6 dní 0 h")
        self.assertEqual(audit.format_remaining(hours(24 * 2), "de"), "2 Tage 0 h")

    def test_test_mail_time_is_stored(self):
        self.assertIsNone(audit.read_last_test(self.settings))
        audit.write_last_test(self.settings, utc(2026, 10, 16, 11, 5, 41))
        self.assertEqual(audit.read_last_test(self.settings), utc(2026, 10, 16, 11, 5, 41))
