import tempfile
from datetime import datetime, timezone as dt_timezone
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
