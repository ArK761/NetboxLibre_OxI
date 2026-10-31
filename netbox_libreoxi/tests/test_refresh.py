import tempfile
import threading
from datetime import datetime, timezone as dt_timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from netbox_libreoxi import oxi
from netbox_libreoxi.jobs import libreoxi
from netbox_libreoxi.scheduler import latest_slot


def utc(*args):
    return datetime(*args, tzinfo=dt_timezone.utc)


class LatestSlotTests(SimpleTestCase):
    def test_slot_is_found_even_when_the_job_runs_late(self):
        self.assertEqual(latest_slot(utc(2026, 10, 14, 7, 31, 10), "*/30 * * * *"), utc(2026, 10, 14, 7, 30))

    def test_slot_in_the_current_minute(self):
        self.assertEqual(latest_slot(utc(2026, 10, 14, 7, 30, 0), "*/30 * * * *"), utc(2026, 10, 14, 7, 30))
        self.assertEqual(latest_slot(utc(2026, 10, 14, 7, 30, 59), "*/30 * * * *"), utc(2026, 10, 14, 7, 30))

    def test_just_before_a_slot(self):
        self.assertEqual(latest_slot(utc(2026, 10, 14, 7, 29, 59), "*/30 * * * *"), utc(2026, 10, 14, 7, 0))

    def test_several_expressions_use_the_latest(self):
        self.assertEqual(latest_slot(utc(2026, 10, 14, 7, 40), "0 * * * *\n*/15 * * * *"), utc(2026, 10, 14, 7, 30))

    def test_empty_schedule(self):
        self.assertIsNone(latest_slot(utc(2026, 10, 14, 7, 40), "# nothing\n"))


class RefreshJobTests(SimpleTestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.settings = SimpleNamespace(
            enabled=True, librenms_url="http://x", api_token_encrypted="t", storage_root=self.root,
            schedule_cron="*/30 * * * *",
        )
        self.marker = Path(self.root) / ".last_cron_slot"
        self.calls = []

    def run_job(self, now, fetch=None, devices=3):
        fetch = fetch or (lambda settings, device: self.calls.append(device) or {"ok": True, "changed": False})
        with mock.patch.object(libreoxi.LibreOXISettings.objects, "first", return_value=self.settings), \
                mock.patch.object(libreoxi, "monitored_devices", return_value=list(range(devices))), \
                mock.patch.object(libreoxi, "fetch_device", side_effect=fetch), \
                mock.patch.object(libreoxi, "connections"), mock.patch.object(libreoxi, "close_old_connections"), \
                mock.patch.object(libreoxi.timezone, "now", return_value=now):
            libreoxi.LibreOXIRefreshJob(job=None).run()

    def log(self):
        return (Path(self.root) / "libreoxi.log").read_text() if (Path(self.root) / "libreoxi.log").exists() else ""

    def test_missed_minute_is_caught_up_once(self):
        self.marker.write_text(str(utc(2026, 10, 14, 7, 0).timestamp()))
        self.run_job(utc(2026, 10, 14, 7, 31, 20))  # the 07:30 minute never ran
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(float(self.marker.read_text()), utc(2026, 10, 14, 7, 30).timestamp())
        self.run_job(utc(2026, 10, 14, 7, 32, 20))
        self.assertEqual(len(self.calls), 3)  # same slot is not repeated

    def test_slot_older_than_the_catch_up_window_is_dropped(self):
        self.settings.schedule_cron = "0 * * * *"
        self.run_job(utc(2026, 10, 14, 7, 50))  # the 07:00 slot is 50 minutes old
        self.assertEqual(self.calls, [])

    def test_killed_run_is_repeated(self):
        def killed(settings, device):
            raise KeyboardInterrupt  # not caught by the job: simulates the run being cut short

        self.marker.write_text(str(utc(2026, 10, 14, 7, 0).timestamp()))
        with self.assertRaises(BaseException):
            self.run_job(utc(2026, 10, 14, 7, 30, 5), fetch=killed, devices=1)
        # the marker is written in `finally`, but a SIGKILL never gets there: emulate by resetting it
        self.marker.write_text(str(utc(2026, 10, 14, 7, 0).timestamp()))
        self.run_job(utc(2026, 10, 14, 7, 31, 5))
        self.assertEqual(len(self.calls), 3)

    def test_stuck_device_cannot_block_the_job(self):
        release = threading.Event()
        self.addCleanup(release.set)

        def stuck(settings, device):
            release.wait(10)
            return {"ok": True, "changed": False}

        with mock.patch.object(libreoxi, "RUN_BUDGET_SECONDS", 1):
            started = threading.Event()
            result = {}

            def target():
                self.run_job(utc(2026, 10, 14, 7, 30, 5), fetch=stuck, devices=20)
                result["done"] = True

            thread = threading.Thread(target=target)
            started.set()
            thread.start()
            thread.join(6)
        self.assertTrue(result.get("done"), "the job did not end although the devices are stuck")
        self.assertIn("exceeded 1s", self.log())
        self.assertIn("scheduled refresh finished", self.log())
        self.assertTrue(self.marker.exists())


class ReadBodyTests(SimpleTestCase):
    def response(self, chunks, delay=0):
        import time

        def iter_content(chunk_size):
            for chunk in chunks:
                time.sleep(delay)
                yield chunk

        return SimpleNamespace(iter_content=iter_content)

    def test_body_is_joined(self):
        self.assertEqual(oxi._read_body(self.response([b'{"a"', b":1}"])), b'{"a":1}')

    def test_slow_dripping_server_is_cut_off(self):
        with mock.patch.object(oxi, "REQUEST_DEADLINE", 0.3):
            with self.assertRaisesRegex(RuntimeError, "not received within"):
                oxi._read_body(self.response([b"x"] * 100, delay=0.05))

    def test_config_parsing_still_works(self):
        self.assertEqual(oxi._extract_config(b'{"status":"ok","config":["a\\n","b\\n"]}'), "a\nb\n")
        with self.assertRaises(RuntimeError):
            oxi._extract_config(b"<html>")
        with self.assertRaises(RuntimeError):
            oxi._extract_config(b'{"status":"error"}')
