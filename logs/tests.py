
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .analysis import (
    detect_brute_force_from_database,
    detect_suspicious_ips,
)
from .log_reader import import_log_file
from .models import SecurityEvent
from .risk_analysis import calculate_ip_risk


class SecurityEventModelTest(TestCase):

    def test_security_event_creation(self):
        event = SecurityEvent.objects.create(
            ip_address="192.168.1.10",
            event_type="LOGIN_FAILED",
            severity="HIGH",
            timestamp=timezone.now(),
            description="Test başarısız giriş",
        )

        self.assertEqual(event.ip_address, "192.168.1.10")
        self.assertEqual(event.event_type, "LOGIN_FAILED")
        self.assertEqual(event.severity, "HIGH")


class SuspiciousIPTest(TestCase):

    def test_detects_ip_with_three_failed_logins(self):
        for _ in range(3):
            SecurityEvent.objects.create(
                ip_address="192.168.1.50",
                event_type="LOGIN_FAILED",
                severity="HIGH",
                timestamp=timezone.now(),
                description="Test başarısız giriş",
            )

        result = detect_suspicious_ips(threshold=3)

        self.assertEqual(result.get("192.168.1.50"), 3)

    def test_ip_below_threshold_is_not_suspicious(self):
        for _ in range(2):
            SecurityEvent.objects.create(
                ip_address="192.168.1.60",
                event_type="LOGIN_FAILED",
                severity="HIGH",
                timestamp=timezone.now(),
                description="Test başarısız giriş",
            )

        result = detect_suspicious_ips(threshold=3)

        self.assertNotIn("192.168.1.60", result)


class RiskAnalysisTest(TestCase):

    def test_zero_failed_logins_is_low_risk(self):
        result = calculate_ip_risk(
            failed_count=0,
            critical_count=0,
        )

        self.assertEqual(result, "Düşük")

    def test_three_failed_logins_is_medium_risk(self):
        result = calculate_ip_risk(
            failed_count=3,
            critical_count=0,
        )

        self.assertEqual(result, "Orta")

    def test_five_failed_logins_is_high_risk(self):
        result = calculate_ip_risk(
            failed_count=5,
            critical_count=0,
        )

        self.assertEqual(result, "Yüksek")

    def test_critical_event_is_high_risk(self):
        result = calculate_ip_risk(
            failed_count=0,
            critical_count=1,
        )

        self.assertEqual(result, "Yüksek")


class LogReaderTest(TestCase):

    def test_imports_valid_log_line(self):
        with TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "test.log"

            log_path.write_text(
                "2026-10-29 10:30:00 WARNING "
                "IP=192.168.1.70 LOGIN_FAILED "
                "Basarisiz giris denemesi\n",
                encoding="utf-8",
            )

            imported_count = import_log_file(log_path)

        self.assertEqual(imported_count, 1)

        event = SecurityEvent.objects.get(
            ip_address="192.168.1.70",
        )

        self.assertEqual(event.event_type, "LOGIN_FAILED")
        self.assertEqual(event.severity, "HIGH")

    def test_does_not_import_same_log_line_twice(self):
        with TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "test.log"

            log_line = (
                "2026-10-29 10:30:00 WARNING "
                "IP=192.168.1.80 LOGIN_FAILED "
                "Basarisiz giris denemesi\n"
            )

            log_path.write_text(
                log_line,
                encoding="utf-8",
            )

            first_import = import_log_file(log_path)
            second_import = import_log_file(log_path)

        self.assertEqual(first_import, 1)
        self.assertEqual(second_import, 0)

        self.assertEqual(
            SecurityEvent.objects.filter(
                ip_address="192.168.1.80",
            ).count(),
            1,
        )


class JSONReportDownloadTest(TestCase):

    def test_json_report_download(self):
        SecurityEvent.objects.create(
            ip_address="192.168.1.90",
            event_type="LOGIN_FAILED",
            severity="HIGH",
            timestamp=timezone.now(),
            description="Test rapor olayi",
        )

        response = self.client.get(
            reverse("logs:download_report"),
        )

        self.assertEqual(response.status_code, 200)

        self.assertEqual(
            response["Content-Type"],
            "application/json",
        )

        self.assertIn(
            "attachment",
            response["Content-Disposition"],
        )

        self.assertIn(
            "security_report.json",
            response["Content-Disposition"],
        )

        content = b"".join(response.streaming_content)

        self.assertIn(b'"total_events"', content)
        self.assertIn(b'"ip_risk_analysis"', content)


class BruteForceDatabaseTests(TestCase):

    def create_failed_login(self, ip, timestamp):
        event = SecurityEvent.objects.create(
            ip_address=ip,
            event_type="LOGIN_FAILED",
            severity="MEDIUM",
            description="Basarisiz giris denemesi",
        )

        # Testte belirlenen zamanı doğrudan veritabanına yaz.
        SecurityEvent.objects.filter(
            pk=event.pk,
        ).update(
            timestamp=timestamp,
        )

        return event

    def test_detects_brute_force_within_one_minute(self):
        now = timezone.now()

        for seconds in (0, 10, 20, 30, 40):
            self.create_failed_login(
                "192.168.1.200",
                now + timedelta(seconds=seconds),
            )

        result = detect_brute_force_from_database()

        detected_ips = [
            item["ip_address"]
            for item in result
        ]

        self.assertIn("192.168.1.200", detected_ips)

    def test_does_not_detect_attempts_spread_over_days(self):
        now = timezone.now()

        for days in range(5):
            self.create_failed_login(
                "192.168.1.201",
                now + timedelta(days=days),
            )

        result = detect_brute_force_from_database()

        detected_ips = [
            item["ip_address"]
            for item in result
        ]

        self.assertNotIn("192.168.1.201", detected_ips)

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from .models import SecurityEvent
from .risk_analysis import detect_brute_force_in_window


class BruteForceWindowTests(TestCase):
    def test_five_attempts_within_one_minute_detected(self):
        now = timezone.now()
        timestamps = [
            now - timedelta(seconds=seconds)
            for seconds in (50, 40, 30, 20, 10)
        ]

        result = detect_brute_force_in_window(
            timestamps,
            threshold=5,
            window_minutes=1,
        )

        self.assertTrue(result)

    def test_four_attempts_are_not_enough(self):
        now = timezone.now()
        timestamps = [
            now - timedelta(seconds=seconds)
            for seconds in (40, 30, 20, 10)
        ]

        result = detect_brute_force_in_window(
            timestamps,
            threshold=5,
            window_minutes=1,
        )

        self.assertFalse(result)

    def test_attempts_spread_over_two_minutes_not_detected(self):
        now = timezone.now()
        timestamps = [
            now - timedelta(minutes=minutes)
            for minutes in (5, 4, 3, 2, 0)
        ]

        result = detect_brute_force_in_window(
            timestamps,
            threshold=5,
            window_minutes=1,
        )

        self.assertFalse(result)

    def test_unsorted_timestamps_are_handled(self):
        now = timezone.now()
        timestamps = [
            now - timedelta(seconds=10),
            now - timedelta(seconds=50),
            now - timedelta(seconds=30),
            now - timedelta(seconds=20),
            now - timedelta(seconds=40),
        ]

        result = detect_brute_force_in_window(
            timestamps,
            threshold=5,
            window_minutes=1,
        )

        self.assertTrue(result)

    def test_same_ip_attempts_at_exact_window_boundary(self):
        now = timezone.now()
        timestamps = [
            now - timedelta(seconds=60),
            now - timedelta(seconds=45),
            now - timedelta(seconds=30),
            now - timedelta(seconds=15),
            now,
        ]

        result = detect_brute_force_in_window(
            timestamps,
            threshold=5,
            window_minutes=1,
        )

        self.assertTrue(result)
