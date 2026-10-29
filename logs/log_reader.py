
from pathlib import Path
from datetime import datetime
from django.utils import timezone
from .models import SecurityEvent


def import_log_file(file_path):
    file_path = Path(file_path)

    if not file_path.exists():
        print(f"Dosya bulunamadi: {file_path}")
        return 0

    imported_count = 0
    skipped_count = 0

    with file_path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            parts = line.split(maxsplit=5)

            if len(parts) < 6:
                skipped_count += 1
                continue

            date_text = parts[0]
            time_text = parts[1]
            level = parts[2]
            ip_text = parts[3]
            event_type = parts[4]
            description = parts[5]

            if not ip_text.startswith("IP="):
                skipped_count += 1
                continue

            ip_address = ip_text[3:]

            try:
                event_datetime = datetime.strptime(
                    f"{date_text} {time_text}",
                    "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                skipped_count += 1
                continue

            if timezone.is_naive(event_datetime):
                event_datetime = timezone.make_aware(event_datetime)

            if event_type not in {
                "LOGIN_SUCCESS",
                "LOGIN_FAILED",
                "SUSPICIOUS_IP",
            }:
                event_type = "OTHER"

            severity_map = {
                "INFO": "LOW",
                "WARNING": "HIGH",
                "ERROR": "HIGH",
                "CRITICAL": "CRITICAL",
            }
            severity = severity_map.get(level, "MEDIUM")

            full_description = (
                f"{date_text} {time_text} - {description}"
            )
            already_exists = SecurityEvent.objects.filter(
               ip_address=ip_address,
               event_type=event_type,
               severity=severity,
               description=full_description,
            ).exists()

            if already_exists:
                skipped_count += 1
                continue

            SecurityEvent.objects.create(
                timestamp=event_datetime,
                ip_address=ip_address,
                event_type=event_type,
                severity=severity,
                description=full_description,
            )

            imported_count += 1

    print(f"Yeni aktarilan olay sayisi: {imported_count}")
    print(f"Atlanan satir veya tekrar sayisi: {skipped_count}")

    return imported_count
