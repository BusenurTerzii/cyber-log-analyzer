
from collections import Counter
from pathlib import Path
from datetime import timedelta
import json

from .models import SecurityEvent, SecurityAlert
from .risk_analysis import (
    calculate_ip_risk,
    classify_ip_activity,
    detect_brute_force_in_window,
)


def analyze_events():
    events = list(
        SecurityEvent.objects.all().order_by("-timestamp")
    )

    print("\n" + "=" * 45)
    print("SIBER GUVENLIK - LOG ANALIZ RAPORU")
    print("=" * 45)
    print(f"\nToplam olay sayisi: {len(events)}")

    if not events:
        print("Analiz edilecek olay bulunamadi.")
        return

    severity_counts = Counter(
        event.get_severity_display() for event in events
    )

    print("\n--- Onem seviyelerine gore dagilim ---")
    for severity, count in severity_counts.items():
        print(f"{severity}: {count}")

    high_critical_events = [
        event for event in events
        if event.severity in ("HIGH", "CRITICAL")
    ]

    print(
        "\nYuksek/kritik olay sayisi: "
        f"{len(high_critical_events)}"
    )

    ip_counts = Counter(event.ip_address for event in events)

    print("\n--- En cok olay gorulen IP adresleri ---")
    for ip, count in ip_counts.most_common(5):
        print(f"{ip}: {count} olay")

    print("\n--- Son guvenlik olaylari ---")
    for event in events[:10]:
        print(
            f"[{event.get_severity_display()}] "
            f"{event.ip_address} | "
            f"{event.get_event_type_display()} | "
            f"{event.timestamp:%Y-%m-%d %H:%M}"
        )

    print("\nAnaliz tamamlandi.")
    print("=" * 45)


def detect_suspicious_ips(threshold=3):
    failed_events = SecurityEvent.objects.filter(
        event_type="LOGIN_FAILED"
    )

    ip_counts = Counter(
        failed_events.values_list("ip_address", flat=True)
    )

    suspicious_ips = {
        ip: count
        for ip, count in ip_counts.items()
        if ip and count >= threshold
    }

    print("\n--- Supheli IP Analizi ---")

    if not suspicious_ips:
        print("Supheli IP bulunamadi.")
        return suspicious_ips

    for ip, count in suspicious_ips.items():
        print(
            f"UYARI: {ip} adresinden "
            f"{count} basarisiz giris!"
        )

    return suspicious_ips


def build_ip_risk_report():
    failed_counts = detect_suspicious_ips(threshold=1)
    risk_report = []

    for ip, failed_count in failed_counts.items():
        critical_count = SecurityEvent.objects.filter(
            ip_address=ip,
            severity="CRITICAL",
        ).count()

        activity_analysis = classify_ip_activity(
            failed_count,
            critical_count,
        )

        risk_report.append({
            "ip_address": ip,
            "failed_login_count": failed_count,
            "critical_event_count": critical_count,
            "risk_level": activity_analysis["risk_level"],
            "brute_force_detected": activity_analysis[
                "brute_force_detected"
            ],
            "activity": activity_analysis["activity"],
        })

    risk_order = {
        "Yüksek": 0,
        "Orta": 1,
        "Düşük": 2,
    }

    risk_report.sort(
        key=lambda item: (
            risk_order[item["risk_level"]],
            -item["failed_login_count"],
        )
    )

    return risk_report


def detect_brute_force_from_database(
    threshold=5,
    window_minutes=1,
):
    """
    Her IP adresinin başarısız girişlerini zaman sırasına
    göre inceler. Belirlenen zaman penceresinde threshold
    kadar giriş varsa olası Brute-Force olarak işaretler.
    """
    if threshold <= 0 or window_minutes < 0:
        raise ValueError(
            "threshold pozitif, window_minutes negatif olmayan bir değer olmalı."
        )

    ip_addresses = (
        SecurityEvent.objects
        .filter(event_type="LOGIN_FAILED")
        .values_list("ip_address", flat=True)
        .distinct()
    )

    detected_ips = []
    window = timedelta(minutes=window_minutes)

    for ip in ip_addresses:
        timestamps = list(
            SecurityEvent.objects.filter(
                ip_address=ip,
                event_type="LOGIN_FAILED",
            )
            .order_by("timestamp")
            .values_list("timestamp", flat=True)
        )

        if len(timestamps) < threshold:
            continue

        if detect_brute_force_in_window(
            timestamps,
            threshold=threshold,
            window_minutes=window_minutes,
        ):
            detected_ips.append({
                "ip_address": ip,
                "failed_login_threshold": threshold,
                "window_minutes": window_minutes,
                "activity": "Olası Brute-Force Saldırısı",
            })

    return detected_ips


def export_json_report():
    events = list(
        SecurityEvent.objects.all().order_by("-timestamp")[:100]
    )

    all_events_count = SecurityEvent.objects.count()

    severity_counts = Counter(
        event.get_severity_display() for event in events
    )

    unique_event_keys = {
        (
            event.ip_address,
            event.event_type,
            event.severity,
            event.description,
        )
        for event in events
    }

    high_critical_events = [
        {
            "timestamp": event.timestamp.isoformat(),
            "ip_address": event.ip_address,
            "event_type": event.get_event_type_display(),
            "severity": event.get_severity_display(),
            "description": event.description,
        }
        for event in events
        if event.severity in ("HIGH", "CRITICAL")
    ]

    report = {
        "generated_at": (
            SecurityEvent.objects.order_by("-timestamp")
            .values_list("timestamp", flat=True)
            .first()
            .isoformat()
            if all_events_count
            else None
        ),
        "total_events": all_events_count,
        "events_in_report": len(events),
        "unique_events_in_report": len(unique_event_keys),
        "possible_duplicate_events_in_report": (
            len(events) - len(unique_event_keys)
        ),
        "severity_distribution": dict(severity_counts),
        "suspicious_ips": detect_suspicious_ips(threshold=3),
        "ip_risk_analysis": build_ip_risk_report(),
        "brute_force_detections": detect_brute_force_from_database(),
        "high_critical_events": high_critical_events,
        "events": [
            {
                "timestamp": event.timestamp.isoformat(),
                "ip_address": event.ip_address,
                "event_type": event.get_event_type_display(),
                "severity": event.get_severity_display(),
                "description": event.description,
            }
            for event in events
        ],
    }

    report_path = Path("security_report.json")

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False, indent=4)

    print(f"JSON raporu kaydedildi: {report_path.resolve()}")

def create_brute_force_alerts(
    threshold=5,
    window_minutes=1,
):
    """
    Zaman pencereli Brute-Force tespitlerini güvenlik
    uyarısı olarak kaydeder. Aynı IP için açık bir uyarı
    varsa tekrar oluşturmaz.
    """
    detections = detect_brute_force_from_database(
        threshold=threshold,
        window_minutes=window_minutes,
    )

    created_count = 0

    for detection in detections:
        ip = detection["ip_address"]

        # Aynı IP için incelenmemiş Brute-Force uyarısı
        # varsa yeni kayıt oluşturma.
        existing_alert = SecurityAlert.objects.filter(
            ip_address=ip,
            title="Olası Brute-Force Saldırısı",
            is_reviewed=False,
        ).exists()

        if existing_alert:
            continue

        SecurityAlert.objects.create(
            ip_address=ip,
            title="Olası Brute-Force Saldırısı",
            description=(
                f"{ip} adresinden {window_minutes} dakika "
                f"içinde en az {threshold} başarısız giriş "
                "tespit edildi."
            ),
            severity="HIGH",
        )

        created_count += 1

    return created_count
