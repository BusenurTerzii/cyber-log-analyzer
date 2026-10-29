
import json
from collections import Counter
from pathlib import Path

from django.contrib import messages
from django.http import FileResponse
from django.shortcuts import render, redirect
from django.utils import timezone

from .models import SecurityEvent, SecurityAlert
from .log_reader import import_log_file
from .analysis import (
    export_json_report,
    detect_brute_force_from_database,
    create_brute_force_alerts,
)
from .risk_analysis import calculate_ip_risk



def dashboard(request):
    if request.method == "POST":
        file_path = Path("sample_security.log")
        imported_count = import_log_file(file_path)

        messages.success(
            request,
            f"Yeni aktarılan olay sayısı: {imported_count}",
        )
        return redirect("logs:dashboard")

    events = SecurityEvent.objects.all().order_by("-timestamp")

    ip_filter = request.GET.get("ip", "").strip()
    severity_filter = request.GET.get("severity", "").strip()
    event_type_filter = request.GET.get("event_type", "").strip()

    if ip_filter:
        events = events.filter(ip_address__icontains=ip_filter)

    if severity_filter in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        events = events.filter(severity=severity_filter)

    if event_type_filter in [
        "LOGIN_SUCCESS",
        "LOGIN_FAILED",
        "SUSPICIOUS_IP",
        "OTHER",
    ]:
        events = events.filter(event_type=event_type_filter)

    # Başarısız girişleri IP adresine göre say.
    failed_events = SecurityEvent.objects.filter(
        event_type="LOGIN_FAILED"
    )

    ip_counts = Counter(
        failed_events.values_list("ip_address", flat=True)
    )

    # Zaman pencereli Brute-Force tespiti.
    brute_force_detections = detect_brute_force_from_database(
        threshold=5,
        window_minutes=1,
    )

    brute_force_ips = {
        item["ip_address"]
        for item in brute_force_detections
    }

    suspicious_ips = []

    for ip, count in ip_counts.items():
        if count < 3:
            continue

        critical_count = SecurityEvent.objects.filter(
            ip_address=ip,
            severity="CRITICAL",
        ).count()

        brute_force_detected = ip in brute_force_ips

        if brute_force_detected or critical_count > 0:
            risk_level = "Yüksek"
        else:
            risk_level = "Orta"

        if brute_force_detected:
            activity = "Olası Brute-Force Saldırısı"
        else:
            activity = "Tekrarlanan Başarısız Giriş"

        suspicious_ips.append({
            "ip_address": ip,
            "failed_count": count,
            "risk_level": risk_level,
            "brute_force_detected": brute_force_detected,
            "activity": activity,
        })

    high_risk_ips = [
        ip for ip in suspicious_ips
        if ip["risk_level"] in ["Yüksek", "Orta"]
    ]

    # Önem seviyesine göre grafik verileri.
    severity_labels = ["Düşük", "Orta", "Yüksek", "Kritik"]
    severity_values = [
        events.filter(severity="LOW").count(),
        events.filter(severity="MEDIUM").count(),
        events.filter(severity="HIGH").count(),
        events.filter(severity="CRITICAL").count(),
    ]

    # Olay türüne göre grafik verileri.
    event_labels = [
        "Başarılı giriş",
        "Başarısız giriş",
        "Şüpheli IP",
        "Diğer",
    ]

    event_values = [
        events.filter(event_type="LOGIN_SUCCESS").count(),
        events.filter(event_type="LOGIN_FAILED").count(),
        events.filter(event_type="SUSPICIOUS_IP").count(),
        events.filter(event_type="OTHER").count(),
    ]

    # Son kritik olaylar.
    critical_event_list = SecurityEvent.objects.filter(
        severity="CRITICAL"
    ).order_by("-timestamp")[:5]
    # Tespit edilen saldırılar için uyarı oluştur.
    create_brute_force_alerts(
        threshold=5,
        window_minutes=1,
    )
    # Son güvenlik uyarıları ve incelenmemiş uyarı sayısı.
    security_alerts = SecurityAlert.objects.all()[:10]

    unreviewed_alert_count = SecurityAlert.objects.filter(
        is_reviewed=False
    ).count()

    context = {
        "total_events": events.count(),
        "high_events": events.filter(severity="HIGH").count(),
        "critical_events": events.filter(severity="CRITICAL").count(),
        "suspicious_events": events.filter(
            event_type="SUSPICIOUS_IP"
        ).count(),
        "recent_events": events[:10],
        "suspicious_ips": suspicious_ips,
        "high_risk_ips": high_risk_ips,
        "critical_event_list": critical_event_list,
        "brute_force_detections": brute_force_detections,
        "security_alerts": security_alerts,
        "unreviewed_alert_count": unreviewed_alert_count,
        "severity_labels": severity_labels,
        "severity_values": severity_values,
        "event_labels": event_labels,
        "event_values": event_values,
        "severity_labels_json": json.dumps(severity_labels),
        "event_labels_json": json.dumps(event_labels),
        "severity_values_json": json.dumps(severity_values),
        "event_values_json": json.dumps(event_values),
    }

    return render(request, "logs/dashboard.html", context)


def download_json_report(request):
    export_json_report()
    report_path = Path("security_report.json")

    if not report_path.exists():
        messages.error(
            request,
            "JSON raporu oluşturulamadı.",
        )
        return redirect("logs:dashboard")

    return FileResponse(
        report_path.open("rb"),
        as_attachment=True,
        filename="security_report.json",
        content_type="application/json",
    )


def ip_detail(request, ip_address):
    # Bu IP adresine ait bütün olaylar.
    all_events = SecurityEvent.objects.filter(
        ip_address=ip_address
    ).order_by("-timestamp")

    # Filtre seçenekleri.
    event_type_filter = request.GET.get("event_type", "").strip()
    severity_filter = request.GET.get("severity", "").strip()

    events = all_events

    if event_type_filter in [
        "LOGIN_SUCCESS",
        "LOGIN_FAILED",
        "SUSPICIOUS_IP",
        "OTHER",
    ]:
        events = events.filter(event_type=event_type_filter)

    if severity_filter in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        events = events.filter(severity=severity_filter)

    # İstatistikler filtrelenmemiş tüm olayları kapsar.
    total_events = all_events.count()

    failed_count = all_events.filter(
        event_type="LOGIN_FAILED"
    ).count()

    successful_count = all_events.filter(
        event_type="LOGIN_SUCCESS"
    ).count()

    critical_count = all_events.filter(
        severity="CRITICAL"
    ).count()

    risk_level = calculate_ip_risk(
        failed_count,
        critical_count,
    )

    # IP için zaman pencereli Brute-Force kontrolü.
    brute_force_results = detect_brute_force_from_database(
        threshold=5,
        window_minutes=1,
    )

    brute_force_detected = any(
        item["ip_address"] == ip_address
        for item in brute_force_results
    )

    context = {
        "risk_level": risk_level,
        "ip_address": ip_address,
        "events": events,
        "total_events": total_events,
        "failed_count": failed_count,
        "successful_count": successful_count,
        "critical_count": critical_count,
        "brute_force_detected": brute_force_detected,
        "event_type_filter": event_type_filter,
        "severity_filter": severity_filter,
    }

    return render(
        request,
        "logs/ip_detail.html",
        context,
    )

from django.utils import timezone
from django.views.decorators.http import require_POST


def mark_alert_reviewed(request, alert_id):
    if request.method != "POST":
        return redirect("logs:dashboard")

    alert = SecurityAlert.objects.filter(id=alert_id).first()

    if alert is None:
        messages.error(
            request,
            "Güvenlik uyarısı bulunamadı."
        )
        return redirect("logs:dashboard")

    if not alert.is_reviewed:
        alert.is_reviewed = True
        alert.reviewed_at = timezone.now()
        alert.save(
            update_fields=["is_reviewed", "reviewed_at"]
        )

        messages.success(
            request,
            "Güvenlik uyarısı incelendi olarak işaretlendi."
        )
    else:
        messages.info(
            request,
            "Bu uyarı zaten incelenmiş."
        )

    return redirect("logs:dashboard")

