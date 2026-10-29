
from datetime import timedelta


def calculate_ip_risk(failed_count, critical_count):
    if critical_count >= 1 or failed_count >= 5:
        return "Yüksek"
    elif failed_count >= 3:
        return "Orta"
    return "Düşük"


def detect_brute_force(
    failed_count,
    threshold=5,
):
    """
    Zaman aralığı kontrol edilmeden yapılan
    basit başarısız giriş sayısı kontrolü.
    """
    return failed_count >= threshold



def detect_brute_force_in_window(
    failed_timestamps,
    threshold=5,
    window_minutes=1,
):
    """
    Belirlenen zaman penceresi içinde threshold kadar
    başarısız giriş varsa True döndürür.
    """
    if threshold <= 0 or window_minutes < 0:
        raise ValueError(
            "threshold pozitif, window_minutes negatif olmayan bir değer olmalı."
        )

    timestamps = sorted(failed_timestamps)

    if len(timestamps) < threshold:
        return False

    window = timedelta(minutes=window_minutes)
    left = 0

    for right in range(len(timestamps)):
        while (
            left < right
            and timestamps[right] - timestamps[left] > window
        ):
            left += 1

        if right - left + 1 >= threshold:
            return True

    return False



def classify_ip_activity(failed_count, critical_count):
    """
    IP adresinin risk seviyesini ve olası saldırı
    davranışını mevcut sayım yöntemine göre belirler.
    """
    risk_level = calculate_ip_risk(
        failed_count,
        critical_count,
    )

    brute_force_detected = detect_brute_force(
        failed_count,
    )

    if brute_force_detected:
        activity = "Olası Brute-Force Saldırısı"
    elif failed_count >= 3:
        activity = "Tekrarlanan Başarısız Giriş"
    else:
        activity = "Normal veya Düşük Şüphe"

    return {
        "risk_level": risk_level,
        "brute_force_detected": brute_force_detected,
        "activity": activity,
    }
