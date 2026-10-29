
from django.db import models


class SecurityEvent(models.Model):
    EVENT_TYPES = [
        ("LOGIN_SUCCESS", "Başarılı giriş"),
        ("LOGIN_FAILED", "Başarısız giriş"),
        ("SUSPICIOUS_IP", "Şüpheli IP"),
        ("OTHER", "Diğer"),
    ]

    SEVERITY_LEVELS = [
        ("LOW", "Düşük"),
        ("MEDIUM", "Orta"),
        ("HIGH", "Yüksek"),
        ("CRITICAL", "Kritik"),
    ]

    timestamp = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Kayıt zamanı",
    )
    ip_address = models.GenericIPAddressField(
        verbose_name="IP adresi",
    )
    event_type = models.CharField(
        max_length=30,
        choices=EVENT_TYPES,
        verbose_name="Olay türü",
    )
    severity = models.CharField(
        max_length=10,
        choices=SEVERITY_LEVELS,
        default="LOW",
        verbose_name="Önem seviyesi",
    )
    description = models.TextField(
        blank=True,
        verbose_name="Açıklama",
    )

    def __str__(self):
        return f"{self.ip_address} - {self.event_type}"


class SecurityAlert(models.Model):
    SEVERITY_LEVELS = [
        ("LOW", "Düşük"),
        ("MEDIUM", "Orta"),
        ("HIGH", "Yüksek"),
        ("CRITICAL", "Kritik"),
    ]

    ip_address = models.GenericIPAddressField(
        verbose_name="IP adresi",
    )
    title = models.CharField(
        max_length=200,
        verbose_name="Uyarı başlığı",
    )
    description = models.TextField(
        verbose_name="Uyarı açıklaması",
    )
    severity = models.CharField(
        max_length=10,
        choices=SEVERITY_LEVELS,
        default="MEDIUM",
        verbose_name="Önem seviyesi",
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Oluşturulma zamanı",
    )
    is_reviewed = models.BooleanField(
        default=False,
        verbose_name="İncelendi",
    )
    reviewed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="İncelenme zamanı",
    )

    class Meta:
        ordering = ["is_reviewed", "-created_at"]
        verbose_name = "Güvenlik uyarısı"
        verbose_name_plural = "Güvenlik uyarıları"

    def __str__(self):
        return f"{self.ip_address} - {self.title}"

        