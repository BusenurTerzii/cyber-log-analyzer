
from django.contrib import admin
from .models import SecurityEvent, SecurityAlert


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = (
        "timestamp",
        "ip_address",
        "event_type",
        "severity",
    )
    list_filter = ("event_type", "severity", "timestamp")
    search_fields = ("ip_address", "description")
    ordering = ("-timestamp",)


@admin.register(SecurityAlert)
class SecurityAlertAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "ip_address",
        "title",
        "severity",
        "is_reviewed",
        "reviewed_at",
    )
    list_filter = ("severity", "is_reviewed", "created_at")
    search_fields = ("ip_address", "title", "description")
    ordering = ("is_reviewed", "-created_at")
    readonly_fields = ("created_at", "reviewed_at")
