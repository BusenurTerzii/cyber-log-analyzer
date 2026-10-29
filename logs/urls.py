
from django.urls import path
from .views import (
    dashboard,
    download_json_report,
    ip_detail,
    mark_alert_reviewed,
)

app_name = "logs"

urlpatterns = [
    path("", dashboard, name="dashboard"),
    path("download-report/", download_json_report, name="download_report"),
    path("ip/<str:ip_address>/", ip_detail, name="ip_detail"),
    path(
        "alerts/<int:alert_id>/review/",
        mark_alert_reviewed,
        name="mark_alert_reviewed",
    ),
]
