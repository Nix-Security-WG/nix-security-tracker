from django.urls import path

from .views import (
    MarkAllNotificationsReadView,
    NotificationCenterView,
    ToggleNotificationReadView,
)

app_name = "notifications"

urlpatterns = [
    path("", NotificationCenterView.as_view(), name="center"),
    path(
        "toggle-read/<int:notification_id>/",
        ToggleNotificationReadView.as_view(),
        name="toggle_read",
    ),
    path(
        "mark-all-read/", MarkAllNotificationsReadView.as_view(), name="mark_all_read"
    ),
]
