from django.urls import path

from .views import (
    MarkAllNotificationsReadView,
    MarkNotificationReadView,
    NotificationCenterView,
)

app_name = "notifications"

urlpatterns = [
    path("", NotificationCenterView.as_view(), name="center"),
    path(
        "mark-read/<int:notification_id>/",
        MarkNotificationReadView.as_view(),
        name="mark_read",
    ),
    path(
        "mark-all-read/", MarkAllNotificationsReadView.as_view(), name="mark_all_read"
    ),
]
