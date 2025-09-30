from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.generic import ListView, TemplateView, View

from webview.models import Notification


class NotificationCenterView(LoginRequiredMixin, ListView):
    """Main notification center view showing user's notifications."""

    template_name = "notification_center.html"
    model = Notification
    context_object_name = "notifications"
    paginate_by = 2

    def get_queryset(self) -> QuerySet[Notification]:
        """Return notifications for the current user, ordered by creation date."""
        return Notification.objects.filter(user=self.request.user).order_by(
            "-created_at"
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add pagination context."""
        context = super().get_context_data(**kwargs)

        # Add adjusted page range for pagination (following existing pattern)
        context["adjusted_elided_page_range"] = context[
            "paginator"
        ].get_elided_page_range(context["page_obj"].number)

        return context


class MarkNotificationReadView(LoginRequiredMixin, TemplateView):
    """Mark a single notification as read - handles both HTMX and standard requests."""

    template_name = "components/notification.html"

    def post(self, request: HttpRequest, notification_id: int) -> HttpResponse:
        """Mark a specific notification as read."""
        notification = get_object_or_404(
            Notification, id=notification_id, user=request.user
        )

        if not notification.is_read:
            notification.is_read = True
            notification.save()

        # Check if this is an HTMX request
        if request.headers.get("HX-Request"):
            # Return the template with notification context
            return self.render_to_response({"notification": notification})
        else:
            # For standard requests (no js): redirect back to the notification center on the right page
            page = request.POST.get("page", "1")
            url = reverse("webview:notifications:center")
            return redirect(f"{url}?page={page}")


class MarkAllNotificationsReadView(LoginRequiredMixin, View):
    """HTMX endpoint to mark all notifications as read."""

    def post(self, request: HttpRequest) -> HttpResponse:
        """Mark all user's notifications as read."""
        Notification.objects.filter(user=request.user, is_read=False).update(
            is_read=True
        )

        # Check if this is an HTMX request
        if request.headers.get("HX-Request"):
            # Refresh the page using HX-Refresh header
            return HttpResponse(headers={"HX-Refresh": "true"})
        else:
            # For standard requests (no js): redirect back to the notification center on the right page
            page = request.POST.get("page", "1")
            url = reverse("webview:notifications:center")
            return redirect(f"{url}?page={page}")
