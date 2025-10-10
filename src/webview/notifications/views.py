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

    template_name = "notifications/notification_center.html"
    model = Notification
    context_object_name = "notifications"
    paginate_by = 10

    def get_queryset(self) -> QuerySet[Notification]:
        """Return notifications for the current user, in descending order by creation date."""
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


class ToggleNotificationReadView(LoginRequiredMixin, TemplateView):
    """Toggle a single notification's read status - handles both HTMX and standard requests."""

    template_name = "notifications/components/notification.html"

    def post(self, request: HttpRequest, notification_id: int) -> HttpResponse:
        """Toggle a specific notification's read status."""
        # Use manager method to toggle and update counter
        new_unread_count = Notification.objects.toggle_read_for_user(
            request.user, notification_id
        )

        # Get the notification for template rendering
        notification = get_object_or_404(
            Notification, id=notification_id, user=request.user
        )

        # Check if this is an HTMX request
        if request.headers.get("HX-Request"):
            # Return the template with notification context
            return self.render_to_response(
                {"notification": notification, "new_unread_count": new_unread_count}
            )
        else:
            # For standard requests (no js): redirect back to the notification center on the right page
            page = request.POST.get("page", "1")
            url = reverse("webview:notifications:center")
            return redirect(f"{url}?page={page}")


class MarkAllNotificationsReadView(LoginRequiredMixin, View):
    """Endpoint to mark all notifications as read."""

    def post(self, request: HttpRequest) -> HttpResponse:
        """Mark all user's notifications as read."""
        # Use manager method to mark all as read and update counter
        Notification.objects.mark_all_read_for_user(request.user)

        # Check if this is an HTMX request
        if request.headers.get("HX-Request"):
            # Refresh the page using HX-Refresh header
            return HttpResponse(headers={"HX-Refresh": "true"})
        else:
            # For standard requests (no js): redirect back to the notification center on the right page
            page = request.POST.get("page", "1")
            url = reverse("webview:notifications:center")
            return redirect(f"{url}?page={page}")


class RemoveAllReadNotificationsView(LoginRequiredMixin, View):
    """Endpoint to remove all read notifications."""

    def post(self, request: HttpRequest) -> HttpResponse:
        """Remove all user's read notifications."""
        # Use manager method to clear read notifications
        Notification.objects.clear_read_for_user(request.user)

        # Let's redirect to first page as were we are might no longer exist
        url = reverse("webview:notifications:center")
        # Check if this is an HTMX request
        if request.headers.get("HX-Request"):
            return HttpResponse(headers={"HX-Redirect": url})
        else:
            return redirect(url)
