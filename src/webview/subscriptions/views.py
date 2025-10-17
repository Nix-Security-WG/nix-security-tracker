from typing import Any

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.views.generic import TemplateView

from shared.models import NixDerivation


class SubscriptionCenterView(LoginRequiredMixin, TemplateView):
    template_name = "subscriptions/subscriptions_center.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context["package_subscriptions"] = (
            self.request.user.profile.package_subscriptions
        )
        return context


def validate_package_exists(package_name: str) -> tuple[bool, str]:
    """
    Validate if a package exists and return validation result with error message.

    Returns:
        tuple: (is_valid, error_message)
    """
    # Sanitize input
    package_name = package_name.strip()

    if not package_name:
        return False, "Package name cannot be empty."

    # Check if package exists in NixDerivation
    if not NixDerivation.objects.filter(attribute=package_name).exists():
        return False, f"Package '{package_name}' does not exist."

    return True, ""


class AddSubscriptionView(LoginRequiredMixin, TemplateView):
    """Add a package subscription for the user."""

    template_name = "subscriptions/components/packages.html"

    def post(self, request: HttpRequest) -> HttpResponse:
        """Add a package subscription."""
        package_name = request.POST.get("package_name", "").strip()

        # Validate package exists
        is_valid, error_message = validate_package_exists(package_name)
        if not is_valid:
            return self._handle_error(request, error_message)

        # Check if already subscribed
        profile = request.user.profile
        if package_name in profile.package_subscriptions:
            return self._handle_error(
                request, f"You are already subscribed to '{package_name}'."
            )

        # Add subscription
        profile.package_subscriptions.append(package_name)
        profile.package_subscriptions.sort()
        profile.save(update_fields=["package_subscriptions"])

        # Handle HTMX vs standard request
        if request.headers.get("HX-Request"):
            return self.render_to_response(
                {
                    "package_subscriptions": profile.package_subscriptions,
                }
            )
        else:
            return redirect(reverse("webview:subscriptions:center"))

    def _handle_error(self, request: HttpRequest, error_message: str) -> HttpResponse:
        """Handle error responses for both HTMX and standard requests."""
        if request.headers.get("HX-Request"):
            return self.render_to_response(
                {
                    "package_subscriptions": request.user.profile.package_subscriptions,
                    "error_message": error_message,
                }
            )
        else:
            # Without javascript, we use Django messages for the errors
            messages.error(request, error_message)
            return redirect(reverse("webview:subscriptions:center"))


class RemoveSubscriptionView(LoginRequiredMixin, TemplateView):
    """Remove a package subscription for the user."""

    template_name = "subscriptions/components/packages.html"

    def post(self, request: HttpRequest) -> HttpResponse:
        """Remove a package subscription."""
        package_name = request.POST.get("package_name", "").strip()

        if not package_name:
            return self._handle_error(request, "Package name is required.")

        profile = request.user.profile

        # Check if subscribed
        if package_name not in profile.package_subscriptions:
            return self._handle_error(
                request, f"You are not subscribed to '{package_name}'."
            )

        # Remove subscription
        profile.package_subscriptions.remove(package_name)
        profile.save(update_fields=["package_subscriptions"])

        # Handle HTMX vs standard request
        if request.headers.get("HX-Request"):
            return self.render_to_response(
                {
                    "package_subscriptions": profile.package_subscriptions,
                }
            )
        else:
            return redirect(reverse("webview:subscriptions:center"))

    def _handle_error(self, request: HttpRequest, error_message: str) -> HttpResponse:
        """Handle error responses for both HTMX and standard requests."""
        if request.headers.get("HX-Request"):
            return self.render_to_response(
                {
                    "package_subscriptions": request.user.profile.package_subscriptions,
                    "error_message": error_message,
                }
            )
        else:
            # Without javascript, we use Django messages for the errors
            messages.error(request, error_message)
            return redirect(reverse("webview:subscriptions:center"))
