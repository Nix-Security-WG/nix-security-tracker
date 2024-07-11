from typing import Any

from django.contrib.admin import AdminSite
from django.contrib.admin.forms import AuthenticationForm  # type: ignore
from shared.auth import isadmin, iscommitter, ismaintainer


class CustomAdminSite(AdminSite):
    """
    App-specific admin site implementation
    """

    login_form = AuthenticationForm

    def has_permission(self, request: Any) -> bool:
        if not request.user.is_authenticated:
            return False

        return (
            isadmin(request.user)
            or iscommitter(request.user)
            or ismaintainer(request.user)
        )


custom_admin_site = CustomAdminSite(name="CustomAdminSite")
