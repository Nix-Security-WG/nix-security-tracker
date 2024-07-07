from typing import Any

from django.contrib.admin import AdminSite
from django.contrib.admin.forms import AuthenticationForm  # type: ignore
from shared.auth import isadmin


class CustomAdminSite(AdminSite):
    """
    App-specific admin site implementation
    """

    login_form = AuthenticationForm

    def has_permission(self, request: Any) -> bool:
        if not request.user.is_authenticated:
            return False

        return request.user.is_staff or isadmin(request)


custom_admin_site = CustomAdminSite(name="CustomAdminSite")
