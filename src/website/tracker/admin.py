from typing import Any

from django.conf import settings
from django.contrib.admin import AdminSite
from django.contrib.admin.forms import AuthenticationForm  # type: ignore
from django.db import models


class CustomAdminSite(AdminSite):
    """
    App-specific admin site implementation
    """

    login_form = AuthenticationForm

    def has_permission(self, request: Any) -> bool:
        if not request.user.is_authenticated:
            return False

        return (
            request.user.is_staff
            or request.user.groups.filter(name=settings.GROUP_SECURITY_TEAM).exists()
        )


custom_admin_site = CustomAdminSite(name="CustomAdminSite")


class CustomPermissionsMixin:
    def has_view_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        if not request.user.is_authenticated:
            return False

        return (
            request.user.is_staff
            or request.user.groups.filter(name=settings.GROUP_SECURITY_TEAM).exists()
        )

    def has_change_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        if not request.user.is_authenticated:
            return False

        return (
            request.user.is_staff
            or request.user.groups.filter(name=settings.GROUP_SECURITY_TEAM).exists()
        )

    def has_add_permission(self, request: Any) -> bool:
        if not request.user.is_authenticated:
            return False

        return (
            request.user.is_staff
            or request.user.groups.filter(name=settings.GROUP_SECURITY_TEAM).exists()
        )

    def has_delete_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        if not request.user.is_authenticated:
            return False

        return (
            request.user.is_staff
            or request.user.groups.filter(name=settings.GROUP_SECURITY_TEAM).exists()
        )

    def has_module_permission(self, request: Any) -> bool:
        if not request.user.is_authenticated:
            return False

        return (
            request.user.is_staff
            or request.user.groups.filter(name=settings.GROUP_SECURITY_TEAM).exists()
        )
