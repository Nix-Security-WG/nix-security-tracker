from typing import Any

from django.conf import settings

from shared.models import NixMaintainer


# Request utilities
def isadmin(user: Any) -> bool:
    return (
        user.is_staff or user.groups.filter(name=settings.GROUP_SECURITY_TEAM).exists()
    )


def iscommitter(user: Any) -> bool:
    return user.groups.filter(name=settings.GROUP_COMMITTERS).exists()


def ismaintainer(user: Any) -> bool:
    return NixMaintainer.objects.filter(github=user.username).exists()
