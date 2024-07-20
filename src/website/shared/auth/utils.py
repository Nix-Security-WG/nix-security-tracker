from typing import Any

from django.conf import settings

from shared.models import NixMaintainer


# Request utilities
def isadmin(user: Any) -> bool:
    return user.is_staff or user.groups.filter(name=settings.DB_SECURITY_TEAM).exists()


def iscommitter(user: Any) -> bool:
    return user.groups.filter(name=settings.DB_COMMITTERS_TEAM).exists()


def ismaintainer(user: Any) -> bool:
    return NixMaintainer.objects.filter(
        github_id=user.socialaccount_set.get(provider="github").uid
    ).exists()
