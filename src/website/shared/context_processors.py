from django.conf import settings
from django.http import HttpRequest


def app_version(request: HttpRequest) -> dict:
    rev = getattr(settings, "APP_REVISION", "Unknown revision")
    version = getattr(settings, "APP_VERSION", None)
    return {
        "app_version": version,
        "app_revision": rev
        if not rev == "0000000000000000000000000000000000000000"
        else "dirty",
    }
