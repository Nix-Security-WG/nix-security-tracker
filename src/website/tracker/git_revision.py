from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest


def git_revision(request: HttpRequest) -> dict[str, str]:
    revision = cache.get("git_revision")
    if revision is None:
        try:
            revision = settings.REVISION
        except Exception:
            revision = "unknown"
        cache.set("git_revision", revision, timeout=None)  # cache indefinitely
    return {"git_revision": revision}
