import subprocess

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest


def git_revision(request: HttpRequest) -> dict[str, str]:
    revision = cache.get("git_revision")
    if revision is None:
        try:
            project_root = settings.BASE_DIR
            revision = (
                subprocess.check_output(
                    ["git", "rev-parse", "--short", "HEAD"],
                    cwd=project_root,
                    stderr=subprocess.DEVNULL,
                )
                .decode("utf-8")
                .strip()
            )
        except Exception:
            revision = "unknown"
        cache.set("git_revision", revision, timeout=None)  # cache indefinitely
    return {"git_revision": revision}
