import logging
from typing import Any

from django.core.management.base import BaseCommand
from shared.listeners.cache_issues import cache_new_issue
from shared.models.cached import CachedNixpkgsIssue
from shared.models.cve import NixpkgsIssue

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Regenerate cached nixpkgs issues"

    def handle(self, *args: Any, **kwargs: Any) -> None:
        # Expire all cached issues
        deleted, _ = CachedNixpkgsIssue.objects.all().delete()
        print(f"Cleared {deleted} cached issues")

        for issue in NixpkgsIssue.objects.all().iterator():
            cache_new_issue(issue)
