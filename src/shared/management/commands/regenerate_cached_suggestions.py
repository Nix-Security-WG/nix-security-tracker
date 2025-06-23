import logging
from typing import Any

from django.core.management.base import BaseCommand

from shared.listeners.cache_suggestions import cache_new_suggestions
from shared.models.cached import CachedSuggestions
from shared.models.linkage import CVEDerivationClusterProposal

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Regenerate cached suggestions"

    def handle(self, *args: Any, **kwargs: Any) -> None:
        # Expire all cached suggestions
        deleted, _ = CachedSuggestions.objects.all().delete()
        print(f"Cleared {deleted} cached suggestions")

        for suggestion in CVEDerivationClusterProposal.objects.all().iterator():
            cache_new_suggestions(suggestion)
