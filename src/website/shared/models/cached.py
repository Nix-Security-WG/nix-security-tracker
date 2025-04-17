from django.core.serializers.json import DjangoJSONEncoder
from django.db import models

from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.nix_evaluation import TimeStampMixin


class CachedSuggestions(TimeStampMixin):
    """
    A cached consolidated view of suggestions.
    """

    proposal = models.OneToOneField(
        CVEDerivationClusterProposal,
        related_name="cached",
        on_delete=models.CASCADE,
        primary_key=True,
    )

    # The exact format of this payload will change until it's properly defined.
    payload = models.JSONField(encoder=DjangoJSONEncoder)

    @property
    def all_maintainers(self) -> list[dict]:
        """
        Returns a deduplicated and sorted (by GitHub handle) list of all the
        maintainers of all the affected packages linked to this suggestion.
        """

        dedup = [
            dict(deduped)
            for deduped in {
                tuple(maintainer.items())
                for package in self.payload["packages"].values()
                for maintainer in package["maintainers"]
            }
        ]
        return sorted(dedup, key=lambda x: x["github"])
