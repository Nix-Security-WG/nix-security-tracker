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
    # TODO: for now we blindly list all maintainers of all affected packages,
    # but in the future we might want to be able to edit this list before
    # creating the GitHub issue. When that happens, this function will need to
    # be updated (or the GitHub creation code should use a distinct
    # `maintainers()` property, for example).
    def all_maintainers(self) -> list[dict]:
        """
        Returns a deduplicated list (by GitHub ID) of all the maintainers of all
        the affected packages linked to this suggestion.
        """

        seen = set()
        result = []
        all_maintainers = [
            m for pkg in self.payload["packages"].values() for m in pkg["maintainers"]
        ]

        for m in all_maintainers:
            if m["github_id"] not in seen:
                seen.add(m["github_id"])
                result.append(m)

        return result
