from django.core.serializers.json import DjangoJSONEncoder
from django.db import models

from shared.models.cve import NixpkgsIssue
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


class CachedNixpkgsIssue(models.Model):
    """
    A cached view of published issues
    """

    issue = models.OneToOneField(
        NixpkgsIssue,
        related_name="cached",
        on_delete=models.CASCADE,
        primary_key=True,
    )

    payload = models.JSONField()
