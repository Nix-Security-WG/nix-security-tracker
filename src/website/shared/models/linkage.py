from django.db import models
from django.utils.translation import gettext_lazy as _

from shared.models.cve import CveRecord
from shared.models.nix_evaluation import NixDerivation, TimeStampMixin


def text_length(choices: type[models.TextChoices]) -> int:
    return max(map(len, choices.values))


class CVEDerivationClusterProposal(TimeStampMixin):
    """
    A proposal to link a CVE to a set of derivations.
    """

    class Status(models.TextChoices):
        PENDING = "pending", _("pending")
        REJECTED = "rejected", _("rejected")
        ACCEPTED = "accepted", _("accepted")

    cve = models.ForeignKey(
        CveRecord, related_name="derivation_links_proposals", on_delete=models.CASCADE
    )
    # NixDerivations of the same product and with a version in the affected range
    derivations = models.ManyToManyField(
        NixDerivation, related_name="cve_links_proposals"
    )

    status = models.CharField(
        max_length=text_length(Status), choices=Status.choices, default=Status.PENDING
    )
