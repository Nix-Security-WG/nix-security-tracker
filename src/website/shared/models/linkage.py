from enum import STRICT, IntFlag, auto

import pghistory
from django.db import models
from django.utils.translation import gettext_lazy as _

import shared.models.cached
from shared.models.cve import CveRecord, Description, IssueStatus, NixpkgsIssue
from shared.models.nix_evaluation import NixDerivation, TimeStampMixin


def text_length(choices: type[models.TextChoices]) -> int:
    return max(map(len, choices.values))


@pghistory.track(fields=["status"])
class CVEDerivationClusterProposal(TimeStampMixin):
    """
    A proposal to link a CVE to a set of derivations.
    """

    class Status(models.TextChoices):
        PENDING = "pending", _("pending")
        REJECTED = "rejected", _("rejected")
        ACCEPTED = "accepted", _("accepted")
        PUBLISHED = "published", _("published")

    cached: "shared.models.cached.CachedSuggestions"

    cve = models.ForeignKey(
        CveRecord, related_name="derivation_links_proposals", on_delete=models.CASCADE
    )
    # NixDerivations of the same product and with a version in the affected range
    derivations = models.ManyToManyField(
        NixDerivation,
        related_name="cve_links_proposals",
        through="DerivationClusterProposalLink",
    )

    status = models.CharField(
        max_length=text_length(Status), choices=Status.choices, default=Status.PENDING
    )

    def create_nixpkgs_issue(self) -> NixpkgsIssue:
        """
        Create a NixpkgsIssue from this suggestion and save it in the database. Note
        that this doesn't create a corresponding GitHub issue; interaction with
        GitHub is handled separately in `shared.github`.
        """

        issue = NixpkgsIssue.objects.create(
            # By default we set the status to affected; a human might later
            # change the status if it turns out we're not affected in the
            # end.
            status=IssueStatus.AFFECTED,
            description=Description.objects.create(
                value=self.cached.payload["description"]
            ),
        )
        issue.cve.add(self.cve)
        issue.derivations.set(self.derivations.all())
        issue.save()
        return issue


class ProvenanceFlags(IntFlag, boundary=STRICT):
    PACKAGE_NAME_MATCH = auto()
    VERSION_CONSTRAINT_INRANGE = auto()
    VERSION_CONSTRAINT_OUTOFRANGE = auto()
    NO_SOURCE_VERSION_CONSTRAINT = auto()
    # Whether the hardware constraint is matched for this derivation.
    HARDWARE_CONSTRAINT_INRANGE = auto()
    KERNEL_CONSTRAINT_INRANGE = auto()


# CVEDerivationClusterProposal `derivations` changes have to be tracked via its `through` model.
@pghistory.track(
    pghistory.InsertEvent("derivations.add"),
    pghistory.DeleteEvent("derivations.remove"),
)
class DerivationClusterProposalLink(models.Model):
    """
    A link between a NixDerivation and a CVEDerivationClusterProposal.
    """

    proposal = models.ForeignKey(CVEDerivationClusterProposal, on_delete=models.CASCADE)

    derivation = models.ForeignKey(NixDerivation, on_delete=models.CASCADE)

    # TODO: how to design the integrity here?
    # we probably want to add a fancy check here.
    provenance_flags = models.IntegerField()
