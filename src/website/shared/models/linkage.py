from enum import STRICT, IntFlag, auto
from typing import Any

import pghistory
from django.db import models
from django.db.models.signals import m2m_changed, post_save
from django.dispatch import receiver
from django.utils.translation import gettext_lazy as _

import shared.models.cached
from shared.models.cve import CveRecord
from shared.models.nix_evaluation import NixDerivation
from shared.models.timestamps import TimeStampWithWritableUpdatedAtMixin


def text_length(choices: type[models.TextChoices]) -> int:
    return max(map(len, choices.values))


@pghistory.track(fields=["status"])
class CVEDerivationClusterProposal(TimeStampWithWritableUpdatedAtMixin):
    """
    A proposal to link a CVE to a set of derivations.
    """

    class Status(models.TextChoices):
        PENDING = "pending", _("pending")
        REJECTED = "rejected", _("rejected")
        ACCEPTED = "accepted", _("accepted")

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


@receiver(post_save, sender=CVEDerivationClusterProposal)
@receiver(m2m_changed, sender=DerivationClusterProposalLink)
def sync_proposals_updated_at(
    sender: CVEDerivationClusterProposal | DerivationClusterProposalLink,
    instance: CVEDerivationClusterProposal,
    **kwargs: dict[str, Any],
) -> None:
    """Keep proposal's `updated_at` field in sync with last relevant update.

    From this function we can import `DerivationClusterProposalLinkEvent`
    without import errors. When we try to import it at the module level,
    there is an error about `shared.models` being partially initialized.
    This is happening because the `Event` models get dynamically added by
    the `@pghistory.track` decorators. The alternatives to having the import
    in the function are:
        - Creating the Event model explicitly.
        - Using `instance.derivations.through.pgh_event_model` where
          `DerivationClusterProposalLinkEvent` is used. However, that
          expression is less readable.

    Keeping `updated_at` in sync would be done more safely with Postgres triggers.
    However, introducing them for this case would involve hardcoding table names.
    Consider changing this logic to triggers once upstream's proposal to support
    Django templating to generate triggers that involve different tables
    (such as this denormalization sync):
        - https://github.com/Opus10/django-pgtrigger/discussions/165
    """
    from shared.models import DerivationClusterProposalLinkEvent  # type: ignore

    last_inserted_timestamp = instance.updated_at

    if sender == CVEDerivationClusterProposal:
        if kwargs["update_fields"] and "status" in kwargs["update_fields"]:
            last_inserted_timestamp = instance.status_events.order_by(  # type: ignore
                "-pgh_created_at"
            ).values_list("pgh_created_at", flat=True)[0]

    else:
        if kwargs["action"] and kwargs["action"] == "post_remove":
            last_inserted_timestamp = (
                DerivationClusterProposalLinkEvent.objects.filter(
                    proposal_id=instance.pk
                )
                .order_by("-pgh_created_at")
                .values_list("pgh_created_at", flat=True)[0]
            )

    if instance.updated_at is None or last_inserted_timestamp > instance.updated_at:  # type: ignore
        instance.updated_at = last_inserted_timestamp
        instance.save()
