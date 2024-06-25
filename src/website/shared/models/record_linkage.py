from django.db import models
from django.utils.translation import gettext_lazy as _

from .cve import Container, text_length
from .nix_evaluation import NixDerivation


class LinkageCandidate(models.Model):
    """Class representing matches for linking CVEs and packages."""

    class CandidateState(models.TextChoices):
        UNTRIAGED = "UNTRIAGED", _("UNTRIAGED")
        ACCEPTED = "ACCEPTED", _("ACCEPTED")
        REJECTED = "REJECTED", _("REJECTED")

    container = models.ForeignKey(
        Container, related_name="linkage_candidate", on_delete=models.CASCADE
    )
    derivation = models.ForeignKey(
        NixDerivation, related_name="linkage_candidate", on_delete=models.CASCADE
    )

    state = models.CharField(
        max_length=text_length(CandidateState),
        choices=CandidateState.choices,
        default=CandidateState.UNTRIAGED,
    )

    # We probably will want to have also a reason field to justify rejection
    # and a way to document the heuristics that generated the match.
