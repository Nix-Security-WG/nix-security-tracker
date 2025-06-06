from datetime import date
from typing import ClassVar

from django.core.serializers.json import DjangoJSONEncoder
from django.db import models
from pydantic import BaseModel

from shared.models.cve import IssueStatus, NixpkgsIssue
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


class CachedNixpkgsIssuePayload(BaseModel):
    # TODO This version number will automatically tag cached issues in the
    # database (see cached.py). If you make modifications to the following
    # pydantic model, BUMP THIS VERSION NUMBER! This way, we will be able to
    # keep track of older representations of cached issues in the db and
    # automate how to process them.
    VERSION: ClassVar[int] = 1

    class Vulnerability(BaseModel):
        cve_id: str

    class RelatedDerivation(BaseModel):
        class Maintainer(BaseModel):
            github: str
            name: str
            email: str

        name: str
        maintainers: list[Maintainer]

    status: IssueStatus
    created_at: date
    description: str
    vulnerabilities: list[Vulnerability]
    related_derivations: list[RelatedDerivation]


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

    # This version number automatically follows the version defined in the
    # pydantic schema. See the comment above.
    version = models.PositiveIntegerField(default=CachedNixpkgsIssuePayload.VERSION)

    payload = models.JSONField()
