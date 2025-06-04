import logging
from datetime import date

import pgpubsub
from pydantic import BaseModel

from shared.channels import NixpkgsIssueChannel
from shared.models.cached import CachedNixpkgsIssue
from shared.models.cve import NixpkgsIssue

logger = logging.getLogger(__name__)


class CachedNixpkgsIssuePayload(BaseModel):
    class Vulnerability(BaseModel):
        cve_id: str

    class RelatedDerivation(BaseModel):
        class Maintainer(BaseModel):
            github: str
            name: str
            email: str
            # email: EmailStr

        name: str
        maintainers: list[Maintainer]

    status: str
    created_at: date
    description: str
    vulnerabilities: list[Vulnerability]
    related_derivations: list[RelatedDerivation]


def cache_new_issue(issue: NixpkgsIssue) -> None:
    status = issue.get_status_display()  # type: ignore
    created_at = issue.created
    description = issue.description.value
    vulnerabilities = [
        CachedNixpkgsIssuePayload.Vulnerability(cve_id=cve.cve_id)
        for cve in issue.cve.all()
    ]
    related_derivations = [
        CachedNixpkgsIssuePayload.RelatedDerivation(
            name=drv.name,
            maintainers=[
                CachedNixpkgsIssuePayload.RelatedDerivation.Maintainer(
                    github=maint.github,
                    name=maint.name,
                    email=maint.email or "",
                )
                for maint in drv.metadata.maintainers.all()
            ]
            if drv.metadata
            else [],
        )
        for drv in issue.derivations.all()
    ]
    payload = CachedNixpkgsIssuePayload(
        status=status,
        created_at=created_at,
        description=description,
        vulnerabilities=vulnerabilities,
        related_derivations=related_derivations,
    )
    _, created = CachedNixpkgsIssue.objects.update_or_create(
        issue=issue, payload=payload.model_dump(mode="json")
    )

    if created:
        logger.info("Issue '%s' cached for the first time", issue.code)
    else:
        logger.info("Issue '%s' cache updated", issue.code)


@pgpubsub.post_insert_listener(NixpkgsIssueChannel)
def cache_new_suggestions_following_new_container(
    old: NixpkgsIssue, new: NixpkgsIssue
) -> None:
    cache_new_issue(new)
