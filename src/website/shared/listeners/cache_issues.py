import logging

import pgpubsub

from shared.channels import NixpkgsIssueChannel
from shared.models.cached import CachedNixpkgsIssue, CachedNixpkgsIssuePayload
from shared.models.cve import IssueStatus, NixpkgsIssue

logger = logging.getLogger(__name__)


def cache_new_issue(issue: NixpkgsIssue) -> None:
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
        status=IssueStatus(issue.status),
        created_at=issue.created,
        description=issue.description.value,
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
def cache_new_issue_following_insert(old: NixpkgsIssue, new: NixpkgsIssue) -> None:
    cache_new_issue(new)
