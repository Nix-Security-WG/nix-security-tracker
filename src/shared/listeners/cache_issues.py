import logging

import pgpubsub
from django.db.models import Prefetch

from shared.channels import NixpkgsIssueChannel
from shared.listeners.cache_suggestions import channel_structure
from shared.models.cached import CachedNixpkgsIssue, CachedNixpkgsIssuePayload
from shared.models.cve import AffectedProduct, IssueStatus, NixpkgsIssue
from shared.models.nix_evaluation import NixMaintainer

logger = logging.getLogger(__name__)


def cache_new_issue(issue: NixpkgsIssue) -> None:
    vulnerabilities = [
        CachedNixpkgsIssuePayload.Vulnerability(cve_id=cve.cve_id)
        for cve in issue.cve.all()
    ]
    derivations = list(
        issue.derivations.select_related("metadata", "parent_evaluation")
        .prefetch_related(
            "outputs",
            "dependencies",
            Prefetch(
                "metadata__maintainers",
                queryset=NixMaintainer.objects.distinct(),
                to_attr="prefetched_maintainers",
            ),
        )
        .all()
    )
    all_versions = list()
    # TODO For now we assume there is only one CVE associated to the issue
    cve = issue.cve.first()
    prefetched_affected_products = AffectedProduct.objects.filter(container__cve=cve)
    for affected_product in prefetched_affected_products:
        if affected_product.package_name:
            all_versions.extend(affected_product.versions.all())
    packages = channel_structure(all_versions, derivations)
    payload = CachedNixpkgsIssuePayload(
        status=IssueStatus(issue.status),
        created_at=issue.created,
        description=issue.description.value,
        packages=packages,
        vulnerabilities=vulnerabilities,
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
