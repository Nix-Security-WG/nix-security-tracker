import logging
from itertools import chain
from typing import Any

import pgpubsub

from shared.channels import CVEDerivationClusterProposalChannel
from shared.models.cached import CachedSuggestions
from shared.models.cve import Severity
from shared.models.linkage import CVEDerivationClusterProposal

logger = logging.getLogger(__name__)


def to_dict(instance: Any) -> dict[str, Any]:
    opts = instance._meta
    data = {}
    for f in chain(opts.concrete_fields, opts.private_fields):
        if getattr(f, "foreign_related_fields", None) is not None:
            raw_value = getattr(instance, f.name)
            if raw_value is not None:
                data[f.name] = to_dict(raw_value)
            else:
                data[f.name] = None
        else:
            data[f.name] = f.value_from_object(instance)
    for f in opts.many_to_many:
        data[f.name] = [to_dict(i) for i in f.value_from_object(instance)]
    return data


def cache_new_suggestions(suggestion: CVEDerivationClusterProposal) -> None:
    # Pre-conditions:
    # - do we have any package_name attached?
    if (
        suggestion.cve.container.filter(affected__package_name__isnull=False).count()
        == 0
    ):
        return

    relevant_data = (
        suggestion.cve.container.prefetch_related("affected", "metrics", "descriptions")
        .values(
            "title",
            "affected__package_name",
            "metrics__base_severity",
            "descriptions__value",
        )
        .all()
    )

    relevant_piece = [x for x in relevant_data if "affected__package_name" in x]
    if not relevant_piece:
        # No package name.
        return
    relevant_piece = relevant_piece[0]

    # This is not a suggestion we want to show.
    if suggestion.derivations.count() > 1_000:
        return

    all_derivations = [
        to_dict(m)
        for m in suggestion.derivations.select_related("metadata", "parent_evaluation")
        .prefetch_related("outputs", "dependencies")
        .all()
        .iterator()
    ]

    only_relevant_data = {
        "package_name": relevant_piece["affected__package_name"],
        "base_severity": relevant_piece.get("metrics__base_severity", Severity.NONE)
        or Severity.NONE,
        "title": relevant_piece["title"],
        "description": relevant_piece["descriptions__value"],
        "derivations": all_derivations,
    }

    # TODO: add format checking to avoid disasters in the frontend.

    _, created = CachedSuggestions.objects.update_or_create(
        payload=dict(only_relevant_data), defaults={"proposal_id": suggestion.pk}
    )

    if created:
        logger.info(
            "CVE '%s' suggestion cached for the first time", suggestion.cve.cve_id
        )
    else:
        logger.info("CVE '%s' suggestion cache updated", suggestion.cve.cve_id)


# FIXME: this breaks the insert listener, let's report it upstream.
# @pgpubsub.post_update_listener(CVEDerivationClusterProposalChannel)
# def expire_cached_suggestions(old: CVEDerivationClusterProposal, new: CVEDerivationClusterProposal) -> None:
#     if new.status != CVEDerivationClusterProposal.Status.PENDING:
#         CachedSuggestions.objects.filter(pk=new.pk).delete()


@pgpubsub.post_insert_listener(CVEDerivationClusterProposalChannel)
def cache_new_suggestions_following_new_container(
    old: CVEDerivationClusterProposal, new: CVEDerivationClusterProposal
) -> None:
    cache_new_suggestions(new)
