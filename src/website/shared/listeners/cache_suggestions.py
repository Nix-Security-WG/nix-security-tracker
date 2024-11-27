import logging
import re
from itertools import chain
from typing import Any

import pgpubsub

from shared.channels import CVEDerivationClusterProposalChannel
from shared.models import NixDerivation
from shared.models.cached import CachedSuggestions
from shared.models.cve import AffectedProduct, Severity, Version
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.nix_evaluation import get_major_channel

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
            # Only used for relevance checking
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

    affected_products = dict()
    all_versions = list()
    prefetched_affected_products = AffectedProduct.objects.filter(
        container__cve=suggestion.cve
    )
    for affected_product in prefetched_affected_products:
        if affected_product.package_name:
            all_versions.extend(affected_product.versions.all())
            if affected_product.package_name not in affected_products:
                affected_products[affected_product.package_name] = {
                    "version_constraints": set(),
                    "cpes": set(),
                }
            affected_products[affected_product.package_name][
                "version_constraints"
            ].update(
                [
                    (vc.status, vc.version_constraint_str())
                    for vc in affected_product.versions.all()
                ]
            )
            affected_products[affected_product.package_name]["cpes"].update(
                [cpe.name for cpe in affected_product.cpes.all()]
            )
    for package_name, data in affected_products.items():
        affected_products[package_name]["version_constraints"] = list(
            data["version_constraints"]
        )
        affected_products[package_name]["cpes"] = list(data["cpes"])

    derivations = (
        suggestion.derivations.select_related("metadata", "parent_evaluation")
        .prefetch_related("outputs", "dependencies")
        .all()
    )

    only_relevant_data = {
        "pk": suggestion.pk,
        "cve_id": suggestion.cve.cve_id,
        "package_name": relevant_piece["affected__package_name"],
        "base_severity": relevant_piece.get("metrics__base_severity", Severity.NONE)
        or Severity.NONE,
        "title": relevant_piece["title"],
        "description": relevant_piece["descriptions__value"],
        "affected_products": affected_products,
        "packages": channel_structure(all_versions, list(derivations)),
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


def is_version_affected(version_statuses: list[str]) -> Version.Status:
    """
    Basically just sums list of version constraints statuses.
    When in doubt, we:
    - Choose Affected over Unknown
    - Choose Unknown over Unaffected
    - Choose Affected over Unaffected
    """
    result = Version.Status.UNKNOWN
    for status in version_statuses:
        if status == result:
            pass
        elif (
            status == Version.Status.AFFECTED and result == Version.Status.UNKNOWN
        ) or (status == Version.Status.UNKNOWN and result == Version.Status.AFFECTED):
            result = Version.Status.AFFECTED
        elif (
            status == Version.Status.UNKNOWN and result == Version.Status.UNAFFECTED
        ) or (status == Version.Status.UNAFFECTED and result == Version.Status.UNKNOWN):
            result = Version.Status.UNKNOWN
        elif (
            status == Version.Status.AFFECTED and result == Version.Status.UNAFFECTED
        ) or (
            status == Version.Status.UNAFFECTED and result == Version.Status.AFFECTED
        ):
            result = Version.Status.AFFECTED
        else:
            assert False, f"Unreachable code: {status} {result}"
    return result


def channel_structure(
    version_constraints: list[Version], derivations: list[NixDerivation]
) -> dict:
    """
    For a list of derivations, massage the data so that in can rendered easily in the suggestions view
    """
    packages = dict()
    for derivation in derivations:
        attribute = derivation.attribute.removesuffix(f".{derivation.system}")
        _, version = parse_drv_name(derivation.name)
        if attribute not in packages:
            packages[attribute] = {
                "versions": {},
                "derivation_ids": [],
            }
            if derivation.metadata and derivation.metadata.description:
                packages[attribute]["description"] = derivation.metadata.description
        packages[attribute]["derivation_ids"].append(derivation.pk)
        branch_name = derivation.parent_evaluation.channel.channel_branch
        major_channel = get_major_channel(branch_name)
        # FIXME This quietly drops unfamiliar branch names
        if major_channel:
            if major_channel not in packages[attribute]["versions"]:
                packages[attribute]["versions"][major_channel] = {
                    "major_version": None,
                    "status": None,
                    "uniform_versions": None,
                    "sub_branches": dict(),
                }
            if not branch_name == major_channel:
                packages[attribute]["versions"][major_channel]["sub_branches"][
                    branch_name
                ] = {
                    "version": version,
                    "status": is_version_affected(
                        [v.is_affected(version) for v in version_constraints]
                    ),
                }
            else:
                packages[attribute]["versions"][major_channel]["major_version"] = (
                    version
                )
    for package_name in packages:
        for mc in packages[package_name]["versions"].keys():
            uniform_versions = True
            major_version = packages[package_name]["versions"][mc]["major_version"]
            packages[package_name]["versions"][mc]["status"] = is_version_affected(
                [v.is_affected(major_version) for v in version_constraints]
            )
            for _branch_name, vdata in packages[package_name]["versions"][mc][
                "sub_branches"
            ].items():
                uniform_versions = (
                    uniform_versions and str(major_version) == vdata["version"]
                )
            packages[package_name]["versions"][mc]["uniform_versions"]
            # We just sort branch names by length to get a good-enough order
            packages[package_name]["versions"][mc]["sub_branches"] = sorted(
                packages[package_name]["versions"][mc]["sub_branches"].items(),
                reverse=True,
                key=lambda item: len(item[0]),
            )
        # Sorting major channel names happens to work out well for bringing them into historical order
        packages[package_name]["versions"] = sorted(
            packages[package_name]["versions"].items()
        )
    return packages


def parse_drv_name(name: str) -> tuple[str, str]:
    """
    Splits the input string `name` into a package name and version.

    https://nix.dev/manual/nix/latest/language/builtins.html#builtins-parseDrvName

    The package name is everything up to but not including the first dash
    not followed by a letter, and the version is everything after that dash.
    """
    match = re.match(r"^(.+?)-([^-]*\d.*)$", name)
    if match:
        return match.group(1), match.group(2)
    else:
        return name, ""
