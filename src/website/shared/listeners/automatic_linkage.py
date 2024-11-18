import logging

import pgpubsub

from shared.channels import ContainerChannel
from shared.models.cve import Container
from shared.models.linkage import CVEDerivationClusterProposal, ProvenanceFlags
from shared.models.nix_evaluation import NixDerivation

logger = logging.getLogger(__name__)


def produce_linkage_candidates(
    container: Container,
) -> dict[NixDerivation, ProvenanceFlags]:
    # Methodology:
    # We start with a large list and we remove things as we sort out that list.
    # Our initialization must be as large as possible.
    candidates: dict[NixDerivation, ProvenanceFlags] = {}
    for affected in container.affected.all():
        # TODO: record what is used to expand the candidate list.
        if affected.package_name is not None:
            drvs = set(
                # TODO: improve accuracy by performing case normalization.
                # TODO: improve accuracy by using bigrams similarity with a `| Q(...)` query.
                NixDerivation.objects.filter(name__contains=affected.package_name)
            )
            for d in drvs:
                if d in candidates:
                    candidates[d] |= ProvenanceFlags.PACKAGE_NAME_MATCH
                else:
                    candidates[d] = ProvenanceFlags.PACKAGE_NAME_MATCH

        # TODO: restrain further the list by checking all version constraints.
        # TODO: restrain further the list by checking hardware constraints or kernel constraints.
        # Remove anything that says that it's *not* the list of potential kernel that are in use:
        # macOS, Linux, Windows, *BSD.
        # TODO: teach it about newcomers kernels such as Redox.

    return candidates


def build_new_links(container: Container) -> None:
    if container.cve.triaged:
        logger.info(
            "Container received for '%s', but already triaged, skipping linkage.",
            container.cve,
        )
        return

    if CVEDerivationClusterProposal.objects.filter(cve=container.cve).exists():
        logger.warning(
            "Proposals already exist for '%s', skipping linkage.", container.cve
        )
        return

    drvs = produce_linkage_candidates(container)

    # only produce suggestions that have possible matches
    if drvs:
        proposal = CVEDerivationClusterProposal.objects.create(cve=container.cve)

        drvs_throughs = [
            CVEDerivationClusterProposal.derivations.through(
                proposal_id=proposal.pk, derivation_id=drv.pk, provenance_flags=flags
            )
            for drv, flags in drvs.items()
        ]

        # We create all the set in one shot.
        CVEDerivationClusterProposal.derivations.through.objects.bulk_create(
            drvs_throughs
        )

        if drvs_throughs:
            logger.info(
                "Matching suggestion for '%s': %d derivations found.",
                container.cve,
                len(drvs_throughs),
            )


@pgpubsub.post_insert_listener(ContainerChannel)
def build_new_links_following_new_containers(old: Container, new: Container) -> None:
    build_new_links(new)
