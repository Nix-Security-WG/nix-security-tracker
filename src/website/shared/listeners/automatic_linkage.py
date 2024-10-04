import logging

import pgpubsub

from shared.channels import ContainerChannel
from shared.models.cve import Container
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.nix_evaluation import NixDerivation

logger = logging.getLogger(__name__)


def produce_linkage_candidates(container: Container) -> set[NixDerivation]:
    # Methodology:
    # We start with a large list and we remove things as we sort out that list.
    # Our initialization must be as large as possible.
    candidates = set()
    for affected in container.affected.all():
        if affected.package_name is not None:
            candidates |= set(
                NixDerivation.objects.filter(name__contains=affected.package_name)
            )

    return candidates


@pgpubsub.post_insert_listener(ContainerChannel)
def build_new_links(old: Container, new: Container) -> None:
    if new.cve.triaged:
        logger.info(
            "New container received for '%s', but already triaged, skipping linkage.",
            new.cve,
        )
        return

    if CVEDerivationClusterProposal.objects.filter(cve=new.cve).exists():
        logger.warning("Proposals already exist for '%s', skipping linkage.", new.cve)
        return

    drvs = produce_linkage_candidates(new)
    proposal = CVEDerivationClusterProposal.objects.create(cve=new.cve)

    drvs_throughs = [
        CVEDerivationClusterProposal.derivations.through(
            cvederivationclusterproposal_id=proposal.pk, nixderivation_id=drv.pk
        )
        for drv in drvs
    ]

    # We create all the set in one shot.
    CVEDerivationClusterProposal.derivations.through.objects.bulk_create(drvs_throughs)

    if drvs_throughs:
        logger.info(
            "Matching suggestion for '%s': %d derivations found.",
            container.cve,
            len(drvs_throughs),
        )
