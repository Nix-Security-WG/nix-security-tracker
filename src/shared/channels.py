from dataclasses import dataclass

from pgpubsub.channel import TriggerChannel

from shared.models import NixDerivation
from shared.models.cve import Container, NixpkgsIssue
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.nix_evaluation import NixChannel, NixEvaluation


@dataclass
class NixChannelChannel(TriggerChannel):
    """
    The name is unfortunate but this is a Django Channel
    for Nix Channel updates.
    """

    model = NixChannel


@dataclass
class NixEvaluationChannel(TriggerChannel):
    model = NixEvaluation
    # To avoid having a process blocked on the same evaluation multiple times.
    # We want to ensure that notifications are processed exactly once.
    # For this, we need to take a lock in the PostgreSQL database via `SELECT FOR UPDATE`
    # and let the pub-sub algorithm loop over available notifications with skip_locked.
    lock_notifications = True


@dataclass
class NixDerivationChannel(TriggerChannel):
    model = NixDerivation


@dataclass
class ContainerChannel(TriggerChannel):
    model = Container
    # Process new structured data for a CVE only once.
    lock_notifications = True


@dataclass
class CVEDerivationClusterProposalChannel(TriggerChannel):
    model = CVEDerivationClusterProposal
    # We don't need to lock notifications.
    # If we are caching twice the same proposal, we will just replace it.
    lock_notifications = False


@dataclass
class NixpkgsIssueChannel(TriggerChannel):
    model = NixpkgsIssue
    lock_notifications = False
