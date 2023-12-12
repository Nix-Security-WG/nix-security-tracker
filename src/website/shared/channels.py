from dataclasses import dataclass

from pgpubsub.channel import TriggerChannel

from shared.models import NixDerivation
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


@dataclass
class NixDerivationChannel(TriggerChannel):
    model = NixDerivation
