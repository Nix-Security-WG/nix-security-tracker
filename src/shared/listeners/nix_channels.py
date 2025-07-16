import logging

import pgpubsub

from shared.channels import NixChannelChannel
from shared.models import NixChannel, NixEvaluation

logger = logging.getLogger(__name__)

# Those are channels we care about.
ADMISSIBLE_CHANNEL_STATES = (
    NixChannel.ChannelState.DEPRECATED,
    NixChannel.ChannelState.BETA,
    NixChannel.ChannelState.STABLE,
    NixChannel.ChannelState.UNSTABLE,
)


def enqueue_evaluation_job(channel: NixChannel) -> tuple[NixEvaluation, bool]:
    eval_job, created = NixEvaluation.objects.get_or_create(
        defaults={
            # We will leave the scheduling to the evaluation channel
            # listener.
            "state": NixEvaluation.EvaluationState.WAITING
        },
        channel=channel,
        commit_sha1=channel.head_sha1_commit,
    )
    logger.info(
        "Enqueued evaluation job %s (already existing: %r ?)", eval_job, created
    )
    return eval_job, created


@pgpubsub.post_update_listener(NixChannelChannel)
def start_evaluation_jobs_upon_updates(old: NixChannel, new: NixChannel) -> None:
    if old is None:
        logger.info("Nix channel created: %s", new.head_sha1_commit)
        if new.state in ADMISSIBLE_CHANNEL_STATES:
            enqueue_evaluation_job(new)
    else:
        # Channel updated.
        logger.info(
            "Nix channel updated: %s -> %s", old.head_sha1_commit, new.head_sha1_commit
        )
        if (
            old.head_sha1_commit != new.head_sha1_commit
            and new.state in ADMISSIBLE_CHANNEL_STATES
        ):
            enqueue_evaluation_job(new)
