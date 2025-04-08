import asyncio
import json
import logging
import pathlib
import random
import tempfile
import time
from collections.abc import AsyncGenerator

import aiofiles
import pgpubsub
from asgiref.sync import sync_to_async
from django.conf import settings
from django.db.models import Avg

from shared.channels import NixEvaluationChannel, NixEvaluationCompleteChannel
from shared.evaluation import (
    SyncBatchAttributeIngester,
    parse_evaluation_result,
)
from shared.git import GitRepo
from shared.listeners.cache_suggestions import cache_new_suggestions
from shared.models import NixDerivation, NixEvaluation
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
)

logger = logging.getLogger(__name__)

SIGSEGV = 137
SIGABRT = 134


async def perform_evaluation(
    working_tree: pathlib.Path, evaluation_log_fd: int, limit: int = 16 * 1024 * 1024
) -> asyncio.subprocess.Process:
    """
    This will run `nix-eval-jobs` on the working tree as a nixpkgs
    input and collect all Hydra jobs, including insecure ones.

    `limit` is the stream reader buffer limit.

    By default, we use 16MB which should give enough time to consume all
    the chunks in time and buffer enough of the evaluation attributes.

    This will return an asynchronous process you can use to control
    the execution runtime.
    """
    # TODO(raitobezarius): bring a Nix code generator, that'd be cuter.
    nixpkgs_config = "{ config = { allowUnfree = true; inHydra = false; allowInsecurePredicate = (_: true); scrubJobs = false; }; };"
    evaluation_wrapper = f"(import <nixpkgs/pkgs/top-level/release.nix> {{ nixpkgsArgs = {nixpkgs_config} }})"
    arguments = [
        "--force-recurse",
        "--meta",
        "--repair",
        "--quiet",
        "--gc-roots-dir",
        settings.EVALUATION_GC_ROOTS_DIRECTORY,
        "--expr",
        evaluation_wrapper,
        "--include",
        f"nixpkgs={working_tree}",
    ]
    return await asyncio.create_subprocess_exec(
        "nix-eval-jobs",
        *arguments,
        limit=limit,
        stdout=asyncio.subprocess.PIPE,
        stderr=evaluation_log_fd,
    )


async def realtime_batch_process_attributes(
    parent_evaluation: NixEvaluation, attributes: list[str]
) -> None | list[NixDerivation]:
    """
    Performs a real-time processing of a batch of attributes
    using bulk staging operations.
    """
    evaluated = []

    for attribute in attributes:
        try:
            partial_eval = parse_evaluation_result(attribute)
            eval_ = partial_eval.evaluation
            if eval_ is None:
                # Too noisy.
                # logger.debug(
                #    "Attribute '%s' does not have a proper evaluated body, skipping...",
                #    partial_eval.attr,
                # )
                continue
            evaluated.append(eval_)
        except KeyError:
            logger.exception(
                "Attribute '%s' does not have the key 'evaluation'", attribute
            )
        except json.decoder.JSONDecodeError:
            logger.exception("Attribute '%s' cannot be parsed in JSON", attribute)

    # Nothing to do here.
    if not evaluated:
        # We don't warn or error here
        # This is too noisy otherwise.
        logger.debug(
            "No attribute evaluated successfully, moving on",
        )
        return None

    start = time.time()
    ingester = SyncBatchAttributeIngester(evaluated)
    await sync_to_async(ingester.initialize)()
    drvs = await sync_to_async(ingester.ingest)(parent_evaluation)

    elapsed = time.time() - start
    logger.info("%d attributes were ingested in %f seconds", len(drvs), elapsed)

    return drvs


async def drain_lines(
    stream: asyncio.StreamReader, timeout: float = 0.25, max_batch_window: int = 10_000
) -> AsyncGenerator[list[bytes], None]:
    """
    This utility will perform an opportunistic line draining
    operation on a StreamReader, the timeout will be reset
    every time we obtain another line.
    """
    lines = []
    eof = False

    class TooManyStuff(BaseException):
        pass

    while not eof:
        try:
            async with asyncio.timeout(timeout) as cm:
                lines.append(await stream.readline())
                old_deadline = cm.when()
                assert (
                    old_deadline is not None
                ), "Timeout context does not have timeout!"
                new_deadline = old_deadline + timeout
                cm.reschedule(new_deadline)

            if len(lines) >= max_batch_window:
                raise TooManyStuff
        except (TimeoutError, TooManyStuff):
            # No line, we retry.
            if len(lines) == 0:
                continue
            # Last line is EOF, so there won't be more lines.
            while lines and (
                lines[-1] == b"" or lines[-1].decode("utf8").strip() == ""
            ):
                eof = True
                # Drop the last line.
                lines = lines[:-1]
            # If we had lines = ["", ...], we just break immediately, there's nothing to yield anymore.
            if not lines:
                break

            yield lines
            lines = []

    assert eof, "Reached the end of `drain_lines` without EOF!"


async def evaluation_entrypoint(
    avg_eval_time: float, evaluation: NixEvaluation
) -> None:
    while (
        await NixEvaluation.objects.filter(
            state=NixEvaluation.EvaluationState.IN_PROGRESS
        ).acount()
    ) > settings.MAX_PARALLEL_EVALUATION:
        # Add in average 30s as a jitter to enable clear winners during the grab for the evaluation slot.
        jitter = random.randint(1, 60)
        await asyncio.sleep(avg_eval_time + jitter)
    # Atomically update the state to prevent anyone going over the
    # specified concurrency.
    await NixEvaluation.objects.filter(id=evaluation.pk).aupdate(
        state=NixEvaluation.EvaluationState.IN_PROGRESS
    )
    repo = GitRepo(settings.LOCAL_NIXPKGS_CHECKOUT)
    start = time.time()
    try:
        # Pull our local checkout up to that evaluation revision.
        await repo.update_from_ref(evaluation.commit_sha1)
        with tempfile.TemporaryDirectory() as working_tree_path:
            # Extract a working tree out of it for our needs.
            evaluation_log_filepath = (
                pathlib.Path(settings.EVALUATION_LOGS_DIRECTORY)
                / f"evaluation-{evaluation.commit_sha1}.log"
            )
            async with (
                repo.extract_working_tree(
                    evaluation.commit_sha1, working_tree_path
                ) as working_tree,
                aiofiles.open(evaluation_log_filepath, "w") as eval_log,
            ):
                # Kickstart the evaluation asynchronously.
                eval_process = await perform_evaluation(
                    working_tree.path, eval_log.fileno()
                )
                assert (
                    eval_process.stdout is not None
                ), "Expected a valid `stdout` pipe for the asynchronous evaluation process"

                # The idea here is that we want to match as close as possible
                # our evaluation speed. So, we read as much lines as possible
                # and then insert them During the insertion time, more lines
                # may come in our internal buffer. On the next read, we will
                # drain them again.
                # Adding an item in the database takes around 1s max.
                # So we don't want to wait more than one second for all the lines we can get.
                count = 0
                async for lines in drain_lines(eval_process.stdout):
                    await realtime_batch_process_attributes(
                        evaluation, [line.decode("utf8") for line in lines]
                    )
                    count += len(lines)
                # Wait for `nix-eval-jobs` to exit, at this point,
                # It should be fairly quick because EOF has been reached.
                rc = await eval_process.wait()
                elapsed = time.time() - start
                if rc in (SIGSEGV, SIGABRT):
                    raise RuntimeError("`nix-eval-jobs` crashed!")
                elif rc != 0:
                    logger.error(
                        "`nix-eval-jobs` failed to evaluate (non-zero exit status), check the evaluation logs"
                    )
                    await NixEvaluation.objects.filter(id=evaluation.pk).aupdate(
                        state=NixEvaluation.EvaluationState.FAILED,
                        elapsed=elapsed,
                    )
                else:
                    logger.info(
                        "Processed %d derivations in real-time in %f seconds",
                        count,
                        elapsed,
                    )
                    await NixEvaluation.objects.filter(id=evaluation.pk).aupdate(
                        state=NixEvaluation.EvaluationState.COMPLETED,
                        elapsed=elapsed,
                    )

                    # Notify that we have a new evaluation ready and
                    # any listeners should now proceed to an global update of old derivations
                    # via attribute path.
                    pgpubsub.notify(
                        "shared.channels.NixEvaluationCompleteChannel",
                        model_id=evaluation.pk,
                    )
    except Exception as e:
        elapsed = time.time() - start
        logger.exception(
            "Failed to run the `nix-eval-job` on revision '%s', marking job as crashed...",
            evaluation.commit_sha1,
        )
        await NixEvaluation.objects.filter(id=evaluation.pk).aupdate(
            state=NixEvaluation.EvaluationState.CRASHED,
            elapsed=elapsed,
            failure_reason=str(e),
        )


@pgpubsub.post_insert_listener(NixEvaluationChannel)
def run_evaluation_job(old: NixEvaluation, new: NixEvaluation) -> None:
    average_evaluation_time = NixEvaluation.objects.aggregate(
        avg_eval_time=Avg("elapsed")
    )
    if average_evaluation_time is not None:
        average_evaluation_time = average_evaluation_time["avg_eval_time"]
    if average_evaluation_time is not None:
        logger.info(
            "Nix evaluation requested: %s, expecting to finish in %f seconds",
            new.commit_sha1,
            average_evaluation_time,
        )
    else:
        logger.info("First nix evaluation requested: %s, no ETA", new.commit_sha1)
    # Can we schedule this one or should we wait on the lock?
    # Lock nix-eval-jobs concurrency behind a lock.
    # Lock this evaluation to avoid any modification for now.
    NixEvaluation.objects.select_for_update().filter(pk=new.pk)
    asyncio.run(
        evaluation_entrypoint(
            average_evaluation_time
            or settings.DEFAULT_SLEEP_WAITING_FOR_EVALUATION_SLOT,
            new,
        )
    )


def rewire_new_derivations_following_attribute_paths(
    proposals: list[CVEDerivationClusterProposal], evaluation: NixEvaluation
) -> None:
    """
    This takes a list of proposals which have derivations from an older Nix channel attached to it.
    The passed evaluation is supposed to be the result of a newer Nix channel evaluation.

    The game is to update all the M2M links from that proposal to the newer derivations.
    How to do this? Attribute paths.

    Attribute paths are supposed to be constant and can relate from a channel to another.
    This is what Hydra does to track what happens to a package build time history, etc.

    This falls short whenever we will rename a package, move it to another attribute path, e.g. promoting a GNOME variant
    to the top-level space of packages.

    In those situations, this is not a big deal, this should not change intrinsically that we made the suggestion
    for that GNOME variant based on intrinsic parameters of said package and therefore, we will lose its trace in
    this new evaluation and will just "lose" it from this suggestion.

    Once we obtain the ability to upgrade existing suggestions, we may re-attach it.
    Nonetheless, we should return the list of lost derivations by rewiring with the new evaluation.
    """

    # Ideally, we would settle this in a single UPDATE statement which looks like this:
    # UPDATE SET derivation_id = nnd.id FROM derivation_cluster_proposal_link JOIN nixderivations AS ond ON ond.id = derivation_id JOIN nixderivations AS nnd ON nnd.attribute_path = ond.attribute_path WHERE proposal_id IN eligible_proposals AND nnd.parent_evaluation_id = new_evaluation_id;
    # But this is a complicated one and it does not handle the situation where the right JOIN has missing items, i.e. lost derivations.
    # Let's do slowly and we will see the impact in production.
    # In general, we do not expect that size of proposal (:= nr of derivations in proposal) to be large and number of proposals should stay low.
    # If we end up do one query for _all_ proposals, we are therefore looking at O(size of all proposals merged) in terms of query complexity.

    current_links = {
        link.derivation.attribute: link
        for link in DerivationClusterProposalLink.objects.select_related("derivation")
        .filter(proposal__in=proposals)
        .iterator()
    }
    attribute_paths = list(current_links.keys())
    new_derivations = {
        d.attribute: d
        for d in NixDerivation.objects.filter(
            attribute__in=attribute_paths, parent_evaluation=evaluation
        )
        .values_list("attribute", "id")
        .iterator()
    }
    updates = []
    # This loop is O(size of all proposals merged) which is ≤ O(sum of size of all proposals).
    # Depending on the situation, we may have many suggestions that shares the same derivations because they are suggestions
    # for different CVE that ends up affecting the same package set.
    # In that scenario, we are reduced to O(max(size of the largest proposal)).
    # In the other scenario, where we have suggestions that affects uniformly all of nixpkgs, we are reduced to O(sum of all sizes of all proposals).
    # The reality is probably between those two extremes.
    for apath in attribute_paths:
        current_link = current_links[apath]
        # This is a lost derivation.
        if apath not in new_derivations:
            logger.warning(
                "We lost the trace of '%s' following the channel update in '%s', marking that proposal's derivation as outdated."
            )
            current_link.outdated = True
            updates.append(current_link)
        # This is a known derivation!
        else:
            current_link.derivation = new_derivations[apath]
            updates.append(current_link)

    DerivationClusterProposalLink.objects.bulk_update(
        updates, fields=("outdated", "derivation"), batch_size=1_000
    )

    # TODO: how to handle the activity log here?
    # Bulk updates may not trigger anything and we would need special rendering here.
    # To inform that the services updated N derivations and could not deal with M derivations (outdated ones).


@pgpubsub.listener(NixEvaluationCompleteChannel)
def run_attribute_tracking_job(evaluation_id: int) -> None:
    # Our objective is to update:
    # - pending suggestions
    # - accepted suggestions
    # TODO: in the future, we should not update "mitigated" issues so we can easily revisit _which_ derivation was the last one.
    try:
        evaluation = NixEvaluation.objects.get(evaluation_id)
    except NixEvaluation.DoesNotExist:
        logger.warning(
            "Evaluation ID '%d' disappeared when we were updating the attributes it induced; this might be normal if we are recovering from a very old state",
            evaluation_id,
        )
        return

    # At this point, we have a known full evaluation.
    # We would like to select all pending or accepted proposals.
    eligible_proposals = list(
        CVEDerivationClusterProposal.objects.filter(
            status__in=(
                CVEDerivationClusterProposal.Status.PENDING,
                CVEDerivationClusterProposal.Status.ACCEPTED,
            )
        )
    )
    rewire_new_derivations_following_attribute_paths(eligible_proposals, evaluation)

    for proposal in eligible_proposals:
        # Once a proposal is rewired, we need to recache it.
        # TODO(Raito): performance-wise, we could do a more complicated recalculation if we had better guarantees on the schema of derivations inside of it.
        # We do not, so we will not until we prove there's a concern about performance.
        cache_new_suggestions(proposal)
