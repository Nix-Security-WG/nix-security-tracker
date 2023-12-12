import asyncio
import logging
import pathlib
import random
import tempfile
import time

import aiofiles
import pgpubsub
from django.conf import settings
from django.db.models import Avg

from shared.channels import NixEvaluationChannel
from shared.evaluation import AsyncAttributeIngester, parse_evaluation_result
from shared.git import NixpkgsRepo
from shared.models import NixDerivation, NixEvaluation

logger = logging.getLogger(__name__)

SIGSEGV = 137
SIGABRT = 134


async def perform_evaluation(
    working_tree: pathlib.Path, evaluation_log_fd: int
) -> asyncio.subprocess.Process:
    """
    This will run `nix-eval-jobs` on the working tree as a nixpkgs
    input and collect all Hydra jobs, including insecure ones.

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
        stdout=asyncio.subprocess.PIPE,
        stderr=evaluation_log_fd,
    )


async def realtime_process_attribute(
    parent_evaluation: NixEvaluation, attribute: str
) -> NixDerivation | None:
    """
    Performs a real-time processing of that evaluated attribute
    without any bulk staging operations.
    """
    partially_evaluated_result = parse_evaluation_result(attribute)
    logger.debug(
        "Real-time processing attribute '%s'...", partially_evaluated_result.attr
    )
    # It's a broken attribute, let's move on.
    if partially_evaluated_result.evaluation is None:
        # We don't warn or error here
        # This is too noisy otherwise.
        logger.debug(
            "Attribute '%s' does not evaluate successfully",
            partially_evaluated_result.attr,
        )
        return None

    start = time.time()
    ingester = AsyncAttributeIngester(partially_evaluated_result.evaluation)
    await ingester.initialize()
    nix_derivation = await ingester.ingest(parent_evaluation)
    elapsed = time.time() - start
    logger.debug(
        "Attribute '%s' has been ingested under Nix derivation ID '%d' (drv path: '%s') in %f seconds",
        partially_evaluated_result.attr,
        nix_derivation.pk,
        nix_derivation.derivation_path,
        elapsed,
    )
    return nix_derivation


async def evaluation_entrypoint(avg_eval_time: float, evaluation: NixEvaluation):
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
    repo = NixpkgsRepo(settings.LOCAL_NIXPKGS_CHECKOUT)
    # Amount of chunks to process in the database in real-time.
    chunks = 10
    try:
        # Pull our local checkout up to that evaluation revision.
        await repo.update_from_ref(evaluation.commit_sha1)
        with tempfile.TemporaryDirectory() as working_tree_path:
            # Extract a working tree out of it for our needs.
            evaluation_log_filepath = (
                settings.EVALUATION_LOGS_DIRECTORY
                / f"evaluation-{evaluation.commit_sha1}.log"
            )
            async with repo.extract_working_tree(
                evaluation.commit_sha1, working_tree_path
            ) as working_tree, aiofiles.open(evaluation_log_filepath, "w") as eval_log:
                start = time.time()
                # Kickstart the evaluation asynchronously.
                eval_process = await perform_evaluation(
                    working_tree.path, eval_log.fileno()
                )
                assert (
                    eval_process.stdout is not None
                ), "Expected a valid `stdout` pipe for the asynchronous evaluation process"
                attribute = await eval_process.stdout.readline()
                processors = []
                while attribute != b"":
                    processors.append(
                        realtime_process_attribute(evaluation, attribute.decode("utf8"))
                    )
                    # logger.debug('Processing derivation in real-time: %s', attribute)
                    attribute = await eval_process.stdout.readline()
                    if len(processors) >= chunks:
                        await asyncio.gather(*processors[:chunks])
                        processors = processors[chunks:]
                # Wait for `nix-eval-jobs` to exit, at this point,
                # It should be fairly quick because EOF has been reached.
                rc = await eval_process.wait()
                if rc in (SIGSEGV, SIGABRT):
                    raise RuntimeError("`nix-eval-jobs` crashed!")
                elif rc != 0:
                    logger.error(
                        "`nix-eval-jobs` failed to evaluate (non-zero exit status), check the evaluation logs"
                    )
                    await NixEvaluation.objects.filter(id=evaluation.pk).aupdate(
                        state=NixEvaluation.EvaluationState.FAILED
                    )
                else:
                    # Wait for all the processing to finish.
                    await asyncio.gather(*processors)
                    elapsed = time.time() - start
                    logger.info(
                        "Processed %d derivations in real-time in %f seconds",
                        len(processors),
                        elapsed,
                    )
                    await NixEvaluation.objects.aupdate(
                        pk=evaluation.pk,
                        state=NixEvaluation.EvaluationState.COMPLETED,
                        elapsed=elapsed,
                    )
    except Exception:
        logger.exception(
            "Failed to run the `nix-eval-job` on revision '%s', marking job as crashed...",
            evaluation.commit_sha1,
        )
        await NixEvaluation.objects.filter(id=evaluation.pk).aupdate(
            state=NixEvaluation.EvaluationState.CRASHED
        )


@pgpubsub.post_insert_listener(NixEvaluationChannel)
def run_evaluation_job(old: NixEvaluation, new: NixEvaluation):
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
    print("selected for update", average_evaluation_time, new, new.pk)
    asyncio.run(
        evaluation_entrypoint(
            average_evaluation_time
            or settings.DEFAULT_SLEEP_WAITING_FOR_EVALUATION_SLOT,
            new,
        )
    )
