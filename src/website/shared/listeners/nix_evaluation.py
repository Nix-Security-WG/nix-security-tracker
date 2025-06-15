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

from shared.channels import NixEvaluationChannel
from shared.evaluation import (
    SyncBatchAttributeIngester,
    parse_evaluation_result,
)
from shared.git import GitRepo
from shared.models import NixDerivation, NixEvaluation

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
        # write drv files to memory.
        # it's a lot faster and there's no harm in losing them since we currently don't use them for anything
        "--eval-store",
        # TODO: create the setting and wire it up with the service module and deployment config.
        # please document what the operator has to do and why
        # should default to /nix/store since not every system will have the right stuff set up
        settings.EVALUATION_STORE_DIR,
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
