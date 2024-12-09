import argparse
import datetime
import json
import logging
import tempfile
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from glob import glob
from typing import Any

import requests
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from github import UnknownObjectException
from github.Repository import Repository
from shared import models
from shared.fetchers import make_cve
from shared.models import CveIngestion
from shared.utils import get_gh

logger = logging.getLogger(__name__)


def get_past_january_first() -> datetime.date:
    today = datetime.date.today()
    past_year = today.year - 1
    # Take the day before.
    return datetime.date(past_year, 1, 1) - datetime.timedelta(days=1)


class NoReleaseError(Exception):
    def __init__(self, day: datetime.datetime) -> None:
        super().__init__(f"No release for day {day}")


def ingest_day(repo: Repository, day: datetime.datetime) -> CveIngestion:
    # Fetch the latest daily release
    try:
        release = repo.get_release(f"cve_{day}_at_end_of_day")
    except UnknownObjectException:
        raise NoReleaseError(day)

    logger.info(f"Fetched release: {release.title}")

    # Get the bulk cve list asset
    if not release.assets:
        raise NoReleaseError(day)

    bundle = release.assets[0]

    if bundle.name != f"{day}_delta_CVEs_at_end_of_day.zip":
        raise CommandError(f"Delta asset has unexpected name: {bundle.name}")

    # Create a temporary directory to work in
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_arc = f"{tmp_dir}/deltaCves.zip"

        # Download the zip file
        logger.info(f"Downloading the delta: {bundle.name}")
        r = requests.get(bundle.browser_download_url)

        if r.status_code != 200:
            raise CommandError(f"Unable to download the delta, error {r.status_code}")

        with open(tmp_arc, "wb") as fz:
            fz.write(r.content)

        # Extract the archive
        with zipfile.ZipFile(tmp_arc) as z_arc:
            logger.info("Extracting the first archive to cves.zip")

            z_arc.extractall(path=tmp_dir)

        # Open a single transaction for the db
        # Traverse the tree and import cves
        cve_list = glob(f"{tmp_dir}/deltaCves/*.json")
        logger.info(f"{len(cve_list)} CVEs to ingest.")

        for j_cve in cve_list:
            with open(j_cve) as fc:
                data = json.load(fc)
                cve_id = data["cveMetadata"]["cveId"]

                with transaction.atomic():
                    make_cve(
                        data,
                        record=models.CveRecord.objects.filter(cve_id=cve_id).first(),
                    )

        # Record the ingestion
        logger.info(f"Saving the ingestion valid up to {day}")

        return CveIngestion.objects.create(valid_to=day, delta=True)


def process_day(repo: Repository, day: datetime.datetime) -> None:
    """Wrapper function to process a single day."""
    try:
        ingest_day(repo, day)
    except NoReleaseError:
        logger.exception(
            f"CVE ingestion on day {day} is impossible as there's no release, continuing for the next days"
        )


def parallel_ingestion(
    repo: Repository,
    next_ingestion: datetime.datetime,
    date: datetime.datetime,
    num_processes: int,
) -> None:
    """
    Parallel ingestion of CVE data.

    :param repo: Repository to ingest data from.
    :param next_ingestion: The starting date for ingestion.
    :param date: The end date for ingestion.
    :param num_processes: Number of parallel processes.
    """
    days = [
        next_ingestion + datetime.timedelta(days=x)
        for x in range((date - next_ingestion).days + 1)
    ]

    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        # Submit tasks to the executor
        futures = {executor.submit(process_day, repo, day): day for day in days}

        for future in as_completed(futures):
            day = futures[future]
            try:
                future.result()
            except Exception as e:
                logger.exception(f"An error occurred while processing day {day}: {e}")


class Command(BaseCommand):
    help = "Ingest CVEs day per day using the MITRE CVE repo"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "date",
            type=datetime.date.fromisoformat,
            help="End date until which we will download all the missing deltas.",
        )
        # A good default is to collect all CVEs from (current year - 1) so that
        # we can operate over "modern" software CVEs and potentially still
        # active ones.
        parser.add_argument(
            "--default-start-ingestion",
            type=datetime.date.fromisoformat,
            help="Default start ingestion date if there is no CVE ingestion record in database",
            default=get_past_january_first(),
        )
        parser.add_argument(
            "--num-parallel-processes",
            type=int,
            help="Number of parallel processes for the ingestion",
            default=1,
        )

    def handle(self, *args: Any, **kwargs: Any) -> None:
        date = kwargs["date"]
        default_start_ingestion = kwargs["default_start_ingestion"]
        num_processes = kwargs["num_parallel_processes"]

        if num_processes > 1:
            logger.warning(
                "Do not run with more than one process if you do not know what you are doing, the ingestion layer is not ready yet."
            )

        if CveIngestion.objects.filter(valid_to__gte=date).exists():
            logger.warning(
                f"The database already contains the delta contents from {date}."
            )

            return

        last_ingestion = (
            CveIngestion.objects.order_by("-valid_to")
            .values_list("valid_to", flat=True)
            .first()
        )

        if last_ingestion is None:
            logger.warning(
                "The database contains no initial ingestion record, normally, it should be initialized via bulk ingestion. It will be initialized now via delta ingestion. This will incur more traffic to GitHub servers."
            )

        # Determine the next ingestion in our calendar.
        next_ingestion = (
            last_ingestion or default_start_ingestion
        ) + datetime.timedelta(days=1)

        # Initialize a GitHub connection
        g = get_gh()

        # Select the CVEList repository
        repo = g.get_repo("CVEProject/cvelistV5")

        parallel_ingestion(repo, next_ingestion, date, num_processes)
