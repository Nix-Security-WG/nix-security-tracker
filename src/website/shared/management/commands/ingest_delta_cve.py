import argparse
import datetime
import json
import logging
import tempfile
import zipfile
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


def ingest_day(repo: Repository, day: datetime.datetime) -> CveIngestion:
    # Fetch the latest daily release
    try:
        release = repo.get_release(f"cve_{day}_at_end_of_day")
    except UnknownObjectException:
        raise CommandError(f"No end of day release for {day} found.")

    logger.info(f"Fetched release: {release.title}")

    # Get the bulk cve list asset
    bundle = release.assets[0]

    if bundle.name != f"{day}_delta_CVEs_at_end_of_day.zip":
        logger.error(f"Wrong delta asset: {bundle.name}")

        raise CommandError("Unable to get delta CVEs.")

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
        with transaction.atomic():
            # Traverse the tree and import cves
            cve_list = glob(f"{tmp_dir}/deltaCves/*.json")
            logger.info(f"{len(cve_list)} CVEs to ingest.")

            for j_cve in cve_list:
                with open(j_cve) as fc:
                    data = json.load(fc)
                    cve_id = data["cveMetadata"]["cveId"]

                    make_cve(
                        data,
                        record=models.CveRecord.objects.filter(cve_id=cve_id).first(),
                    )

    # Record the ingestion
    logger.info(f"Saving the ingestion valid up to {day}")

    return CveIngestion.objects.create(valid_to=day, delta=True)


class Command(BaseCommand):
    help = "Ingest CVEs in bulk using the Mitre CVE repo"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "date",
            type=datetime.date.fromisoformat,
            help="End date until which we will download all the missing deltas.",
        )

    def handle(self, *args: Any, **kwargs: Any) -> None:
        date = kwargs["date"]

        if CveIngestion.objects.filter(valid_to__gte=date).exists():
            logger.warning(
                f"The database already contains the delta contents from {date}."
            )

            return

        last_ingestion = (
            CveIngestion.objects.order_by("-valid_to")
            .values_list("valid_to", flat=True)
            .last()
        )

        if last_ingestion is None:
            logger.error(
                "The database contains no initial ingestion record, please perform a first bulk import for initialization."
            )

            return

        # Determine the next ingestion in our calendar.
        next_ingestion = last_ingestion + datetime.timedelta(days=1)

        # Initialize a GitHub connection
        g = get_gh()

        # Select the CVEList repository
        repo = g.get_repo("CVEProject/cvelistV5")

        # We need to retrieve all daily releases from last_ingestion up to date now.
        for day in (
            next_ingestion + datetime.timedelta(days=x)
            for x in range((date - next_ingestion).days + 1)
        ):
            ingest_day(repo, day)
