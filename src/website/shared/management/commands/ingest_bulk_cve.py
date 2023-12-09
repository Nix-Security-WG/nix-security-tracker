import json
import logging
import tempfile
import zipfile
from datetime import date
from glob import glob

import requests
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from shared.fetchers import mkCve
from shared.models import CveIngestion
from shared.utils import get_gh

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Ingest CVEs in bulk using the Mitre CVE repo"

    def add_arguments(self, parser):
        parser.add_argument(
            "--test",
            action="store_true",
            help="Import a small subset of CVEs for testing",
        )

    def handle(self, *args, **kwargs) -> None:  # pyright: ignore reportUnusedVariable
        # Initialize a GitHub connection
        g = get_gh()

        # Select the CVEList repository
        repo = g.get_repo("CVEProject/cvelistV5")

        # Fetch the latest daily release
        release = repo.get_latest_release()

        logger.warn(f"Fetched latest release: {release.title}")

        # Get the bulk cve list asset
        bundle = release.assets[0]

        if not bundle.name.endswith(".zip.zip"):
            logger.error(f"Wrong bundle asset: {bundle.name}")

            raise CommandError("Unable to get bundled CVEs.")

        # Create a temporary directory to work in
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_arc = f"{tmp_dir}/cves.zip.zip"

            # Download the zip file
            logger.warn(f"Downloading the bundle: {bundle.name}")
            r = requests.get(bundle.browser_download_url)

            if r.status_code != 200:
                raise CommandError(
                    f"Unable to download the bundle, error {r.status_code}"
                )

            with open(tmp_arc, "wb") as fz:
                fz.write(r.content)

            # Extract the archive
            with zipfile.ZipFile(tmp_arc) as z_arc:
                logger.warn("Extract the first archive to cves.zip")

                z_arc.extractall(path=tmp_dir)

            with zipfile.ZipFile(f"{tmp_dir}/cves.zip") as z_arc:
                logger.warn("Extract the second archive to cves")

                z_arc.extractall(path=tmp_dir)

            # Open a single transaction for the db
            with transaction.atomic():
                # Traverse the tree and import cves
                cve_list = glob(f"{tmp_dir}/cves/*/*/*.json")
                if kwargs["test"]:
                    cve_list = cve_list[0:100]
                logger.warn(f"{len(cve_list)} CVEs to ingest.")

                for j_cve in cve_list:
                    with open(j_cve) as fc:
                        mkCve(json.load(fc), triaged=True)

        # Record the ingestion
        v_date = release.tag_name.split("_")[1]

        logger.warn(f"Saving the ingestion valid up to {v_date}")

        CveIngestion.objects.create(valid_to=date.fromisoformat(v_date), delta=False)
