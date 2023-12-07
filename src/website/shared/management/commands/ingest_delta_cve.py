import datetime
import json
import logging
import tempfile
import zipfile
from glob import glob

import requests
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from github import UnknownObjectException

from shared import models
from shared.fetchers import mkCve
from shared.models import CveIngestion
from shared.utils import get_gh

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Ingest CVEs in bulk using the Mitre CVE repo"

    def add_arguments(self, parser):
        parser.add_argument("date", help="Date of the delta to download.")

    def handle(self, *args, **kwargs) -> None:
        _date = kwargs["date"]

        try:
            date = datetime.date.fromisoformat(_date)
        except ValueError:
            raise CommandError(f"Not a valid date format: {_date}")

        if CveIngestion.objects.filter(valid_to__gte=date).exists():
            logger.warn(
                f"The database already contains the delta contents from {date}."
            )

            return

        # Initialize a GitHub connection
        g = get_gh()

        # Select the CVEList repository
        repo = g.get_repo("CVEProject/cvelistV5")

        # Fetch the latest daily release
        try:
            release = repo.get_release(f"cve_{date}_at_end_of_day")
        except UnknownObjectException:
            raise CommandError(f"No end of day release for {date} found.")

        logger.warn(f"Fetched release: {release.title}")

        # Get the bulk cve list asset
        bundle = release.assets[0]

        if bundle.name != f"{date}_delta_CVEs_at_end_of_day.zip":
            logger.error(f"Wrong delta asset: {bundle.name}")

            raise CommandError("Unable to get delta CVEs.")

        # Create a temporary directory to work in
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_arc = f"{tmp_dir}/deltaCves.zip"

            # Download the zip file
            logger.warn(f"Downloading the delta: {bundle.name}")
            r = requests.get(bundle.browser_download_url)

            if r.status_code != 200:
                raise CommandError(
                    f"Unable to download the delta, error {r.status_code}"
                )

            with open(tmp_arc, "wb") as fz:
                fz.write(r.content)

            # Extract the archive
            with zipfile.ZipFile(tmp_arc) as z_arc:
                logger.warn("Extracting the first archive to cves.zip")

                z_arc.extractall(path=tmp_dir)

            # Open a single transaction for the db
            with transaction.atomic():
                # Traverse the tree and import cves
                cve_list = glob(f"{tmp_dir}/deltaCves/*.json")
                logger.warn(f"{len(cve_list)} CVEs to ingest.")

                for j_cve in cve_list:
                    with open(j_cve) as fc:
                        data = json.load(fc)
                        cve_id = data["cveMetadata"]["cveId"]

                        mkCve(
                            data,
                            record=models.CveRecord.objects.filter(
                                cve_id=cve_id
                            ).first(),
                        )

        # Record the ingestion
        logger.warn(f"Saving the ingestion valid up to {date}")

        CveIngestion.objects.create(valid_to=date, delta=True)
