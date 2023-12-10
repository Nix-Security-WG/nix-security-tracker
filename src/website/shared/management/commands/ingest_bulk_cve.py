import json
import logging
import shutil
import tempfile
import zipfile
from datetime import date
from glob import glob
from os import environ as env, mkdir, path

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
            "-s",
            "--subset",
            nargs="?",
            type=int,
            help="Integer value reprepathsenting the N subset of total entries. "
            + " Useful to generate a small dataset for development.",
            default=0,
        )
        parser.add_argument(
            "--force-download",
            action="store_true",
            help="Ignore the local data cache content and download the CVEs zip again.",
        )

    def _download_gh_bundle(self, data_cache_dir):
        # Initialize a GitHub connection
        g = get_gh()

        # Select the CVEList repository
        repo = g.get_repo("CVEProject/cvelistV5")

        # Fetch the latest daily release
        release = repo.get_latest_release()

        logger.warn(f"Fetched latest release: {release.title}")

        # Get the bulk cve list asset
        bundle = release.assets[0]

        if not bundle.name.endswith(".zip"):
            logger.error(f"Wrong bundle asset: {bundle.name}")

            raise CommandError("Unable to get bundled CVEs.")

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

            # Extract the archive into $DATA_CACHE_DIR
            with zipfile.ZipFile(tmp_arc) as z_arc:
                logger.warn("Extract the first archive to cves.zip")

                z_arc.extractall(path=tmp_dir)

            with zipfile.ZipFile(f"{tmp_dir}/cves.zip") as z_arc:
                logger.warn("Extract the second archive to cves")

                z_arc.extractall(path=data_cache_dir)

        return release

    def _set_cve_data_cache_dir(self):
        data_cache_dir = env.get("DATA_CACHE_DIRECTORY")

        if data_cache_dir is None:
            data_cache_dir = path.join(
                path.dirname(path.realpath(__file__)), ".data_cache"
            )
            logger.warn("$DATA_CACHE_DIRECTORY was not set. Using the local dir.")

        # Work in the $DATA_CACHE_DIRECTORY
        if not path.exists(data_cache_dir):
            mkdir(path.join(data_cache_dir))

        return data_cache_dir, path.join(data_cache_dir, "cves")

    def handle(self, *args, **kwargs) -> None:  # pyright: ignore reportUnusedVariable
        data_cache_dir, cve_data_cache_dir = self._set_cve_data_cache_dir()

        # delete if force-download
        if kwargs["force_download"] and path.exists(cve_data_cache_dir):
            shutil.rmtree(cve_data_cache_dir)

        if not path.exists(cve_data_cache_dir):
            # Doing a self assignment trick to keep pyright happy ...
            self.release = self._download_gh_bundle(data_cache_dir)

        # Traverse the tree and import cves if they already exist
        cve_list = glob(f"{cve_data_cache_dir}/*/*/*.json")

        # Open a single transaction for the db
        with transaction.atomic():
            if kwargs["subset"] > 0:
                cve_list = cve_list[: kwargs["subset"]]
            logger.warn(f"{len(cve_list)} CVEs to ingest.")

            for j_cve in cve_list:
                with open(j_cve) as fc:
                    mkCve(json.load(fc), triaged=True)

        if not path.exists(cve_data_cache_dir):
            # Record the ingestion
            v_date = self.release.tag_name.split("_")[1]

            logger.warn(f"Saving the ingestion valid up to {v_date}")

            CveIngestion.objects.create(
                valid_to=date.fromisoformat(v_date), delta=False
            )
