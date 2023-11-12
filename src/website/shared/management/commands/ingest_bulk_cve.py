import json
import logging
import tempfile
import zipfile
from glob import glob
from os import environ as env
from typing import Optional

import requests
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from github import Auth, Github
from shared.fetchers import mkCve

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Ingest CVEs in bulk using the Mitre CVE repo"

    def handle(self, *args, **kwargs):
        credentials_dir = env.get("CREDENTIALS_DIRECTORY")

        gh_auth: Optional[Auth.Auth] = None

        if credentials_dir is None:
            logger.warn(
                "No credentials directory available, using unauthenticated API."
            )
        else:
            try:
                with open(f"{credentials_dir}/github_token", encoding="utf-8") as f:
                    gh_auth = Auth.Token(f.read())
            except FileNotFoundError:
                logger.warn(
                    "No token available in the credentials directory, "
                    "using unauthenticated API."
                )

        # Initialize a GitHub connection
        g = Github(auth=gh_auth)

        # Select the CVEList repository
        repo = g.get_repo("CVEProject/cvelistV5")

        # Fetch the latest daily release
        release = repo.get_latest_release()

        logger.info(f"Fetched latest release: {release.title}")

        # Get the bulk cve list asset
        bundle = release.assets[0]

        if not bundle.name.endswith(".zip.zip"):
            logger.error(f"Wrong bundle asset: {bundle.name}")

            raise CommandError("Unable to get bundled CVEs.")

        # Create a temporary directory to work in
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_arc = f"{tmp_dir}/cves.zip.zip"

            # Download the zip file
            r = requests.get(bundle.browser_download_url)

            if r.status_code != 200:
                raise CommandError(
                    f"Unable to download the bundle, error {r.status_code}"
                )

            with open(tmp_arc, "wb") as fz:
                fz.write(r.content)

            # Extract the archive
            with zipfile.ZipFile(tmp_arc) as z_arc:
                z_arc.extractall(path=tmp_dir)

            with zipfile.ZipFile(f"{tmp_dir}/cves.zip") as z_arc:
                z_arc.extractall(path=tmp_dir)

            # Open a single transaction for the db
            with transaction.atomic():
                # Traverse the tree and import cves
                cve_list = glob(f"{tmp_dir}/cves/*/*/*.json")
                logger.warn(f"{len(cve_list)} CVEs to ingest.")

                for j_cve in cve_list:
                    with open(j_cve) as fc:
                        mkCve(json.load(fc))
