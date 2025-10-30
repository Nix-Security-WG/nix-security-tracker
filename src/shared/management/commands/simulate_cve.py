import argparse
import logging
import random
import uuid
from datetime import datetime
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from shared.fetchers import make_cve
from shared.models import NixDerivation

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Simulate the arrival of a CVE affecting a specific package for testing purposes"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "package_name",
            type=str,
            help="Name of the package that should be affected by the simulated CVE",
        )
        parser.add_argument(
            "--severity",
            type=str,
            choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            default="MEDIUM",
            help="CVSS severity level (default: MEDIUM)",
        )
        parser.add_argument(
            "--cve-id",
            type=str,
            help="Specific CVE ID to use (default: auto-generate)",
        )
        parser.add_argument(
            "--description",
            type=str,
            help="CVE description (default: auto-generate)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        package_name = options["package_name"]
        severity = options["severity"]
        cve_id = options.get("cve_id")
        description = options.get("description")

        # Validate that package exists in derivations
        matching_derivations = NixDerivation.objects.filter(
            name__icontains=package_name
        )
        if not matching_derivations.exists():
            # Try by attribute name as well
            matching_derivations = NixDerivation.objects.filter(
                attribute__icontains=package_name
            )

        if not matching_derivations.exists():
            self.stdout.write(
                self.style.WARNING(
                    f"No derivations found containing '{package_name}'. "
                    "The CVE will still be created but may not link to any packages."
                )
            )
        else:
            derivation_count = matching_derivations.count()
            self.stdout.write(
                f"Found {derivation_count} derivation(s) that may match '{package_name}'"
            )

        # Generate CVE ID if not provided
        if not cve_id:
            current_year = datetime.now().year
            # Generate a random 4-7 digit number for the CVE ID
            cve_number = random.randint(10000, 9999999)
            cve_id = f"CVE-{current_year}-{cve_number:04d}"

        # Generate description if not provided
        if not description:
            description = (
                f"Simulated vulnerability in {package_name}. "
                f"This is a test CVE created for development/testing purposes. "
                f"Severity: {severity}."
            )

        # Create the CVE data structure that matches the expected format
        current_time = timezone.now().isoformat()

        # Generate UUIDs for organizations
        assigner_uuid = str(uuid.uuid4())
        provider_uuid = str(uuid.uuid4())

        cve_data = {
            "cveMetadata": {
                "cveId": cve_id,
                "state": "PUBLISHED",
                "assignerOrgId": assigner_uuid,
                "assignerShortName": "TEST-ORG",
                "datePublished": current_time,
                "dateUpdated": current_time,
                "serial": 1,
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "orgId": provider_uuid,
                        "shortName": "TEST-CNA",
                    },
                    "title": f"Vulnerability in {package_name}",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": description,
                        }
                    ],
                    "affected": [
                        {
                            "packageName": package_name,
                            "vendor": "nixpkgs",
                            "product": package_name,
                            "versions": [
                                {
                                    "status": "affected",
                                    "version": "*",
                                }
                            ],
                        }
                    ],
                    "metrics": [
                        {
                            "format": "cvssV3_1",
                            "scenarios": [
                                {
                                    "lang": "en",
                                    "value": "GENERAL",
                                }
                            ],
                            "cvssV3_1": {
                                "version": "3.1",
                                "vectorString": self._get_cvss_vector(severity),
                                "baseScore": self._get_base_score(severity),
                                "baseSeverity": severity,
                            },
                        }
                    ],
                    "problemTypes": [
                        {
                            "descriptions": [
                                {
                                    "lang": "en",
                                    "description": "Simulated vulnerability for testing",
                                    "type": "text",
                                }
                            ]
                        }
                    ],
                    "references": [
                        {
                            "url": "https://github.com/NixOS/nixpkgs",
                            "name": "NixOS/nixpkgs",
                        }
                    ],
                    "datePublic": current_time,
                }
            },
        }

        try:
            # Create the CVE using the existing infrastructure
            cve_record = make_cve(cve_data, triaged=False)

            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully created simulated CVE: {cve_record.cve_id}"
                )
            )
            self.stdout.write(f"  Package: {package_name}")
            self.stdout.write(f"  Severity: {severity}")
            self.stdout.write(f"  Description: {description}")
            self.stdout.write(
                "\nThe automatic linkage system should now process this CVE and:"
            )
            self.stdout.write("  1. Link it to relevant derivations")
            self.stdout.write("  2. Create suggestions for maintainers")
            self.stdout.write("  3. Notify subscribed users")

        except Exception as e:
            logger.exception(f"Failed to create simulated CVE: {e}")
            raise CommandError(f"Failed to create CVE: {e}")

    def _get_cvss_vector(self, severity: str) -> str:
        """Generate a CVSS vector string based on severity."""
        vectors = {
            "LOW": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",
            "MEDIUM": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
            "HIGH": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
            "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        }
        return vectors[severity]

    def _get_base_score(self, severity: str) -> float:
        """Get a CVSS base score based on severity."""
        scores = {
            "LOW": 3.8,
            "MEDIUM": 5.4,
            "HIGH": 7.6,
            "CRITICAL": 9.8,
        }
        return scores[severity]
