from argparse import ArgumentParser
from datetime import datetime
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from shared.models import (
    AffectedProduct,
    Container,
    CveRecord,
    Description,
    Organization,
    Version,
)


class Command(BaseCommand):
    help = "Create a test CVE for a specific package"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "package_name",
            type=str,
            help="Package name to create a CVE for",
        )
        parser.add_argument(
            "--cve-id",
            type=str,
            help="Custom CVE ID (default: auto-generated)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        package_name = options["package_name"]
        cve_id = options.get("cve_id")

        # Generate CVE ID if not provided
        if not cve_id:
            current_year = datetime.now().year
            existing_cves = CveRecord.objects.filter(
                cve_id__startswith=f"CVE-{current_year}-"
            ).count()
            cve_id = f"CVE-{current_year}-{(existing_cves + 1):04d}"

        # Check if CVE already exists
        if CveRecord.objects.filter(cve_id=cve_id).exists():
            raise CommandError(f"CVE {cve_id} already exists")

        with transaction.atomic():
            # Create organization
            org, _ = Organization.objects.get_or_create(
                short_name="TEST_ORG",
                defaults={"uuid": "12345678-1234-5678-9abc-123456789012"},
            )

            # Create CVE record
            cve_record = CveRecord.objects.create(
                cve_id=cve_id,
                state=CveRecord.RecordState.PUBLISHED,
                assigner=org,
                date_published=datetime.now(),
                date_updated=datetime.now(),
                triaged=False,
            )

            # Create description
            description = Description.objects.create(
                lang="en",
                value=f"Test vulnerability in {package_name} package.",
            )

            # Create container
            container = Container.objects.create(
                _type=Container.Type.CNA,
                cve=cve_record,
                provider=org,
                title=f"Vulnerability in {package_name}",
                date_public=datetime.now(),
            )
            container.descriptions.add(description)

            # Create affected product
            affected_product = AffectedProduct.objects.create(
                vendor="nixpkgs",
                product=package_name,
                package_name=package_name,
                default_status=AffectedProduct.Status.AFFECTED,
            )

            # Add version constraint
            version_affected = Version.objects.create(
                status=Version.Status.AFFECTED,
                version_type="semver",
                less_than="*",
            )
            affected_product.versions.add(version_affected)

            # Link to container
            container.affected.add(affected_product)

        self.stdout.write(
            self.style.SUCCESS(f"Created CVE {cve_id} for {package_name}")
        )
