import argparse
import datetime
import logging
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from shared import models
from shared.listeners.automatic_linkage import build_new_links

logger = logging.getLogger(__name__)


def check_delta_in_reasonable_range(value: str) -> int:
    ivalue = int(value)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError(f"{value} is an invalid positive int value")
    elif ivalue >= 365 * 100:
        raise argparse.ArgumentTypeError(f"{value} is more than a century, unlikely")
    return ivalue


class Command(BaseCommand):
    help = "Propose new CVE links on all CVE of a certain time range"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "delta_range_in_days",
            type=check_delta_in_reasonable_range,
            help="Since when should we redo all the links in days? e.g. `5` for 5 days ago.",
        )

    def handle(self, *args: Any, **kwargs: Any) -> None:
        _delta = kwargs["delta_range_in_days"]

        try:
            delta = datetime.timedelta(days=int(_delta))
            since_date = datetime.datetime.now() - delta
        except ValueError:
            raise CommandError(f"Not a valid delta format: {_delta}")

        logger.info("Proposing new CVE links starting '%s'", since_date.isoformat())
        with transaction.atomic():
            # Collect all containers since that delta range.
            containers = models.Container.objects.filter(date_public__gte=since_date)

            for container in containers.iterator():
                build_new_links(container)
