import argparse
import logging
from typing import Any

from django.core.management.base import BaseCommand

# TODO: move to shared.auth or shared.auth_utils
from shared.models import reset_group_permissions

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Reset group permissions manually."

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        pass

    def handle(self, *args: str, **kwargs: Any) -> None:  # pyright: ignore reportUnusedVariable
        logger.info("Resetting group permissions")

        reset_group_permissions()
