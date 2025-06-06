import asyncio
import sys
from argparse import ArgumentParser
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand
from shared.git import GitRepo


async def clone_with_progress(repo: GitRepo, reference: str | None) -> None:
    process = await repo.clone(reference)
    await process.wait()


class Command(BaseCommand):
    help = "Initiate a Nixpkgs local checkout if it doesn't exist yet"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "-r",
            "--reference",
            type=str,
            help="Existing reference to a Nixpkgs repo, accelerate the initialization",
        )

    def handle(self, *args: Any, **kwargs: Any) -> str | None:
        print(
            f"Will clone {settings.GIT_CLONE_URL} into {settings.LOCAL_NIXPKGS_CHECKOUT}"
        )
        repo = GitRepo(
            settings.LOCAL_NIXPKGS_CHECKOUT,
            stdout=sys.stdout.fileno(),
            stderr=sys.stderr.fileno(),
        )
        reference = kwargs.get("reference", None)
        asyncio.run(clone_with_progress(repo, reference))
