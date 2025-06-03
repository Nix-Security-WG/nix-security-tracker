import asyncio
import sys
import tempfile
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand
from shared.git import GitRepo
from shared.models.nix_evaluation import NixChannel


async def test_worktree(repo: GitRepo, channel: NixChannel) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        async with repo.extract_working_tree(channel.head_sha1_commit, tmpdir) as wt:
            print("Tested the creation of a working tree", wt)
            print(await repo.worktrees())


class Command(BaseCommand):
    help = "Test mounting the worktree of a Nix channel"

    def handle(self, *args: str, **kwargs: Any) -> None:
        repo = GitRepo(
            settings.LOCAL_NIXPKGS_CHECKOUT,
            stdout=sys.stdout.fileno(),
            stderr=sys.stderr.fileno(),
        )
        channel = NixChannel.objects.first()
        if channel is not None:
            asyncio.run(test_worktree(repo, channel))
