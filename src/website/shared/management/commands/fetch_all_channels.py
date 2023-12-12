import asyncio
import sys
from argparse import ArgumentParser
from collections.abc import Coroutine
from dataclasses import dataclass
from pprint import pprint
from typing import Any

import requests
from django.conf import settings
from django.core.management.base import BaseCommand
from shared.git import GitRepo
from shared.models.nix_evaluation import NixChannel


@dataclass
class MonitoredChannel:
    name: str
    revision: str
    status: str


def release_from_branch(branch: str) -> str | None:
    """
    >>> release_from_branch("nixpkgs-23.05-darwin")
    23.05
    >>> release_from_branch("nixpkgs-23.11-darwin")
    23.11
    >>> release_from_branch("nixpkgs-23.05")
    23.05
    >>> release_from_branch("nixpkgs-unstable")
    None
    >>> release_from_branch("nixpkgs-unstable-small")
    None
    """
    parts = branch.split("-")
    if len(parts) < 2:
        return None

    ver = parts[1]
    if "." not in ver:
        return None

    return ver


def state_from_status(status: str) -> NixChannel.ChannelState:
    if status == "unmaintained":
        return NixChannel.ChannelState.END_OF_LIFE
    elif status == "deprecated":
        return NixChannel.ChannelState.DEPRECATED
    elif status == "beta":
        return NixChannel.ChannelState.BETA
    elif status == "stable":
        return NixChannel.ChannelState.STABLE
    elif status == "rolling":
        return NixChannel.ChannelState.UNSTABLE
    else:
        return NixChannel.ChannelState.STAGING


def staging_from_branch(branch: str) -> str:
    release_ver = release_from_branch(branch)
    if release_ver is None:
        return "master"
    else:
        return f"release-{release_ver}"


def aggregate_by_channels(data: list[dict[str, Any]]) -> dict[str, MonitoredChannel]:
    channels = {}
    for metric in data:
        m = metric["metric"]
        channels[m["channel"]] = MonitoredChannel(
            name=m["channel"], revision=m["revision"], status=m["status"]
        )
    return channels


def fetch_from_monitoring() -> dict[str, MonitoredChannel]:
    resp = requests.get(
        "https://monitoring.nixos.org/prometheus/api/v1/query?query=channel_revision"
    )
    resp.raise_for_status()
    return aggregate_by_channels(resp.json()["data"]["result"])


async def wait_for_parallel_fetches(
    parallel_fetches: list[Coroutine[Any, Any, bool]]
) -> list[Any]:
    return await asyncio.gather(*parallel_fetches, return_exceptions=True)


class Command(BaseCommand):
    help = "Register Nix channels"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "-r",
            "--repository",
            type=str,
            help="Repository for those specific Nix channels",
            default="https://github.com/NixOS/nixpkgs",
        )

    def handle(self, *args: Any, **kwargs: Any) -> str | None:
        fresh_channels = fetch_from_monitoring()
        defaults = {"repository": kwargs["repository"]}
        for channel in fresh_channels.values():
            channel_branch = channel.name
            staging_branch = staging_from_branch(channel.name)
            branch_info = defaults | {
                "staging_branch": staging_branch,
                "state": state_from_status(channel.status),
                "head_sha1_commit": channel.revision,
                "release_version": release_from_branch(channel.name),
            }
            pprint(branch_info | {"channel_branch": channel.name})
            NixChannel.objects.update_or_create(
                branch_info, channel_branch=channel_branch
            )

        repo = GitRepo(
            settings.LOCAL_NIXPKGS_CHECKOUT,
            stdout=sys.stdout.fileno(),
            stderr=sys.stderr.fileno(),
        )
        parallel_fetches = []
        for channel in NixChannel.objects.iterator():
            parallel_fetches.append(repo.update_from_ref(channel.head_sha1_commit))

        results = asyncio.run(wait_for_parallel_fetches(parallel_fetches))
        print("Parallel fetches results", results)
