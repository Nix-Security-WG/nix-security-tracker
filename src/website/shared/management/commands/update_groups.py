import argparse
import logging
from typing import Any

from django.contrib.auth.models import Group, User
from django.core.management.base import BaseCommand
from django.db import transaction
from shared.templatetags.gh_tags import get_gh_organization, get_gh_team

# TODO: move to shared.auth or shared.auth_utils

logger = logging.getLogger(__name__)


def get_team_member_ids(orgname: str, teamname: str) -> set[int]:
    org = get_gh_organization(orgname)
    if org:
        team = get_gh_team(org, teamname)
        if team:
            members = team.get_members()
            logger.info(
                f"Caching {members.totalCount} IDs from team {orgname}/{teamname}..."
            )

            # The iterator will make the extra page API calls for us.
            return {member.id for member in members}
    return set()


def get_github_ids_cache() -> dict[str, set[int]]:
    ids: dict[str, set[int]] = dict()

    ids["security_team"] = get_team_member_ids("NixOS", "security")
    ids["committers"] = get_team_member_ids("NixOS", "nixpkgs-committers")
    ids["maintainers"] = get_team_member_ids("NixOS", "nixpkgs-maintainers")

    logger.info("Done caching IDs from Github.")

    return ids


class Command(BaseCommand):
    help = "Update group memberships according to Github memberships."

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        pass

    def handle(self, *args: str, **kwargs: Any) -> None:  # pyright: ignore reportUnusedVariable
        logger.info("Resetting group permissions")

        id_cache: dict[str, set[int]] = get_github_ids_cache()

        # Get the group objects for the transaction
        group_objects: dict[str, Group] = {}
        for groupname in id_cache.keys():
            group_objects[groupname] = Group.objects.get(name=groupname)

        logger.info("Using Github ID cache to update database groups...")

        users = User.objects.all()
        for user in users:
            social = user.socialaccount_set.filter(provider="github").first()  # type: ignore
            if social:
                # Open a single transaction for the db
                with transaction.atomic():
                    for groupname, ids in id_cache.items():
                        if social.extra_data["id"] in ids:
                            user.groups.add(group_objects[groupname])
                        else:
                            user.groups.remove(group_objects[groupname])

                logger.info("Done updating database groups.")
            else:
                if not user.is_staff:
                    logger.error(
                        f"User {user} with ID {user.id} has no social account auth."  # type: ignore
                    )
