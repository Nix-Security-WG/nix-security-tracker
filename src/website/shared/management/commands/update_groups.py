import argparse
import logging
from typing import Any

from django.conf import settings
from django.contrib.auth.models import Group, User
from django.core.management.base import BaseCommand
from django.db import transaction
from shared.auth import get_github_ids_cache

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Update group memberships according to Github memberships."

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        pass

    def handle(self, *args: str, **kwargs: Any) -> None:  # pyright: ignore reportUnusedVariable
        logger.info(
            "Resetting group permissions based on their Github team memberships."
        )

        id_cache: dict[str, set[int]] = get_github_ids_cache()

        # Get the group objects for the transaction
        group_objects: dict[str, Group] = {}
        for groupname in id_cache.keys():
            group_objects[groupname] = Group.objects.get(name=groupname)

        logger.info("Using Github ID cache to update database groups...")

        users = User.objects.prefetch_related("socialaccount_set").iterator()
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
                # Superusers and the anonymous user are the only possible users
                # with no social account. Log an error if we find any other user that didn't
                # setup up their account via Github login.
                # NOTE: the anonymous user is created by django-guardian.
                if (
                    not user.is_superuser
                    and user.username != settings.ANONYMOUS_USER_NAME
                ):
                    logger.error(
                        "User %s with ID %s has no social account auth.",
                        user,
                        user.id,  # type: ignore
                    )
