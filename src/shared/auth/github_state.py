"""
Utilities to sync the user groups in our database with GitHub teams in order to correctly map permissions.

We implement a class, an instance of which must be attached to the server on startup in order to conveniently:
- register a hook to update user information on user signup
- cache remote data that only needs to be fetched once
- access data that needs to be fetched repeatedly
It will persist for the entire application lifetime.
"""

import logging
from typing import Any

from allauth.account.signals import user_signed_up
from allauth.socialaccount.models import SocialLogin
from django.apps import apps
from django.conf import settings
from django.contrib.auth.models import Group, User
from django.dispatch import receiver
from github import Github
from github.NamedUser import NamedUser
from github.Organization import Organization
from github.Team import Team
from shared.github import get_gh

logger = logging.getLogger(__name__)

logger.info("Syncing initial GitHub state.")


class GithubState:
    def __init__(
        self,
        github: Github = get_gh(per_page=100),  # 100 is the API limit
    ) -> None:
        self.github = github
        self.organization: Organization = self.github.get_organization(
            org=settings.GH_ORGANIZATION
        )
        self.security_team: Team = self.organization.get_team_by_slug(
            slug=settings.GH_SECURITY_TEAM
        )
        self.committers_team: Team = self.organization.get_team_by_slug(
            slug=settings.GH_COMMITTERS_TEAM
        )
        self.security_group = Group.objects.get(name=settings.DB_SECURITY_TEAM)
        self.committers_group = Group.objects.get(name=settings.DB_COMMITTERS_TEAM)

    # All GithubState methods are sync functions
    def sync_groups_with_github_teams(self) -> None:
        """
        Update group memberships for all users in the database based on their Github team memebership.
        """
        logger.info("Retrieving Github IDs to update database groups...")
        gh_security_team_ids = {
            member.id for member in self.security_team.get_members()
        }
        gh_committers_team_ids = {
            member.id for member in self.committers_team.get_members()
        }

        users = User.objects.prefetch_related("socialaccount_set").iterator()
        for user in users:
            social = user.socialaccount_set.filter(provider="github").first()  # type: ignore
            if not social:
                # Superusers are the only possible users with no social account.
                # Log an error if we find any other user that didn't
                # setup up their account via Github login.
                if not user.is_superuser:
                    logger.error(
                        "User with ID %s has no social account auth.",
                        user.id,  # type: ignore
                    )
                continue

            github_user_id = social.uid

            if github_user_id in gh_security_team_ids:
                user.groups.add(self.security_group)
            else:
                user.groups.remove(self.security_group)

            if github_user_id in gh_committers_team_ids:
                user.groups.add(self.committers_group)
            else:
                user.groups.remove(self.committers_group)

        logger.info("Done updating database groups.")

    def sync_team_membership_from_webhook(
        self, action: str, github_team_id: int, github_user_id: int
    ) -> None:
        """
        Update group membership from the payload received via GitHub webhook.
        """

        user: User = User.objects.get(socialaccount__uid=github_user_id)

        if self.security_team.id == github_team_id:
            if action == "added":
                user.groups.add(self.security_group)
            elif action == "removed":
                user.groups.remove(self.security_group)

        if self.committers_team.id == github_team_id:
            if action == "added":
                user.groups.add(self.committers_group)
            elif action == "removed":
                user.groups.remove(self.committers_group)


# On social sign up receiver
@receiver(user_signed_up)
def set_groups_for_new_user(sociallogin: SocialLogin, **kwargs: dict[str, Any]) -> None:
    """
    Setup group memberships for a newly created user.
    """
    if sociallogin.account:
        gh_state = apps.get_app_config("shared").github_state  # type: ignore

        github_id: int = int(sociallogin.account.uid)
        gh_named_user: NamedUser = gh_state.github.get_user_by_id(user_id=github_id)

        if gh_state.security_team.has_in_members(gh_named_user):
            sociallogin.account.user.groups.add(gh_state.security_group)

        if gh_state.committers_team.has_in_members(gh_named_user):
            sociallogin.account.user.groups.add(gh_state.committers_group)

    else:
        logger.error("Found a user sign up that didn't set an account.")
