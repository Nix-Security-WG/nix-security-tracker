import logging
from functools import lru_cache
from typing import Any, cast

from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from django.contrib.auth.models import Group
from github import Github
from github.NamedUser import NamedUser
from github.Organization import Organization
from github.Team import Team

from shared.models import NixMaintainer
from shared.utils import get_gh

github: Github = get_gh(per_page=100)  # 100 is the API limit
logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_gh_organization(orgname: str) -> Organization | None:
    """
    Return the Github Organization instance given an organization name.
    """
    try:
        return github.get_organization(login=orgname)
    except Exception:
        logger.exception("Failed to get organization %s", orgname)
        return None


# We only care about caching two teams (security-team and committers)
# from github at the moment.
# It benefits the on-first login logic, but there's no point for the
# one-time per user login `is_team_member` function to be cached.
@lru_cache(maxsize=2)
def get_gh_team(org_or_orgname: Organization | str, teamname: str) -> Team | None:
    """
    Return the Github Team instance given an Organization instance and a team name.
    """
    gh_org: Organization | None = None
    if isinstance(org_or_orgname, str):
        gh_org = get_gh_organization(org_or_orgname)

    if gh_org:
        try:
            return gh_org.get_team_by_slug(teamname)
        except Exception:
            logger.exception("Failed to get team %s", teamname)

    return None


def get_team_member_ids(orgname: str, teamname: str) -> set[int]:
    team = get_gh_team(orgname, teamname)
    if team:
        members = team.get_members()
        logger.info(
            "Getting %s IDs from team %s/%s...",
            members.totalCount,
            orgname,
            teamname,
        )

        # The iterator will make the extra page API calls for us.
        return {member.id for member in members}
    return set()


def is_team_member(username: str, orgname: str, teamname: str) -> bool:
    """
    Return whether a given username is a member of a Github team
    """
    gh_named_user: NamedUser = cast(NamedUser, github.get_user(login=username))

    gh_team: Team | None = get_gh_team(orgname, teamname)
    if gh_team:
        return gh_team.has_in_members(gh_named_user)
    return False


def init_user_groups(instance: SocialAccount, created: bool, **kwargs: Any) -> None:
    """
    Setup group memberships for a newly created user.
    """
    # Ignore updates and deletions
    if not created:
        return

    logger.info("New Github account: %s. Setting up groups...", instance)

    social_account = instance
    gh_username = social_account.extra_data.get("login")  # type: ignore
    user = social_account.user

    if is_team_member(gh_username, settings.GH_ORGANIZATION, settings.GH_SECURITY_TEAM):
        user.groups.add(Group.objects.get(name=settings.GROUP_SECURITY_TEAM))
    if is_team_member(
        gh_username, settings.GH_ORGANIZATION, settings.GH_COMMITTERS_TEAM
    ):
        user.groups.add(Group.objects.get(name=settings.GROUP_COMMITTERS))


# Request utilities
@lru_cache(maxsize=1)
def isadmin(user: Any) -> bool:
    return (
        user.is_staff or user.groups.filter(name=settings.GROUP_SECURITY_TEAM).exists()
    )


@lru_cache(maxsize=1)
def ismaintainer(user: Any) -> bool:
    return NixMaintainer.objects.filter(github=user.username).exists()
