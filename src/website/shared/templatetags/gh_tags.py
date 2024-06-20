import logging
from typing import cast

from allauth.socialaccount.models import SocialAccount
from django import template
from django.contrib.auth.models import User
from github import Github
from github.NamedUser import NamedUser
from github.Organization import Organization
from github.Team import Team
from shared.models import SocialUser
from shared.utils import get_gh

register = template.Library()
github: Github = get_gh(per_page=100)
logger = logging.getLogger(__name__)


def get_gh_username(user: User) -> str | None:
    """
    Return the Github username of a given Auth.User.
    """
    social_user = SocialUser.objects.get(id=user.id)  # type: ignore
    social_account: SocialAccount | None = social_user.github_account
    if social_account:
        return social_account.extra_data.get("login")  # type: ignore

    logger.warning(f"Failed to get GitHub username for user {user}.")
    return None


def get_gh_organization(orgname: str) -> Organization | None:
    """
    Return the Github Organization instance given an organization name.
    """
    try:
        return github.get_organization(login=orgname)
    except Exception as e:
        logger.warning(f"Failed to get organization {orgname}: {e}")
        return None


def get_gh_team(gh_org: Organization, teamname: str) -> Team | None:
    """
    Return the Github Team instance given an Organization instance and a team name.
    """
    try:
        return gh_org.get_team_by_slug(teamname)
    except Exception as e:
        logger.warning(f"Failed to get team {teamname}: {e}")
        return None


def is_org_member(username: str, orgname: str) -> bool:
    """
    Return whether a given username is a member of a Github organization
    """
    gh_named_user: NamedUser = cast(NamedUser, github.get_user(login=username))

    gh_org: Organization | None = get_gh_organization(orgname)
    if gh_org:
        return gh_org.has_in_members(gh_named_user)
    return False


def is_team_member(username: str, orgname: str, teamname: str) -> bool:
    """
    Return whether a given username is a member of a Github team
    """
    gh_named_user: NamedUser = cast(NamedUser, github.get_user(login=username))

    gh_org: Organization | None = get_gh_organization(orgname)
    if gh_org:
        gh_team: Team | None = get_gh_team(gh_org, teamname)
        if gh_team:
            return gh_team.has_in_members(gh_named_user)
    return False


@register.simple_tag
def is_nixos_member(user: User) -> bool:
    username: str | None = get_gh_username(user)
    if username:
        return is_org_member(username, "NixOS")
    return False


@register.simple_tag
def is_committer(user: User) -> bool:
    username: str | None = get_gh_username(user)
    if username:
        return is_team_member(username, "NixOS", "nixpkgs-committers")
    return False


@register.simple_tag
def is_security_member(user: User) -> bool:
    username: str | None = get_gh_username(user)
    if username:
        return is_team_member(username, "NixOS", "security-team")
    return False
