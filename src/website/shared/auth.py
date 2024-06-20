import logging
from typing import Any, cast

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import Group, Permission, User
from django.db.models import Q
from github import Github
from github.NamedUser import NamedUser
from github.Organization import Organization
from github.Team import Team

from shared.utils import get_gh

github: Github = get_gh(per_page=100)  # 100 is the API limit
logger = logging.getLogger(__name__)


def get_gh_username(user: User) -> str | None:
    """
    Return the Github username of a given Auth.User.
    """
    social_user = User.objects.get(id=user.id)  # type: ignore
    social_account: SocialAccount | None = (
        social_user.socialaccount_set.filter(provider="github").first()  # type: ignore
    )
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
        except Exception as e:
            logger.warning(f"Failed to get team {teamname}: {e}")

    return None


def get_github_ids_cache() -> dict[str, set[int]]:
    """
    Return a dictionary cache with the Github IDs for each team.
    """

    def get_team_member_ids(orgname: str, teamname: str) -> set[int]:
        team = get_gh_team(orgname, teamname)
        if team:
            members = team.get_members()
            logger.info(
                f"Caching {members.totalCount} IDs from team {orgname}/{teamname}..."
            )

            # The iterator will make the extra page API calls for us.
            return {member.id for member in members}
        return set()

    ids: dict[str, set[int]] = dict()

    ids["security_team"] = get_team_member_ids("NixOS", "security")
    ids["committers"] = get_team_member_ids("NixOS", "nixpkgs-committers")
    ids["maintainers"] = get_team_member_ids("NixOS", "nixpkgs-maintainers")

    logger.info("Done caching IDs from Github.")

    return ids


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

    gh_team: Team | None = get_gh_team(orgname, teamname)
    if gh_team:
        return gh_team.has_in_members(gh_named_user)
    return False


def reset_group_permissions(**kwargs: Any) -> None:
    """
    Reset general permissions in case new tables were created.
    """
    logger.info("Resetting general group permissions...")

    # Secury team members have admin permissions
    security = Group.objects.get(name="security_team")
    security.permissions.set(Permission.objects.all())
    security.save()

    # Committers have write permissions on packages
    committers = Group.objects.get(name="committers")
    # TODO: finetune filter
    committers.permissions.set(
        Permission.objects.filter(
            (Q(codename__icontains="view_") | Q(codename__icontains="change_"))
            & Q(codename__icontains="nix")
        )
    )
    committers.save()

    # Readers have read permissions on packages
    readers = Group.objects.get(name="readers")
    # TODO: finetune filter
    readers.permissions.set(
        Permission.objects.filter(
            Q(codename__icontains="view_") & Q(codename__icontains="nix")
        )
    )
    readers.save()
