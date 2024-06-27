import logging
from functools import lru_cache
from typing import Any, cast

from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import Group, Permission, User
from django.db.models import Q, QuerySet
from github import Github
from github.NamedUser import NamedUser
from github.Organization import Organization
from github.Team import Team
from guardian.shortcuts import assign_perm, remove_perm

from shared.models import NixDerivationMeta, NixMaintainer, NixpkgsIssue
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

    if is_team_member(gh_username, "NixOS", "security"):
        user.groups.add(Group.objects.get(name="security_team"))
    if is_team_member(gh_username, "NixOS", "nixpkgs-committers"):
        user.groups.add(Group.objects.get(name="committers"))


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


def update_maintainer_permissions(
    action: str, user: User, metadata: NixDerivationMeta
) -> None:
    """
    Update maintainer permissions over a package according to the m2m changed signal action.

    A maitainer of a package is able to change:
        - Derivations (NixDerivation) whose metadata points at them as a maintainer and
          the metadata itself (NixDerivationMeta).
        - Issues (NixpkgsIssue) that point to previous derivations as involved packages.
    """
    # TODO(alejandrosame): Figure out the best way to do prefetching
    issues: QuerySet[NixpkgsIssue] = metadata.derivation.nixpkgsissue_set.all()  # type: ignore
    if action == "post_add":
        assign_perm("change_nixderivation", user, metadata.derivation)  # type: ignore
        assign_perm("change_nixderivationmeta", user, metadata)
        for issue in issues:
            assign_perm("change_nixpkgsissue", user, issue)
    elif action == "post_remove":
        remove_perm("change_nixderivation", user, metadata.derivation)  # type: ignore
        remove_perm("change_nixderivationmeta", user, metadata)
        for issue in issues:
            remove_perm("change_nixpkgsissue", user, issue)
    pass


def update_maintainer_permissions_m2m_receiver(
    instance: NixDerivationMeta | NixMaintainer,
    action: str,
    reverse: bool,
    pk_set: set[int],
    **kwargs: Any,
) -> None:
    """
    Update maintainer permissions when a package metadata is changed.

    This function returns early in the following cases:
        - When the action is not 'post_add' or 'post_remove'.
        - When the pk_set is empty. For example, trying to add a maintainer
          to a package that is already in its metadatadata, will not create a duplicate
          entry in the database, which is reflected in the signal with an empty `pk_set`.

    The direction of the signal trigger is:
        - `derivation.metadata.maintainers.add(maintainer)` when `reverse` is `False`.
        - `maintainer.nixderivationmeta_set.add(derivation.metadata)` when `reverse` is `True`.
    """
    if action not in ["post_add", "post_remove"]:
        return
    if pk_set == set():
        return

    if reverse:  # `instance` is NixMaintainer and `pk_set` contains metadata keys
        maintainer: NixMaintainer = cast(NixMaintainer, instance)
        user: User = User.objects.get(username=maintainer.github)
        metadatas: QuerySet[NixDerivationMeta] = NixDerivationMeta.objects.filter(
            id__in=pk_set
        ).all()
        for metadata in metadatas:
            update_maintainer_permissions(action, user, metadata)

    else:  # `instance` is NixDerivationMeta and `pk_set` contains maintainer keys
        maintainer_usernames: set[str] = set(
            NixMaintainer.objects.filter(github_id__in=pk_set)
            .all()
            .values_list("github", flat=True)
        )
        users: QuerySet[User] = User.objects.filter(username__in=maintainer_usernames)
        metadata: NixDerivationMeta = cast(NixDerivationMeta, instance)
        for user in users:
            update_maintainer_permissions(action, user, metadata)
