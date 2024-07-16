"""
Test suite for GitHub sync utilities
"""
from typing import Any, TypedDict

from allauth.socialaccount.models import SocialAccount, SocialLogin
from django.conf import settings
from django.contrib.auth.models import Group, User
from django.test import TestCase

from shared.auth import isadmin, iscommitter, ismaintainer
from shared.auth.github_state import GithubState


# Mock classes
class GithubNamedUserMock:
    def __init__(self, id_value: str) -> None:
        self.id: str = id_value


class GithubTeamApiMock:
    def __init__(self, ids: list[str]) -> None:
        self.ids = ids

    def get_members(self) -> list[GithubNamedUserMock]:
        return [GithubNamedUserMock(id_value=id) for id in self.ids]


class GithubStateMock(GithubState):
    def __init__(
        self, security_ids: list[str] = [], committer_ids: list[str] = []
    ) -> None:
        self.security_group = Group.objects.get(name=settings.GROUP_SECURITY_TEAM)
        self.committers_group = Group.objects.get(name=settings.GROUP_COMMITTERS)
        self.github = (  # type: ignore
            None  # Force failures if anyone tries to make calls with self.github
        )
        self.security_team = GithubTeamApiMock(ids=security_ids)  # type: ignore
        self.committers_team = GithubTeamApiMock(ids=committer_ids)  # type: ignore


# Object creation utilities
def create_sociallogin_for_user(user: User, user_uid: str) -> SocialLogin:
    user_socialaccount = SocialAccount.objects.create(
        user=user,
        provider="github",
        uid=user_uid,
    )

    return SocialLogin(
        user=user,
        account=user_socialaccount,
    )


class MockLoginDict(TypedDict):
    uid: str
    user: User
    socialLogin: SocialLogin


def create_user_with_sociallogin(
    name: str, uid_base: int, amount: int
) -> list[MockLoginDict]:
    users = []

    for i in range(amount):
        uid: str = str(uid_base + i)
        user = User.objects.create_user(username=f"{name}-{i+1}")
        sociallogin = create_sociallogin_for_user(user=user, user_uid=uid)
        users.append({"user": user, "uid": uid, "sociallogin": sociallogin})

    return users


# Test suite
class GithubSyncTests(TestCase):
    @classmethod
    def setUpTestData(cls: Any) -> None:
        # Create users
        cls.password = "pass"
        cls.superuser = User.objects.create_superuser(
            username="superuser", password="pass", email="superuser@localhost"
        )
        # Security members get admin permissions.
        cls.security_users = create_user_with_sociallogin(
            name="security-member", uid_base=10, amount=2
        )
        # Committers get write permissions to models that relate to derivations they maintain
        cls.committer_users = create_user_with_sociallogin(
            name="committer", uid_base=20, amount=2
        )
        # Anybody else gets read permissions
        cls.reader_users = create_user_with_sociallogin(
            name="reader", uid_base=30, amount=1
        )
        cls.user_without_social = User.objects.create_user(
            username="user-without-social"
        )

    def test_users_without_sociallogin(self) -> None:
        gh_state = GithubStateMock()
        gh_state.sync_groups_with_github_teams()

        # Superusers bypass all auth logic, and get admin permissions
        self.assertTrue(isadmin(self.superuser))
        self.assertFalse(iscommitter(self.user_without_social))
        self.assertFalse(ismaintainer(self.user_without_social))

        # A user without a socialaccount doesn't get the option
        # to be admin (through security membership) or committer.
        self.assertFalse(isadmin(self.user_without_social))
        self.assertFalse(iscommitter(self.user_without_social))
        self.assertFalse(ismaintainer(self.user_without_social))

    def test_sync_groups_with_teams(self) -> None:
        # Setup mock GitHub state
        gh_state = GithubStateMock(
            security_ids=[self.security_users[0]["uid"]],
            committer_ids=[self.committer_users[0]["uid"]],
        )

        # Before running the sync, no user should have explicit permissions
        for security_user in self.security_users:
            self.assertFalse(isadmin(security_user["user"]))
            self.assertFalse(iscommitter(security_user["user"]))
            self.assertFalse(ismaintainer(security_user["user"]))

        for committer in self.committer_users:
            self.assertFalse(isadmin(committer["user"]))
            self.assertFalse(iscommitter(committer["user"]))
            self.assertFalse(ismaintainer(committer["user"]))

        for reader in self.reader_users:
            self.assertFalse(isadmin(reader["user"]))
            self.assertFalse(iscommitter(reader["user"]))
            self.assertFalse(ismaintainer(reader["user"]))

        # Run sync
        gh_state.sync_groups_with_github_teams()

        # After running the sync:
        #  the first user of each type should have the appropiate permissions
        self.assertTrue(isadmin(self.security_users[0]["user"]))
        self.assertFalse(iscommitter(self.security_users[0]["user"]))
        self.assertFalse(ismaintainer(self.security_users[0]["user"]))

        self.assertFalse(isadmin(self.committer_users[0]["user"]))
        self.assertTrue(iscommitter(self.committer_users[0]["user"]))
        self.assertFalse(ismaintainer(self.committer_users[0]["user"]))

        #  but the second user of each type should have no explicit permissions
        self.assertFalse(isadmin(self.security_users[1]["user"]))
        self.assertFalse(iscommitter(self.security_users[1]["user"]))
        self.assertFalse(ismaintainer(self.security_users[1]["user"]))

        self.assertFalse(isadmin(self.committer_users[1]["user"]))
        self.assertFalse(iscommitter(self.committer_users[1]["user"]))
        self.assertFalse(ismaintainer(self.committer_users[1]["user"]))

        # the reader is still a reader
        for reader in self.reader_users:
            self.assertFalse(isadmin(reader["user"]))
            self.assertFalse(iscommitter(reader["user"]))
            self.assertFalse(ismaintainer(reader["user"]))

    def test_sync_groups_with_teams_invert_permissions(self) -> None:
        # Setup mock GitHub state
        gh_state = GithubStateMock(
            security_ids=[self.security_users[0]["uid"]],
            committer_ids=[self.committer_users[0]["uid"]],
        )

        # Run sync
        gh_state.sync_groups_with_github_teams()

        # Now give permissions to the second users of each type
        gh_state = GithubStateMock(
            security_ids=[self.security_users[1]["uid"]],
            committer_ids=[self.committer_users[1]["uid"]],
        )

        # Run sync again
        gh_state.sync_groups_with_github_teams()

        # After running the second sync:
        #  the first user of each type should have no explicit permissions
        self.assertFalse(isadmin(self.security_users[0]["user"]))
        self.assertFalse(iscommitter(self.security_users[0]["user"]))
        self.assertFalse(ismaintainer(self.security_users[0]["user"]))

        self.assertFalse(isadmin(self.committer_users[0]["user"]))
        self.assertFalse(iscommitter(self.committer_users[0]["user"]))
        self.assertFalse(ismaintainer(self.committer_users[0]["user"]))

        #  but the second user of each type should have the appropiate permissions
        self.assertTrue(isadmin(self.security_users[1]["user"]))
        self.assertFalse(iscommitter(self.security_users[1]["user"]))
        self.assertFalse(ismaintainer(self.security_users[1]["user"]))

        self.assertFalse(isadmin(self.committer_users[1]["user"]))
        self.assertTrue(iscommitter(self.committer_users[1]["user"]))
        self.assertFalse(ismaintainer(self.committer_users[1]["user"]))

        # the reader is still a reader
        for reader in self.reader_users:
            self.assertFalse(isadmin(reader["user"]))
            self.assertFalse(iscommitter(reader["user"]))
            self.assertFalse(ismaintainer(reader["user"]))

    def test_sync_groups_with_teams_is_idempotent(self) -> None:
        # Setup mock GitHub state
        gh_state = GithubStateMock(
            security_ids=[self.security_users[0]["uid"]],
            committer_ids=[self.committer_users[0]["uid"]],
        )
        # Sync once
        gh_state.sync_groups_with_github_teams()

        # Call sync again to check for imdempotency (no errors should be raised)
        gh_state.sync_groups_with_github_teams()
