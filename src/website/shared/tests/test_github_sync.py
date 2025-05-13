"""
Test suite for GitHub sync utilities
"""

from typing import Any

from allauth.socialaccount.models import SocialAccount, SocialLogin
from django.apps import apps
from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase
from shared.auth import isadmin, iscommitter
from shared.auth.github_state import GithubState, set_groups_for_new_user
from shared.auth.github_webhook import handle_webhook


# Mock classes
class MockGithubUser:
    def __init__(self, id_value: str) -> None:
        self.id: str = id_value


class MockGithubTeam:
    def __init__(self, id: int, user_ids: list[str]) -> None:
        self.user_ids = user_ids
        self.id = id

    def get_members(self) -> list[MockGithubUser]:
        return [MockGithubUser(id_value=id) for id in self.user_ids]

    def has_in_members(self, named_user: MockGithubUser) -> bool:
        return named_user.id in self.user_ids


class MockGithubOrganization:
    def __init__(
        self, security_ids: list[str] = [], committer_ids: list[str] = []
    ) -> None:
        self.teams = {}
        self.teams[settings.GH_SECURITY_TEAM] = MockGithubTeam(
            id=1, user_ids=security_ids
        )
        self.teams[settings.GH_COMMITTERS_TEAM] = MockGithubTeam(
            id=2, user_ids=committer_ids
        )

    def get_team_by_slug(self, slug: str) -> MockGithubTeam:
        return self.teams[slug]


class MockGithub:
    def __init__(
        self, security_ids: list[str] = [], committer_ids: list[str] = []
    ) -> None:
        self.security_ids = security_ids
        self.committer_ids = committer_ids

    def get_user_by_id(self, user_id: int) -> MockGithubUser:
        return MockGithubUser(id_value=str(user_id))

    def get_organization(
        self, *args: Any, **kwargs: dict[str, Any]
    ) -> MockGithubOrganization:
        return MockGithubOrganization(
            security_ids=self.security_ids, committer_ids=self.committer_ids
        )


def create_users_with_sociallogin(
    name: str, uid_offset: int, amount: int
) -> list[SocialLogin]:
    result = []

    for i in range(amount):
        uid: str = str(uid_offset + i)  # GitHub has numeric user IDs
        user = User.objects.create_user(username=f"{name}-{i+1}")
        account = SocialAccount.objects.create(
            user=user,
            provider="github",
            uid=uid,
        )
        result.append(SocialLogin(user=user, account=account))

    return result


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
        cls.security_users = create_users_with_sociallogin(
            name="security-member", uid_offset=10, amount=2
        )
        # Committers get write permissions to models that relate to derivations they maintain
        cls.committer_users = create_users_with_sociallogin(
            name="committer", uid_offset=20, amount=2
        )
        # Anybody else gets read permissions
        cls.reader_users = create_users_with_sociallogin(
            name="reader", uid_offset=30, amount=1
        )
        cls.user_without_social = User.objects.create_user(
            username="user-without-social"
        )

    def test_users_without_sociallogin(self) -> None:
        gh_state = GithubState(github=MockGithub())  # type: ignore
        gh_state.sync_groups_with_github_teams()

        # Superusers bypass all auth logic, and get admin permissions
        self.assertTrue(isadmin(self.superuser))
        self.assertFalse(iscommitter(self.user_without_social))

        # A user without a socialaccount doesn't get the option
        # to be admin (through security membership) or committer.
        self.assertFalse(isadmin(self.user_without_social))
        self.assertFalse(iscommitter(self.user_without_social))

    def test_sync_groups_with_teams(self) -> None:
        # Setup mock GitHub state
        gh_state = GithubState(
            github=MockGithub(  # type: ignore
                security_ids=[self.security_users[0].account.uid],
                committer_ids=[self.committer_users[0].account.uid],
            )
        )

        # Before running the sync, no user should have explicit permissions
        for security_user in self.security_users:
            self.assertFalse(isadmin(security_user.user))
            self.assertFalse(iscommitter(security_user.user))

        for committer in self.committer_users:
            self.assertFalse(isadmin(committer.user))
            self.assertFalse(iscommitter(committer.user))

        for reader in self.reader_users:
            self.assertFalse(isadmin(reader.user))
            self.assertFalse(iscommitter(reader.user))

        # Run sync
        gh_state.sync_groups_with_github_teams()

        # After running the sync:
        #  the first user of each type should have the appropiate permissions
        self.assertTrue(isadmin(self.security_users[0].user))
        self.assertFalse(iscommitter(self.security_users[0].user))

        self.assertFalse(isadmin(self.committer_users[0].user))
        self.assertTrue(iscommitter(self.committer_users[0].user))

        #  but the second user of each type should have no explicit permissions
        self.assertFalse(isadmin(self.security_users[1].user))
        self.assertFalse(iscommitter(self.security_users[1].user))

        self.assertFalse(isadmin(self.committer_users[1].user))
        self.assertFalse(iscommitter(self.committer_users[1].user))

        # the reader is still a reader
        for reader in self.reader_users:
            self.assertFalse(isadmin(reader.user))
            self.assertFalse(iscommitter(reader.user))

    def test_sync_groups_with_teams_invert_permissions(self) -> None:
        # Setup mock GitHub state
        gh_state = GithubState(
            github=MockGithub(  # type: ignore
                security_ids=[self.security_users[0].account.uid],
                committer_ids=[self.committer_users[0].account.uid],
            )
        )

        # Run sync
        gh_state.sync_groups_with_github_teams()

        # Now give permissions to the second users of each type
        gh_state = GithubState(
            github=MockGithub(  # type: ignore
                security_ids=[self.security_users[1].account.uid],
                committer_ids=[self.committer_users[1].account.uid],
            )
        )

        # Run sync again
        gh_state.sync_groups_with_github_teams()

        # After running the second sync:
        #  the first user of each type should have no explicit permissions
        self.assertFalse(isadmin(self.security_users[0].user))
        self.assertFalse(iscommitter(self.security_users[0].user))

        self.assertFalse(isadmin(self.committer_users[0].user))
        self.assertFalse(iscommitter(self.committer_users[0].user))

        #  but the second user of each type should have the appropiate permissions
        self.assertTrue(isadmin(self.security_users[1].user))
        self.assertFalse(iscommitter(self.security_users[1].user))

        self.assertFalse(isadmin(self.committer_users[1].user))
        self.assertTrue(iscommitter(self.committer_users[1].user))

        # the reader is still a reader
        for reader in self.reader_users:
            self.assertFalse(isadmin(reader.user))
            self.assertFalse(iscommitter(reader.user))

    def test_sync_groups_with_teams_is_idempotent(self) -> None:
        # Setup mock GitHub state
        gh_state = GithubState(
            github=MockGithub(  # type: ignore
                security_ids=[self.security_users[0].account.uid],
                committer_ids=[self.committer_users[0].account.uid],
            )
        )

        # Sync once
        gh_state.sync_groups_with_github_teams()

        # Call sync again to check for idempotency (no errors should be raised)
        gh_state.sync_groups_with_github_teams()

    def test_sync_groups_for_new_users(self) -> None:
        # Setup mock GitHub state
        apps.get_app_config("shared").github_state = GithubState(  # type: ignore
            github=MockGithub(  # type: ignore
                security_ids=[self.security_users[0].account.uid],
                committer_ids=[self.committer_users[0].account.uid],
            )
        )

        # "New" users don't have explicit permissions set
        self.assertFalse(isadmin(self.security_users[0].user))
        self.assertFalse(iscommitter(self.security_users[0].user))

        self.assertFalse(isadmin(self.committer_users[0].user))
        self.assertFalse(iscommitter(self.committer_users[0].user))

        # Call the sign up signal receiver directly
        set_groups_for_new_user(self.security_users[0])
        set_groups_for_new_user(self.committer_users[0])

        # After signal receiver setup, they have the permissions that correspond to their Github teams
        self.assertTrue(isadmin(self.security_users[0].user))
        self.assertFalse(iscommitter(self.security_users[0].user))

        self.assertFalse(isadmin(self.committer_users[0].user))
        self.assertTrue(iscommitter(self.committer_users[0].user))

    def test_sync_groups_from_webhook_payload(self) -> None:
        # Setup mock GitHub state
        gh_state = GithubState(github=MockGithub())  # type: ignore
        apps.get_app_config("shared").github_state = gh_state  # type: ignore

        # Mocked webhook payloads
        event = "membership"
        action_added = {"action": "added"}
        action_removed = {"action": "removed"}
        common_payload_security = {
            "team": {"id": gh_state.security_team.id},
            "member": {"id": self.security_users[0].account.uid},
        }
        common_payload_committer = {
            "team": {"id": gh_state.committers_team.id},
            "member": {"id": self.committer_users[0].account.uid},
        }
        payload_security_added = {**action_added, **common_payload_security}
        payload_committer_added = {**action_added, **common_payload_committer}
        payload_security_removed = {**action_removed, **common_payload_security}
        payload_committer_removed = {**action_removed, **common_payload_committer}

        # Pre webhook request state
        self.assertFalse(isadmin(self.security_users[0].user))
        self.assertFalse(iscommitter(self.security_users[0].user))

        self.assertFalse(isadmin(self.committer_users[0].user))
        self.assertFalse(iscommitter(self.committer_users[0].user))

        # Process mocked "added" payloads
        handle_webhook(event=event, payload=payload_security_added)
        handle_webhook(event=event, payload=payload_committer_added)

        # After handling "added" webhooks
        self.assertTrue(isadmin(self.security_users[0].user))
        self.assertFalse(iscommitter(self.security_users[0].user))

        self.assertFalse(isadmin(self.committer_users[0].user))
        self.assertTrue(iscommitter(self.committer_users[0].user))

        # Process mocked "removed" payloads
        handle_webhook(event=event, payload=payload_security_removed)
        handle_webhook(event=event, payload=payload_committer_removed)

        # Check permissions are reset after "removed" payloads are processed
        self.assertFalse(isadmin(self.security_users[0].user))
        self.assertFalse(iscommitter(self.security_users[0].user))

        self.assertFalse(isadmin(self.committer_users[0].user))
        self.assertFalse(iscommitter(self.committer_users[0].user))
