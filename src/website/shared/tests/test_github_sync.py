"""
Test suite for GitHub sync utilities
"""


from typing import Any

from django.test import TestCase

from shared.auth.github_state import GithubState


class GithubSyncTests(TestCase):
    @classmethod
    def setUpTestData(cls: Any) -> None:
        gh_state = GithubState()  # noqa # delete comment once we have tests for real

        pass

    def test_network_call(self) -> None:
        pass
