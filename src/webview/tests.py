from typing import Any
from unittest.mock import patch

from allauth.account.utils import get_login_redirect_url
from allauth.socialaccount.providers.oauth2.views import OAuth2LoginView
from allauth.socialaccount.templatetags.socialaccount import provider_login_url
from django.contrib.auth import get_user_model, login
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.test import Client, TestCase
from django.urls import reverse

from shared.models.cached import CachedSuggestions
from shared.models.cve import CveRecord, Organization
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.nix_evaluation import NixMaintainer


class Login(TestCase):
    def setUp(self) -> None:
        # location to start navigation
        self.entry_point = reverse("webview:suggestions_view")

    def test_redirect_after_login(self) -> None:
        response = self.client.get(self.entry_point)
        # expect the correct login URL in the response,
        # which will redirect back to the same page on success
        context = response.context[0]
        login_url = provider_login_url(
            context,
            provider="github",
            next=context.request.get_full_path(),
        )
        self.assertIn(login_url, response.content.decode("utf-8"))
        # follow the login workflow as displayed
        response = self.client.get(login_url)
        # expect confirmation to log in and a CSRF barrier via POST request
        self.assertIn("form", response.content.decode("utf-8"))

        def mock_login(
            self: OAuth2LoginView, request: HttpRequest, *args: Any, **kwargs: Any
        ) -> HttpResponse:
            user, _ = get_user_model().objects.get_or_create(username="testuser")
            login(
                request,
                user,
                backend="allauth.account.auth_backends.AuthenticationBackend",
            )
            return redirect(get_login_redirect_url(request))

        with patch.object(OAuth2LoginView, "dispatch", mock_login):
            # log in and follow redirect
            response = self.client.post(login_url, {}, follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["user"].is_authenticated)
        location, status = response.redirect_chain[-1]
        self.assertEqual(location, self.entry_point)


class AddMaintainerViewTests(TestCase):
    def setUp(self) -> None:
        # Create user and log in
        self.user = User.objects.create_user(username="admin", password="pw")
        self.user.is_staff = True
        self.user.save()
        self.client = Client()
        self.client.login(username="admin", password="pw")

        # Create a maintainer
        self.maintainer = NixMaintainer.objects.create(
            github_id=123,
            github="existinguser",
            name="Existing User",
            email="existing@example.com",
        )

        # Create a suggestion and cached suggestion with the maintainer
        self.assigner = Organization.objects.create(uuid=1, short_name="foo")
        self.cve_record = CveRecord.objects.create(
            cve_id="CVE-2025-0001",
            assigner=self.assigner,
        )
        self.suggestion = CVEDerivationClusterProposal.objects.create(
            status=CVEDerivationClusterProposal.Status.PENDING,
            cve_id=self.cve_record.id,
        )
        self.cached = CachedSuggestions.objects.create(
            proposal=self.suggestion,
            payload={
                "maintainers": [
                    {
                        "github_id": 123,
                        "github": "existinguser",
                        "name": "Existing User",
                        "email": "existing@example.com",
                    }
                ],
                "packages": {},
                "title": "Test Suggestion",
            },
        )

    def test_add_existing_maintainer_returns_error(self) -> None:
        url = reverse("webview:add_maintainer")
        response = self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "new_maintainer_github_handle": "existinguser",
            },
        )
        self.assertEqual(response.context["error_msg"], "Already a maintainer")

    def test_add_new_unknown_maintainer_success(self) -> None:
        url = reverse("webview:add_maintainer")
        # Simulate GitHub API returning a new user
        with patch("webview.views.fetch_user_info") as mock_fetch:
            mock_fetch.return_value = {
                "id": 456,
                "login": "newuser",
                "name": "New User",
                "email": "new@example.com",
            }
            response = self.client.post(
                url,
                {
                    "suggestion_id": self.suggestion.pk,
                    "new_maintainer_github_handle": "newuser",
                },
            )
        self.assertEqual(response.status_code, 200)
        # Reload cached suggestion and check maintainers
        self.cached.refresh_from_db()
        maintainers = self.cached.payload["maintainers"]
        github_handles = [m["github"] for m in maintainers]
        self.assertIn("newuser", github_handles)

    def test_add_new_existing_db_maintainer_success(self) -> None:
        url = reverse("webview:add_maintainer")
        # Create a maintainer in the DB who is not yet in the suggestion
        NixMaintainer.objects.create(
            github_id=456, github="dbuser", name="DB User", email="db@example.com"
        )
        response = self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "new_maintainer_github_handle": "dbuser",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.cached.refresh_from_db()
        maintainers = self.cached.payload["maintainers"]
        github_handles = [m["github"] for m in maintainers]
        self.assertIn("dbuser", github_handles)

    def test_add_maintainer_invalid_github_handle(self) -> None:
        url = reverse("webview:add_maintainer")
        # Simulate GitHub API not returning a user
        with patch("webview.views.fetch_user_info") as mock_fetch:
            mock_fetch.return_value = None
            response = self.client.post(
                url,
                {
                    "suggestion_id": self.suggestion.pk,
                    "new_maintainer_github_handle": "newuser",
                },
            )
        self.assertEqual(
            response.context["error_msg"], "Could not fetch maintainer from GitHub"
        )
