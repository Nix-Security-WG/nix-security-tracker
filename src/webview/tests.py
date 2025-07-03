from typing import Any
from unittest.mock import patch

from allauth.account.utils import get_login_redirect_url
from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.providers.oauth2.views import OAuth2LoginView
from allauth.socialaccount.templatetags.socialaccount import provider_login_url
from django.contrib.auth import get_user_model, login
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.test import Client, TestCase
from django.urls import reverse

from shared.listeners.cache_suggestions import cache_new_suggestions
from shared.models.cve import (
    AffectedProduct,
    CveRecord,
    Description,
    Metric,
    Organization,
    Version,
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
    MaintainersEdit,
    ProvenanceFlags,
)
from shared.models.nix_evaluation import (
    NixChannel,
    NixDerivation,
    NixDerivationMeta,
    NixEvaluation,
    NixMaintainer,
)


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

        # Create a GitHub social account for the user
        SocialAccount.objects.get_or_create(
            user=self.user,
            provider="github",
            uid="123456",
            extra_data={"login": "admin"},
        )

        self.client = Client()
        self.client.login(username="admin", password="pw")

        # Create relevant mock data including a maintainer, CVE, and suggestion

        self.assigner = Organization.objects.create(uuid=1, short_name="foo")
        self.cve_record = CveRecord.objects.create(
            cve_id="CVE-2025-0001",
            assigner=self.assigner,
        )
        # Create a container with affected product, description, and metric to satisfy cache_new_suggestions preconditions
        self.description = Description.objects.create(value="Test description")
        self.metric = Metric.objects.create(format="cvssV3_1", raw_cvss_json={})
        self.affected_product = AffectedProduct.objects.create(
            package_name="dummy-package"
        )
        self.affected_product.versions.add(
            Version.objects.create(status=Version.Status.AFFECTED, version="1.0")
        )
        self.cve_container = self.cve_record.container.create(
            provider=self.assigner,
            title="Dummy Title",
        )
        self.cve_container.affected.add(self.affected_product)
        self.cve_container.descriptions.add(self.description)
        self.cve_container.metrics.add(self.metric)

        # Create the maintainer and link to a derivation
        self.maintainer = NixMaintainer.objects.create(
            github_id=123,
            github="existinguser",
            name="Existing User",
            email="existing@example.com",
        )
        self.meta = NixDerivationMeta.objects.create(
            description="Dummy derivation",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        self.meta.maintainers.add(self.maintainer)

        # Create a NixEvaluation and NixDerivation, link meta and suggestion
        self.evaluation = NixEvaluation.objects.create(
            channel=NixChannel.objects.create(
                staging_branch="release-24.05",
                channel_branch="nixos-24.05",
                head_sha1_commit="deadbeef",
                state=NixChannel.ChannelState.STABLE,
                release_version="24.05",
                repository="https://github.com/NixOS/nixpkgs",
            ),
            commit_sha1="deadbeef",
            state=NixEvaluation.EvaluationState.COMPLETED,
        )
        self.derivation = NixDerivation.objects.create(
            attribute="dummyAttr",
            derivation_path="/nix/store/dummy.drv",
            name="dummy-package-1.0",
            metadata=self.meta,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )
        self.suggestion = CVEDerivationClusterProposal.objects.create(
            status=CVEDerivationClusterProposal.Status.ACCEPTED,
            cve_id=self.cve_record.pk,
        )
        DerivationClusterProposalLink.objects.create(
            proposal=self.suggestion,
            derivation=self.derivation,
            provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
        )

        # Cache the suggestion
        cache_new_suggestions(self.suggestion)
        self.suggestion.refresh_from_db()

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
        self.suggestion.refresh_from_db()
        maintainers = self.suggestion.cached.payload["maintainers"]
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
        self.suggestion.refresh_from_db()
        maintainers = self.suggestion.cached.payload["maintainers"]
        github_handles = [m["github"] for m in maintainers]
        self.assertIn("dbuser", github_handles)

    def test_new_maintainter_edit_in_db(self) -> None:
        url = reverse("webview:add_maintainer")
        # Create a maintainer in the DB who is not yet in the suggestion
        NixMaintainer.objects.create(
            github_id=456, github="dbuser", name="DB User", email="db@example.com"
        )
        self.client.post(
            url,
            {
                "suggestion_id": self.suggestion.pk,
                "new_maintainer_github_handle": "dbuser",
            },
        )
        self.assertTrue(
            MaintainersEdit.objects.filter(
                suggestion=self.suggestion,
                maintainer__github="dbuser",
                edit_type=MaintainersEdit.EditType.ADD,
            ).exists()
        )

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

    def test_add_maintainer_widget_visible_when_admin(self) -> None:
        url = reverse("webview:drafts_view")
        response = self.client.get(url)
        response_content = response.content.decode("utf-8")
        self.assertIn("maintainer-add-container", response_content)

    def test_add_maintainer_widget_not_visible_when_logged_out(self) -> None:
        self.client.logout()
        url = reverse("webview:drafts_view")
        response = self.client.get(url)
        response_content = response.content.decode("utf-8")
        self.assertNotIn("maintainer-add-container", response_content)
