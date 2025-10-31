from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse

from shared.listeners.automatic_linkage import build_new_links
from shared.listeners.notify_users import create_package_subscription_notifications
from shared.models.cve import (
    AffectedProduct,
    CveRecord,
    Description,
    Metric,
    Organization,
    Version,
)
from shared.models.linkage import CVEDerivationClusterProposal
from shared.models.nix_evaluation import (
    NixChannel,
    NixDerivation,
    NixDerivationMeta,
    NixEvaluation,
    NixMaintainer,
)


class SubscriptionTests(TestCase):
    def setUp(self) -> None:
        # Create test user with social account
        self.user = User.objects.create_user(username="testuser", password="testpass")
        self.user.is_staff = True
        self.user.save()

        SocialAccount.objects.get_or_create(
            user=self.user,
            provider="github",
            uid="123456",
            extra_data={"login": "testuser"},
        )

        self.client = Client()
        self.client.login(username="testuser", password="testpass")

        # Create test NixDerivation data for package validation
        self.maintainer = NixMaintainer.objects.create(
            github_id=123,
            github="testmaintainer",
            name="Test Maintainer",
            email="test@example.com",
        )
        self.meta = NixDerivationMeta.objects.create(
            description="Test package",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        self.meta.maintainers.add(self.maintainer)

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

        # Create valid packages that can be subscribed to
        self.valid_package1 = NixDerivation.objects.create(
            attribute="firefox",
            derivation_path="/nix/store/firefox.drv",
            name="firefox-120.0",
            metadata=self.meta,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

        # Create separate metadata for chromium
        self.meta2 = NixDerivationMeta.objects.create(
            description="Test chromium package",
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
        )
        self.meta2.maintainers.add(self.maintainer)

        self.valid_package2 = NixDerivation.objects.create(
            attribute="chromium",
            derivation_path="/nix/store/chromium.drv",
            name="chromium-119.0",
            metadata=self.meta2,
            system="x86_64-linux",
            parent_evaluation=self.evaluation,
        )

    def test_user_subscribes_to_valid_package_success(self) -> None:
        """Test successful subscription to an existing package"""
        url = reverse("webview:subscriptions:add")
        response = self.client.post(url, {"package_name": "firefox"})

        # Should redirect for non-HTMX request
        self.assertEqual(response.status_code, 302)
        self.assertIn("subscriptions", response.url)

        # Follow redirect and check subscription center context
        response = self.client.get(response.url)
        self.assertEqual(response.status_code, 200)

        # Verify subscription appears in context
        self.assertIn("package_subscriptions", response.context)
        self.assertIn("firefox", response.context["package_subscriptions"])

    def test_user_subscribes_to_invalid_package_fails(self) -> None:
        """Test subscription fails for non-existent package"""
        url = reverse("webview:subscriptions:add")
        response = self.client.post(url, {"package_name": "nonexistent-package"})

        # Should redirect for non-HTMX request
        self.assertEqual(response.status_code, 302)

        # Follow redirect and check for error message and context
        response = self.client.get(response.url)
        self.assertEqual(response.status_code, 200)

        # Check that error message is in Django messages
        messages = list(response.context["messages"])
        self.assertTrue(any("does not exist" in str(message) for message in messages))

        # Verify no invalid subscription in context
        self.assertIn("package_subscriptions", response.context)
        self.assertEqual(response.context["package_subscriptions"], [])

    def test_user_subscribes_to_valid_package_success_htmx(self) -> None:
        """Test successful subscription to an existing package via HTMX"""
        url = reverse("webview:subscriptions:add")
        response = self.client.post(
            url, {"package_name": "firefox"}, HTTP_HX_REQUEST="true"
        )

        # Should return 200 with component template for HTMX request
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "subscriptions/components/packages.html")

        # Verify subscription appears in context
        self.assertIn("package_subscriptions", response.context)
        self.assertIn("firefox", response.context["package_subscriptions"])

        # Should not have error message
        self.assertNotIn("error_message", response.context)

    def test_user_subscribes_to_invalid_package_fails_htmx(self) -> None:
        """Test subscription fails for non-existent package via HTMX"""
        url = reverse("webview:subscriptions:add")
        response = self.client.post(
            url, {"package_name": "nonexistent-package"}, HTTP_HX_REQUEST="true"
        )

        # Should return 200 with component template for HTMX request
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "subscriptions/components/packages.html")

        # Check that error message is in context
        self.assertIn("error_message", response.context)
        self.assertIn("does not exist", response.context["error_message"])

        # Verify no invalid subscription in context
        self.assertIn("package_subscriptions", response.context)
        self.assertNotIn(
            "nonexistent-package", response.context["package_subscriptions"]
        )

    def test_user_subscribes_to_empty_package_name_fails_htmx(self) -> None:
        """Test subscription fails for empty package name via HTMX"""
        url = reverse("webview:subscriptions:add")
        response = self.client.post(url, {"package_name": ""}, HTTP_HX_REQUEST="true")

        # Should return 200 with component template for HTMX request
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "subscriptions/components/packages.html")

        # Check that error message is in context
        self.assertIn("error_message", response.context)
        self.assertIn("cannot be empty", response.context["error_message"])

        # Verify no subscriptions in context
        self.assertIn("package_subscriptions", response.context)
        self.assertEqual(response.context["package_subscriptions"], [])

    def test_user_cannot_subscribe_to_same_package_twice_htmx(self) -> None:
        """Test duplicate subscription prevention via HTMX"""
        url = reverse("webview:subscriptions:add")

        # First subscription should succeed
        response = self.client.post(
            url, {"package_name": "firefox"}, HTTP_HX_REQUEST="true"
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("firefox", response.context["package_subscriptions"])

        # Second subscription to same package should fail
        response = self.client.post(
            url, {"package_name": "firefox"}, HTTP_HX_REQUEST="true"
        )

        # Should return 200 with component template
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "subscriptions/components/packages.html")

        # Check that error message is in context
        self.assertIn("error_message", response.context)
        self.assertIn("already subscribed", response.context["error_message"])

        # Verify firefox still appears only once in context
        self.assertIn("package_subscriptions", response.context)
        self.assertIn("firefox", response.context["package_subscriptions"])

    def test_user_unsubscribes_from_package_success_htmx(self) -> None:
        """Test successful unsubscription via HTMX"""
        # First subscribe to a package via HTMX
        add_url = reverse("webview:subscriptions:add")
        self.client.post(add_url, {"package_name": "firefox"}, HTTP_HX_REQUEST="true")

        # Now unsubscribe via HTMX
        remove_url = reverse("webview:subscriptions:remove")
        response = self.client.post(
            remove_url, {"package_name": "firefox"}, HTTP_HX_REQUEST="true"
        )

        # Should return 200 with component template for HTMX request
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "subscriptions/components/packages.html")

        # Verify subscription was removed from context
        self.assertIn("package_subscriptions", response.context)
        self.assertNotIn("firefox", response.context["package_subscriptions"])
        self.assertEqual(response.context["package_subscriptions"], [])

        # Should not have error message
        self.assertNotIn("error_message", response.context)

    def test_user_cannot_unsubscribe_from_non_subscribed_package_htmx(self) -> None:
        """Test unsubscription fails for packages not subscribed to via HTMX"""
        url = reverse("webview:subscriptions:remove")
        response = self.client.post(
            url, {"package_name": "firefox"}, HTTP_HX_REQUEST="true"
        )

        # Should return 200 with component template for HTMX request
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "subscriptions/components/packages.html")

        # Check that error message is in context
        self.assertIn("error_message", response.context)
        self.assertIn("not subscribed", response.context["error_message"])

        # Verify empty subscriptions in context
        self.assertIn("package_subscriptions", response.context)
        self.assertEqual(response.context["package_subscriptions"], [])

    def test_subscription_center_shows_user_subscriptions(self) -> None:
        """Test that the center displays user's current subscriptions"""
        # First add some subscriptions via HTMX
        add_url = reverse("webview:subscriptions:add")
        self.client.post(add_url, {"package_name": "firefox"}, HTTP_HX_REQUEST="true")

        # Add second package
        self.client.post(add_url, {"package_name": "chromium"}, HTTP_HX_REQUEST="true")

        # Check subscription center shows both subscriptions
        response = self.client.get(reverse("webview:subscriptions:center"))
        self.assertEqual(response.status_code, 200)

        # Check context contains both subscriptions
        self.assertIn("package_subscriptions", response.context)
        subscriptions = response.context["package_subscriptions"]
        self.assertIn("firefox", subscriptions)
        self.assertIn("chromium", subscriptions)
        self.assertEqual(len(subscriptions), 2)

    def test_subscription_center_shows_empty_state(self) -> None:
        """Test empty state when user has no subscriptions"""
        response = self.client.get(reverse("webview:subscriptions:center"))
        self.assertEqual(response.status_code, 200)

        # Check context shows empty subscriptions
        self.assertIn("package_subscriptions", response.context)
        self.assertEqual(response.context["package_subscriptions"], [])

    def test_subscription_center_requires_login(self) -> None:
        """Test that subscription center redirects when not logged in"""
        # Logout the user
        self.client.logout()

        response = self.client.get(reverse("webview:subscriptions:center"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

        # Test add endpoint also requires login
        response = self.client.post(
            reverse("webview:subscriptions:add"), {"package_name": "firefox"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

        # Test remove endpoint also requires login
        response = self.client.post(
            reverse("webview:subscriptions:remove"), {"package_name": "firefox"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

        # Test HTMX requests also require login
        response = self.client.post(
            reverse("webview:subscriptions:add"),
            {"package_name": "firefox"},
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

        response = self.client.post(
            reverse("webview:subscriptions:remove"),
            {"package_name": "firefox"},
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_user_unsubscribes_from_empty_package_name_fails_htmx(self) -> None:
        """Test unsubscription fails for empty package name via HTMX"""
        url = reverse("webview:subscriptions:remove")
        response = self.client.post(url, {"package_name": ""}, HTTP_HX_REQUEST="true")

        # Should return 200 with component template for HTMX request
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "subscriptions/components/packages.html")

        # Check that error message is in context
        self.assertIn("error_message", response.context)
        self.assertIn("required", response.context["error_message"])

        # Verify empty subscriptions in context
        self.assertIn("package_subscriptions", response.context)
        self.assertEqual(response.context["package_subscriptions"], [])

    def test_user_receives_notification_for_subscribed_package_suggestion(self) -> None:
        """Test that users receive notifications when suggestions affect their subscribed packages"""
        # User subscribes to firefox package
        add_url = reverse("webview:subscriptions:add")
        self.client.post(add_url, {"package_name": "firefox"}, HTTP_HX_REQUEST="true")

        # Create CVE and container - this should trigger automatic linkage and then notifications
        assigner = Organization.objects.create(uuid=1, short_name="test_org")
        cve_record = CveRecord.objects.create(
            cve_id="CVE-2025-0001",
            assigner=assigner,
        )

        description = Description.objects.create(value="Test firefox vulnerability")
        metric = Metric.objects.create(format="cvssV3_1", raw_cvss_json={})
        affected_product = AffectedProduct.objects.create(package_name="firefox")
        affected_product.versions.add(
            Version.objects.create(status=Version.Status.AFFECTED, version="120.0")
        )

        container = cve_record.container.create(
            provider=assigner,
            title="Firefox Security Issue",
        )

        container.affected.set([affected_product])
        container.descriptions.set([description])
        container.metrics.set([metric])

        # Trigger the linkage and notification system manually since pgpubsub triggers won't work in tests
        linkage_created = build_new_links(container)

        if linkage_created:
            # Get the created proposal and trigger notifications
            suggestion = CVEDerivationClusterProposal.objects.get(cve=cve_record)
            create_package_subscription_notifications(suggestion)

        # Verify notification appears in notification center context
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)

        # Check that notification appears in context
        notifications = response.context["notifications"]
        self.assertEqual(len(notifications), 1)

        notification = notifications[0]
        self.assertEqual(notification.user, self.user)
        self.assertIn("firefox", notification.title)
        self.assertIn("CVE-2025-0001", notification.message)
        self.assertFalse(notification.is_read)  # Should be unread initially

    def test_package_subscription_page_shows_valid_package(self) -> None:
        """Test that the package subscription page displays correctly for valid packages"""
        url = reverse(
            "webview:subscriptions:package", kwargs={"package_name": "firefox"}
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "subscriptions/package_subscription.html")

        # Check context
        self.assertEqual(response.context["package_name"], "firefox")
        self.assertTrue(response.context["package_exists"])
        self.assertFalse(response.context["is_subscribed"])
        self.assertIsNone(response.context["error_message"])

    def test_package_subscription_page_shows_invalid_package(self) -> None:
        """Test that the package subscription page shows error for invalid packages"""
        url = reverse(
            "webview:subscriptions:package", kwargs={"package_name": "nonexistent"}
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "subscriptions/package_subscription.html")

        # Check context
        self.assertEqual(response.context["package_name"], "nonexistent")
        self.assertFalse(response.context["package_exists"])
        self.assertFalse(response.context["is_subscribed"])
        self.assertIsNotNone(response.context["error_message"])
        self.assertIn("does not exist", response.context["error_message"])

    def test_package_subscription_page_subscribe_action(self) -> None:
        """Test subscribing to a package via the package subscription page"""
        url = reverse(
            "webview:subscriptions:package", kwargs={"package_name": "firefox"}
        )
        response = self.client.post(url, {"action": "subscribe"})

        # Should redirect back to the same page
        self.assertEqual(response.status_code, 302)
        self.assertIn("firefox", response.url)

        # Follow redirect and check subscription status
        response = self.client.get(response.url)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["is_subscribed"])

    def test_package_subscription_page_unsubscribe_action(self) -> None:
        """Test unsubscribing from a package via the package subscription page"""
        # First subscribe to the package
        self.user.profile.package_subscriptions.append("firefox")
        self.user.profile.save(update_fields=["package_subscriptions"])

        url = reverse(
            "webview:subscriptions:package", kwargs={"package_name": "firefox"}
        )

        # Verify initially subscribed
        response = self.client.get(url)
        self.assertTrue(response.context["is_subscribed"])

        # Unsubscribe
        response = self.client.post(url, {"action": "unsubscribe"})

        # Should redirect back to the same page
        self.assertEqual(response.status_code, 302)
        self.assertIn("firefox", response.url)

        # Follow redirect and check subscription status
        response = self.client.get(response.url)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["is_subscribed"])
