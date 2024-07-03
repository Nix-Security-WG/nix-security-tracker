from typing import Any

from django.conf import settings
from django.contrib.auth.models import Group, User
from django.test import TestCase
from django.urls import reverse


class AuthTests(TestCase):
    @classmethod
    def setUpTestData(cls: Any) -> None:
        cls.group_security_team = Group.objects.get(name=settings.GROUP_SECURITY_TEAM)
        cls.password = "pass"
        # Superusers bypass all auth logic, creating one to validate the happy path
        cls.superuser = User.objects.create_superuser(
            username="superuser", password=cls.password, email="superuser@localhost"
        )
        # Security members get admin permissions.
        cls.security_member = User.objects.create_user(
            username="security-member", password=cls.password
        )
        cls.security_member.groups.add(cls.group_security_team)
        # Committers get write permissions to models that relate to derivations they maintain
        cls.committer = User.objects.create_user(
            username="committer", password=cls.password
        )
        # Anybody else gets read permissions
        cls.viewer = User.objects.create_user(username="viewer", password=cls.password)

        # Create some objects to check list views
        # TODO:

    def test_superuser_can_add_issue_from_admin_site(self) -> None:
        self.client.login(username=self.superuser.username, password=self.password)
        response = self.client.post(reverse("admin:shared_nixpkgsissue_add"))
        self.assertEqual(response.status_code, 200)

    def test_security_can_add_issue_from_admin_site(self) -> None:
        # print(self.security_member.groups.all())
        # print(self.security_member.groups.get(name=settings.GROUP_SECURITY_TEAM))
        self.client.login(
            username=self.security_member.username, password=self.password
        )
        response = self.client.post(reverse("admin:shared_nixpkgsissue_add"))
        self.assertEqual(response.status_code, 200)

    def test_committer_cannot_add_non_related_issue_from_admin_site(self) -> None:
        # Committers can add issues that relate to derivations they maintain
        self.client.login(username=self.committer.username, password=self.password)
        response = self.client.post(reverse("admin:shared_nixpkgsissue_add"))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(
            response,
            f"/admin/login/?next={reverse('admin:shared_nixpkgsissue_add')}",
            status_code=302,
        )

    # TODO: make test_committer_can_add_related_issue_from_admin_site(self) -> None:

    def test_viewer_cannot_add_issue_from_admin_site(self) -> None:
        self.client.login(username=self.viewer.username, password=self.password)
        response = self.client.post(reverse("admin:shared_nixpkgsissue_add"))
        self.assertRedirects(
            response,
            f"/admin/login/?next={reverse('admin:shared_nixpkgsissue_add')}",
            status_code=302,
        )
