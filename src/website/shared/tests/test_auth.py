from typing import Any

from django.conf import settings
from django.contrib.auth.models import Group, User
from django.test import RequestFactory, TestCase
from django.urls import reverse

# TODELETE: It wasn't possible to make the custom form work with admin autocomplete easily
# from webview.admin import nixpkgsissueform_factory
from shared import models


# Helper functions (to improve setup readability)
def create_metadata_with_maintainer(id: int, username: str) -> models.NixDerivationMeta:
    meta = models.NixDerivationMeta.objects.create(
        insecure=False,
        available=False,
        broken=False,
        unfree=False,
        unsupported=False,
    )

    meta.maintainers.add(
        models.NixMaintainer.objects.create(github_id=id, github=username)
    )

    return meta


def create_evaluation() -> models.NixEvaluation:
    return models.NixEvaluation.objects.create(
        channel=models.NixChannel.objects.create(),
    )


class AuthTests(TestCase):
    @classmethod
    def setUpTestData(cls: Any) -> None:
        cls.factory = RequestFactory()
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
        cls.cve = models.CveRecord.objects.create(
            assigner=models.Organization.objects.create(
                uuid="8254265b-2729-46b6-b9e3-3dfca2d5bfca"
            )
        )
        cls.description = models.Description.objects.create()
        cls.evaluation = create_evaluation()
        cls.derivation = models.NixDerivation.objects.create(
            metadata=create_metadata_with_maintainer(1, cls.committer.username),
            parent_evaluation=cls.evaluation,
        )
        cls.derivation_not_related = models.NixDerivation.objects.create(
            metadata=create_metadata_with_maintainer(2, "not-related"),
            parent_evaluation=cls.evaluation,
        )

    def test_superuser_can_add_issue_from_admin_site(self) -> None:
        self.client.login(username=self.superuser.username, password=self.password)
        response = self.client.post(reverse("admin:shared_nixpkgsissue_add"))
        self.assertEqual(response.status_code, 200)

    def test_security_can_add_issue_from_admin_site(self) -> None:
        self.client.login(
            username=self.security_member.username, password=self.password
        )
        response = self.client.post(reverse("admin:shared_nixpkgsissue_add"))
        self.assertEqual(response.status_code, 200)

    """
    # FIXME: Check whether test or logic is wrong
    def test_committer_cannot_add_non_related_issue_from_admin_site(self) -> None:
        # Committers can add issues that relate to derivations they maintain
        self.client.login(username=self.committer.username, password=self.password)
        data = {
            "code": "NIXPKGS-2024-0000",
            "cve": [self.cve.id],  # type: ignore
            "description": self.description.id,  # type: ignore
            "status": "U",
            "derivations": [self.derivation_not_related.id],  # type: ignore
        }

        response = self.client.post(reverse("admin:shared_nixpkgsissue_add"))
        self.assertEqual(response.status_code, 200)

        '''
        # TODO: Find another way to prevent insertions from non related maintainers
        request = self.factory.post(reverse("admin:shared_nixpkgsissue_add"))
        request.user = self.committer
        form_class = nixpkgsissueform_factory(request)
        form = form_class(data=data)  # type: ignore

        self.assertFalse(form.is_valid())
        self.assertEqual(
            form.errors["derivations"],
            ["Cannot add issues that relate to derivations you do not maintain."],
        )
        '''

    def test_committer_can_add_related_issue_from_admin_site(self) -> None:
        # Committers can add issues that relate to derivations they maintain
        self.client.login(username=self.committer.username, password=self.password)
        data = {
            "code": "NIXPKGS-2024-0000",
            "cve": [self.cve.id],  # type: ignore
            "description": self.description.id,  # type: ignore
            "status": "U",
            "derivations": [self.derivation.id],  # type: ignore
        }

        self.assertTrue(
            self.derivation.metadata.maintainers.filter(  # type: ignore
                github=self.committer.username
            ).exists()
        )

        response = self.client.post(reverse("admin:shared_nixpkgsissue_add"), data=data)
        self.assertEqual(response.status_code, 302)

        '''
        # TODO: Find another way to prevent insertions from non related maintainers
        request = self.factory.post(reverse("admin:shared_nixpkgsissue_add"))
        request.user = self.committer
        form_class = nixpkgsissueform_factory(request)
        form = form_class(data=data)  # type: ignore
        
        self.assertTrue(form.is_valid())
        '''
    """

    def test_viewer_cannot_add_issue_from_admin_site(self) -> None:
        self.client.login(username=self.viewer.username, password=self.password)
        response = self.client.post(reverse("admin:shared_nixpkgsissue_add"))
        self.assertRedirects(
            response,
            f"/admin/login/?next={reverse('admin:shared_nixpkgsissue_add')}",
            status_code=302,
        )
