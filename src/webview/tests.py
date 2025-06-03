from unittest.mock import patch

from allauth.socialaccount.templatetags.socialaccount import provider_login_url
from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.shortcuts import redirect
from django.test import TestCase
from django.urls import reverse


class Login(TestCase):
    def setUp(self):
        # location to start navigation
        self.entry_point = reverse("webview:suggestions_view")

    def test_foo(self):
        response = self.client.get(self.entry_point)
        context = response.context[0]
        login_url = provider_login_url(context, "github")
        # follow the login workflow as displayed
        self.assertIn(login_url, response.content.decode("utf-8"))
        response = self.client.get(login_url)
        # expect confirmation to log in and a CSRF barrier via POST request
        self.assertIn("form", response.content.decode("utf-8"))

        def mock_login(self, request, *args, **kwargs):
            user, _ = get_user_model().objects.get_or_create(username="testuser")
            login(
                request,
                user,
                backend="allauth.account.auth_backends.AuthenticationBackend",
            )
            return redirect(settings.LOGIN_REDIRECT_URL)

        with patch(
            "allauth.socialaccount.providers.oauth2.views.OAuth2LoginView.dispatch",
            mock_login,
        ):
            # log in and follow redirect
            response = self.client.post(login_url, {}, follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["user"].is_authenticated)
        location, status = response.redirect_chain[-1]
        self.assertEqual(location, self.entry_point)
