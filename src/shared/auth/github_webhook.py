"""
This view is based on the guide [1] which I (alejandrosame) saw when reading the django forum post [2].

There is a project [3] that implements this logic with a class view, consider using it if this
view function gives problems.

[1] https://gist.github.com/grantmcconnaughey/6169d8b7a2e770e85c5617bc80ed00a9
[2] https://forum.djangoproject.com/t/solved-github-webhooks-django-authentification-help-please/9933
[3] https://github.com/fladi/django-github-webhook
"""

import hashlib
import hmac
import json
import logging

from django.apps import apps
from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)


def handle_webhook(event: str, payload: dict) -> None:
    if event == "membership" and "team" in payload:
        logger.info("Webhook received, updating team membership.")

        gh_state = apps.get_app_config("shared").github_state  # type: ignore
        gh_state.sync_team_membership_from_webhook(
            action=payload["action"],
            github_team_id=payload["team"]["id"],
            github_user_id=payload["member"]["id"],
        )


@csrf_exempt
def handle_github_hook(request: HttpRequest) -> HttpResponse:
    # Validate that the request is from GitHub
    # https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#validating-webhook-deliveries
    try:
        github_signature = request.META["HTTP_X_HUB_SIGNATURE"]
    except KeyError:
        return HttpResponseForbidden("Missing signature header")

    # NOTE: Without utf-8 encoding the secret, hmac.new fails without raising any exception
    signature = hmac.new(
        settings.GH_WEBHOOK_SECRET.encode("utf-8"),
        msg=request.body,
        digestmod=hashlib.sha1,
    )
    expected_signature = "sha1=" + signature.hexdigest()
    if not hmac.compare_digest(github_signature, expected_signature):
        return HttpResponseForbidden("Invalid signature header")

    # Sometimes the payload comes in as the request body, sometimes it comes in
    # as a POST parameter. This will handle either case.
    if "payload" in request.POST:
        payload = json.loads(request.POST["payload"])
    else:
        payload = json.loads(request.body)

    event = request.META["HTTP_X_GITHUB_EVENT"]

    handle_webhook(event, payload)

    return HttpResponse("Webhook received", status=200)
