from argparse import ArgumentParser
from typing import Any

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError

from webview.models import Notification


class Command(BaseCommand):
    help = "Create a test notification for a user"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--user",
            type=str,
            help="Username to create notification for",
            required=True,
        )
        parser.add_argument(
            "--title",
            type=str,
            default="Test Notification",
            help="Notification title (default: 'Test Notification')",
        )
        parser.add_argument(
            "--message",
            type=str,
            default="This is a test notification for debugging purposes.",
            help="Notification message (default: test message)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        username = options["user"]
        title = options["title"]
        message = options["message"]

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError(f"User '{username}' does not exist")

        # Use manager method to create notification and update counter
        notification = Notification.objects.create_for_user(
            user=user,
            title=title,
            message=message,
        )

        self.stdout.write(
            self.style.SUCCESS(
                f"Created notification (ID: {notification.pk}) for user '{username}'"
            )
        )
        self.stdout.write(f"  Title: '{title}'")
        self.stdout.write(f"  Message: '{message}'")
