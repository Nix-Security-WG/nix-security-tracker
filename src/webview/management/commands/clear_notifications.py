from argparse import ArgumentParser
from typing import Any

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError

from webview.models import Notification


class Command(BaseCommand):
    help = "Clear all notifications for a user"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--user",
            type=str,
            help="Username to clear notifications for",
            required=True,
        )

    def handle(self, *args: Any, **options: Any) -> None:
        username = options["user"]

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError(f"User '{username}' does not exist")

        # Use manager method to clear all notifications and get count
        count = Notification.objects.clear_all_for_user(user)

        if count == 0:
            self.stdout.write(f"No notifications found for user '{username}'")
            return

        self.stdout.write(
            self.style.SUCCESS(f"Cleared {count} notification(s) for user '{username}'")
        )
