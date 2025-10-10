from argparse import ArgumentParser
from typing import Any

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError

from webview.models import Notification


class Command(BaseCommand):
    help = "List all notifications for a user"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--user",
            type=str,
            help="Username to list notifications for",
            required=True,
        )

    def handle(self, *args: Any, **options: Any) -> None:
        username = options["user"]

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError(f"User '{username}' does not exist")

        notifications = Notification.objects.filter(user=user).order_by("-created_at")

        if not notifications.exists():
            self.stdout.write(f"No notifications found for user '{username}'")
            return

        self.stdout.write(f"Notifications for user '{username}':")
        self.stdout.write("-" * 50)

        for notification in notifications:
            status = "READ" if notification.is_read else "UNREAD"
            status_style = (
                self.style.SUCCESS if notification.is_read else self.style.WARNING
            )

            self.stdout.write(f"ID: {notification.pk}")
            self.stdout.write(f"Status: {status_style(status)}")
            self.stdout.write(f"Title: {notification.title}")
            self.stdout.write(f"Message: {notification.message}")
            self.stdout.write(f"Created: {notification.created_at}")
            if notification.is_read:
                self.stdout.write(f"Read: {notification.updated_at}")
            self.stdout.write("-" * 50)

        total = notifications.count()
        unread = notifications.filter(is_read=False).count()
        self.stdout.write(f"Total: {total} notifications ({unread} unread)")
