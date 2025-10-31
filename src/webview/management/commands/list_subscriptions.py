from argparse import ArgumentParser
from typing import Any

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "List all package subscriptions for a user"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--user",
            type=str,
            help="Username to list subscriptions for",
            required=True,
        )

    def handle(self, *args: Any, **options: Any) -> None:
        username = options["user"]

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError(f"User '{username}' does not exist")

        subscriptions = user.profile.package_subscriptions

        if not subscriptions:
            self.stdout.write(f"No package subscriptions found for user '{username}'")
            return

        self.stdout.write(f"Package subscriptions for user '{username}':")
        self.stdout.write("-" * 50)

        for i, package in enumerate(subscriptions, 1):
            self.stdout.write(f"{i}. {package}")
