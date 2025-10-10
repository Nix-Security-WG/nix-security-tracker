from argparse import ArgumentParser
from typing import Any

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.db import transaction

from webview.models import Profile


class Command(BaseCommand):
    help = "Create missing profiles for users that don't have them"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--user",
            type=str,
            help="Username to create profile for (if not provided, creates for all users missing profiles)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        username = options.get("user")

        if username:
            try:
                user = User.objects.get(username=username)
                users = [user]
                self.stdout.write(f"Creating missing profile for user '{username}'")
            except User.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"User '{username}' does not exist"))
                return
        else:
            users = User.objects.all()
            self.stdout.write("Creating missing profiles for all users")

        created_count = 0

        with transaction.atomic():
            for user in users:
                try:
                    user.profile
                    if username:
                        self.stdout.write(
                            f"Profile already exists for '{user.username}'"
                        )
                except Profile.DoesNotExist:
                    Profile.objects.create(user=user)
                    self.stdout.write(f"Created profile for '{user.username}'")
                    created_count += 1

        if created_count > 0:
            self.stdout.write(
                self.style.SUCCESS(f"Created {created_count} missing profiles")
            )
        else:
            self.stdout.write("No missing profiles found")
