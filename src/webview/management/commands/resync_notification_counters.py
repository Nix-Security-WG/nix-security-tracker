from argparse import ArgumentParser
from typing import Any

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.db import transaction

from webview.models import Profile


class Command(BaseCommand):
    help = "Resync unread notification counters for user profiles"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--user",
            type=str,
            help="Username to resync counter for (if not provided, resyncs all users)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        username = options.get("user")

        if username:
            try:
                user = User.objects.get(username=username)
                users = [user]
                self.stdout.write(
                    f"Resyncing notifications counter for user '{username}'"
                )
            except User.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"User '{username}' does not exist"))
                return
        else:
            users = User.objects.all()
            self.stdout.write("Resyncing notifications counters for all users")

        updated_count = 0
        created_count = 0

        with transaction.atomic():
            for user in users:
                # Get or create profile for this user
                try:
                    profile = user.profile

                    # Store old count for comparison
                    old_count = profile.unread_notifications_count

                    # Use profile method to recalculate and update counter
                    profile.recalculate_unread_notifications_count()

                    # Check if it actually changed
                    if old_count != profile.unread_notifications_count:
                        self.stdout.write(
                            f"'{user.username}': {old_count} -> {profile.unread_notifications_count}"
                        )
                        updated_count += 1

                except Profile.DoesNotExist:
                    self.stderr.write(f"Missing profile for '{user.username}'")

        self.stdout.write(
            self.style.SUCCESS(
                f"Complete: Created {created_count} profiles, updated {updated_count} counters"
            )
        )
