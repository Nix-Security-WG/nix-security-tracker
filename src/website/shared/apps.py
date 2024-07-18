import sys

from django.apps import AppConfig


class SharedConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "shared"

    def ready(self) -> None:
        import shared.listeners  # noqa

        # This hook is called on any `manage` subcommand.
        # Only connect to GitHub when the server is started.
        if "runserver" in sys.argv:
            from shared.auth.github_state import GithubState

            self.github_state = GithubState()

            # Sync the group memberships with the GitHub teams. This is relevant:
            # - when starting the server for the first time.
            # - when restarting, in case it missed webhook notifications while being down.
            self.github_state.sync_groups_with_github_teams()
