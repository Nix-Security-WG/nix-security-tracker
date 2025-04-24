from django.apps import AppConfig
from django.conf import settings


class SharedConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "shared"

    def ready(self) -> None:
        import shared.listeners  # noqa

        # TODO: run this as a separate service, as this is almost exclusively a deployment concern
        if settings.SYNC_GITHUB_STATE_AT_STARTUP:
            from shared.auth.github_state import GithubState

            self.github_state = GithubState()

            # Sync the group memberships with the GitHub teams. This is relevant:
            # - when starting the server for the first time.
            # - when restarting, in case it missed webhook notifications while being down.
            self.github_state.sync_groups_with_github_teams()
