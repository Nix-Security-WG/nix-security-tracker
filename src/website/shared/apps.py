from django.apps import AppConfig
from django.db.models.signals import post_save


class SharedConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "shared"

    def ready(self) -> None:
        import shared.listeners  # noqa
        from shared.auth import (
            init_user_groups,
        )
        from allauth.socialaccount.models import SocialAccount

        # Configuration of signals

        # Initialize group memberships when a user first logs in via Github.
        post_save.connect(init_user_groups, sender=SocialAccount)
