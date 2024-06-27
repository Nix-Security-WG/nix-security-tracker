from django.apps import AppConfig
from django.db.models.signals import m2m_changed, post_migrate, post_save


class SharedConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "shared"

    def ready(self) -> None:
        import shared.listeners  # noqa
        from shared.auth import (
            init_user_groups,
            reset_group_permissions,
            update_maintainer_permissions_m2m_receiver,
        )
        from shared.models import NixDerivationMeta
        from allauth.socialaccount.models import SocialAccount

        # Configuration of signals

        # Reset general group perimissions after migrations to
        # include potential new permissions added.
        post_migrate.connect(reset_group_permissions, sender=self)

        # Initialize group memberships when a user first logs in via Github.
        post_save.connect(init_user_groups, sender=SocialAccount)

        # Initialize group memberships when a user first logs in via Github.
        m2m_changed.connect(
            update_maintainer_permissions_m2m_receiver,
            sender=NixDerivationMeta.maintainers.through,
        )
