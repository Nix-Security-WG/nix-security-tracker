from django.apps import AppConfig
from django.db.models.signals import post_migrate


class SharedConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "shared"

    def ready(self) -> None:
        import shared.listeners  # noqa
        from shared.auth import reset_group_permissions

        # Configuration of signals

        # Reset general group perimissions after migrations to
        # include potential new permissions added.
        post_migrate.connect(reset_group_permissions, sender=self)
