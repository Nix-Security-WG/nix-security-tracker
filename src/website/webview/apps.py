from django.apps import AppConfig
from django.db.models.signals import post_migrate
from django.dispatch import receiver


class WebviewConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "webview"

    def ready(self):
        pass


@receiver(post_migrate)
def ensure_groups(sender, **kwargs):
    from django.contrib.auth.models import Group

    secteam, created = Group.objects.get_or_create(name="Security team")
    maintainers, created = Group.objects.get_or_create(name="Package maintainers")
