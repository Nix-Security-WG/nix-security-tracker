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

        # Update admin registry
        """
        Update the custom admin site registry with the contrib's admin site registry entries.

        Strangely, third party apps are not registering their admin views to the custom admin site,
        despite it being defined as the default admin site.

        From the perspective of the 'tracker' project, the init code below enters an infinite recursion
        when referencing `admin.site._registry`, which means there is a cirucular reference and third 
        party apps should be pointed at the right admin site by default in normal cicumstances.
        '''
            from django.contrib import admin
            ...
            class CustomAdminSite(admin.AdminSite):
                def __init__(self, *args, **kwargs):
                    super(CustomAdminSite, self).__init__(*args, **kwargs)
                    self._registry.update(admin.site._registry)
        '''
        """
        from django.contrib.admin import site
        from tracker.admin import custom_admin_site

        custom_admin_site._registry.update(site._registry)
