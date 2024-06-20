from typing import Any

from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.db.models.signals import post_migrate
from django.dispatch import receiver


def reset_group_permissions() -> None:
    """
    Reset general permissions in case new tables were created.
    """
    # Secury team members have admin permissions
    security = Group.objects.get(name="security_team")
    security.permissions.set(Permission.objects.all())
    security.save()

    # Committers have write permissions
    committers = Group.objects.get(name="committers")
    # TODO: finetune filter
    committers.permissions.set(
        Permission.objects.filter(
            (Q(codename__icontains="view_") | Q(codename__icontains="change_"))
            & Q(codename__icontains="nix")
        )
    )
    committers.save()

    # Readers have read permissions
    readers = Group.objects.get(name="readers")
    # TODO: finetune filter
    readers.permissions.set(
        Permission.objects.filter(
            Q(codename__icontains="view_") & Q(codename__icontains="nix")
        )
    )
    readers.save()


@receiver(post_migrate)
def reset_group_permissions_post_migration(sender: Any, **kwargs: Any) -> None:
    reset_group_permissions()
