# Create your models here.
from typing import Any

from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from shared.models import NixpkgsIssue


class Profile(models.Model):
    """
    Profile associated to a user, storing extra non-auth-related data such as
    active issue subscriptions.
    """

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    subscriptions = models.ManyToManyField(NixpkgsIssue, related_name="subscribers")


@receiver(post_save, sender=User)
def create_profile(
    sender: type[User], instance: User, created: bool, **kwargs: Any
) -> None:
    if created:
        Profile.objects.create(user=instance)
