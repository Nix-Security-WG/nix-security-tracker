# Create your models here.
from django.contrib.auth.models import User
from django.db import models
from shared.models import NixpkgsIssue


class Profile(models.Model):
    """
    Profile associated to a user, storing extra non-auth-related data such as
    active issue subscriptions.
    """

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    subscriptions = models.ManyToManyField(NixpkgsIssue, related_name="subscribers")
