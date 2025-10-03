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
    unread_notifications_count = models.PositiveIntegerField(default=0)

    def recalculate_unread_notifications_count(self) -> None:
        """Recalculate and update the unread notifications count from the database."""
        count = self.user.notifications.filter(is_read=False).count()
        if self.unread_notifications_count != count:
            self.unread_notifications_count = count
            self.save(update_fields=["unread_notifications_count"])


@receiver(post_save, sender=User)
def create_profile(
    sender: type[User], instance: User, created: bool, **kwargs: Any
) -> None:
    if created:
        Profile.objects.create(user=instance)


class NotificationManager(models.Manager):
    def create_for_user(
        self, user: User, title: str, message: str, is_read: bool = False
    ) -> "Notification":
        """Create a notification and update the user's unread counter."""
        notification = self.create(
            user=user, title=title, message=message, is_read=is_read
        )

        # Update counter if notification is unread
        if not is_read:
            profile = user.profile
            profile.unread_notifications_count += 1
            profile.save(update_fields=["unread_notifications_count"])

        return notification

    def mark_read_for_user(self, user: User, notification_id: int) -> bool:
        """Mark a specific notification as read and update counter. Returns True if status changed."""
        try:
            notification = self.get(id=notification_id, user=user)
            if not notification.is_read:
                notification.is_read = True
                notification.save(update_fields=["is_read"])

                # Update counter
                profile = user.profile
                profile.unread_notifications_count = max(
                    0, profile.unread_notifications_count - 1
                )
                profile.save(update_fields=["unread_notifications_count"])
                return True
            return False
        except self.model.DoesNotExist:
            return False

    def mark_unread_for_user(self, user: User, notification_id: int) -> bool:
        """Mark a specific notification as unread and update counter. Returns True if status changed."""
        try:
            notification = self.get(id=notification_id, user=user)
            if notification.is_read:
                notification.is_read = False
                notification.save(update_fields=["is_read"])

                # Update counter
                profile = user.profile
                profile.unread_notifications_count += 1
                profile.save(update_fields=["unread_notifications_count"])
                return True
            return False
        except self.model.DoesNotExist:
            return False

    def toggle_read_for_user(self, user: User, notification_id: int) -> int:
        """Toggle a notification's read status and update counter. Returns the new unread counter."""
        try:
            notification = self.get(id=notification_id, user=user)
            old_is_read = notification.is_read
            notification.is_read = not notification.is_read
            notification.save(update_fields=["is_read"])

            # Update counter based on the change
            new_is_read = old_is_read
            if old_is_read and not notification.is_read:
                # Was read, now unread - increment
                profile = user.profile
                new_is_read = profile.unread_notifications_count + 1
                profile.unread_notifications_count = new_is_read
                profile.save(update_fields=["unread_notifications_count"])
            elif not old_is_read and notification.is_read:
                # Was unread, now read - decrement
                profile = user.profile
                new_is_read = profile.unread_notifications_count - 1
                profile.unread_notifications_count = new_is_read
                profile.save(update_fields=["unread_notifications_count"])

            return new_is_read
        except self.model.DoesNotExist:
            return False

    def mark_all_read_for_user(self, user: User) -> int:
        """Mark all notifications as read for a user and reset counter. Returns count of notifications marked."""
        unread_count = self.filter(user=user, is_read=False).count()

        if unread_count > 0:
            # Mark all as read
            self.filter(user=user, is_read=False).update(is_read=True)

            # Reset counter to 0
            profile = user.profile
            profile.unread_notifications_count = 0
            profile.save(update_fields=["unread_notifications_count"])

        return unread_count

    def clear_all_for_user(self, user: User) -> int:
        """Delete all notifications for a user and reset counter. Returns count of notifications deleted."""
        count = self.filter(user=user).count()

        if count > 0:
            self.filter(user=user).delete()

            # Reset counter to 0
            profile = user.profile
            profile.unread_notifications_count = 0
            profile.save(update_fields=["unread_notifications_count"])

        return count

    def clear_read_for_user(self, user: User) -> int:
        """Delete all read notifications for a user. Counter should remain unchanged."""
        count = self.filter(user=user, is_read=True).count()

        if count > 0:
            self.filter(user=user, is_read=True).delete()
            # Note: Counter doesn't change since we only deleted read notifications

        return count


class Notification(models.Model):
    """
    Notification to appear in the notification center of a user.
    """

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="notifications"
    )
    title = models.CharField(max_length=255)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = NotificationManager()
