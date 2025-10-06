from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse

from webview.models import Notification


class NotificationUserStoriesTests(TestCase):
    def setUp(self) -> None:
        # Create test user with social account
        self.user = User.objects.create_user(username="testuser", password="testpass")
        self.user.is_staff = True
        self.user.save()

        SocialAccount.objects.get_or_create(
            user=self.user,
            provider="github",
            uid="123456",
            extra_data={"login": "testuser"},
        )

        self.client = Client()
        self.client.login(username="testuser", password="testpass")

        # Create another user to test security boundaries
        self.other_user = User.objects.create_user(
            username="otheruser", password="testpass"
        )

    def test_user_receives_and_manages_single_notification(self) -> None:
        """
        Complete user story: User receives notification and manages it

        1. User receives notification (system creates it)
        2. User sees badge with count "1" on any page
        3. User clicks badge, goes to notification center
        4. User sees unread notification highlighted
        5. User clicks "mark read", notification updates, badge shows "0"
        6. User clicks "mark unread", notification updates, badge shows "1"
        """
        # Step 1: System creates notification for user
        notification = Notification.objects.create_for_user(
            user=self.user,
            title="Test Notification",
            message="This is a test notification for the user story.",
        )

        # Step 2: User sees badge with count "1" on main page
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)
        # Check that user's profile has correct unread count in context
        self.assertEqual(response.context["user"].profile.unread_notifications_count, 1)

        # Step 3: User clicks badge and goes to notification center
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Test Notification")
        self.assertContains(response, "This is a test notification")

        # Step 4: User sees unread notification highlighted (check CSS class)
        self.assertContains(response, "notification-unread")

        # Step 5: User clicks "mark read" - notification updates, badge shows "0"
        response = self.client.post(
            reverse("webview:notifications:toggle_read", args=[notification.id])
        )
        self.assertEqual(response.status_code, 302)  # Redirect for non-HTMX

        # Verify notification is now read and counter updated
        notification.refresh_from_db()
        self.assertTrue(notification.is_read)

        # Check notification center no longer shows unread styling
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertNotContains(response, "notification-unread")

        # Step 6: User clicks "mark unread" - notification updates, badge shows "1"
        response = self.client.post(
            reverse("webview:notifications:toggle_read", args=[notification.id])
        )
        self.assertEqual(response.status_code, 302)

        # Verify notification is unread again and counter updated
        notification.refresh_from_db()
        self.assertFalse(notification.is_read)
        # Check counter in fresh response context
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.context["user"].profile.unread_notifications_count, 1)

    def test_user_manages_multiple_notifications_with_bulk_operations(self) -> None:
        """
        User story: User handles multiple notifications using bulk operations

        1. User receives multiple notifications
        2. User sees correct badge count
        3. User goes to notification center, sees all notifications
        4. User uses "mark all as read" button
        5. User sees all notifications marked as read, badge shows "0"
        6. User uses "remove all read" to clean up
        7. User sees notification center is now empty
        """
        # Step 1: User receives multiple notifications
        notifications = []
        for i in range(3):
            notification = Notification.objects.create_for_user(
                user=self.user,
                title=f"Notification {i + 1}",
                message=f"This is test notification number {i + 1}",
            )
            notifications.append(notification)

        # Step 2: User sees correct badge count
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"].profile.unread_notifications_count, 3)

        # Step 3: User goes to notification center, sees all notifications
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)
        for i in range(3):
            self.assertContains(response, f"Notification {i + 1}")
            self.assertContains(response, f"test notification number {i + 1}")

        # All should be unread initially
        response_content = response.content.decode()
        unread_count = response_content.count("notification-unread")
        self.assertEqual(unread_count, 3)

        # Step 4: User uses "mark all as read" button
        response = self.client.post(reverse("webview:notifications:mark_all_read"))
        self.assertEqual(response.status_code, 302)  # Redirect for non-HTMX

        # Step 5: All notifications marked as read, badge shows "0"
        for notification in notifications:
            notification.refresh_from_db()
            self.assertTrue(notification.is_read)

        # Check notification center shows no unread notifications
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertNotContains(response, "notification-unread")
        # Verify counter is 0 in context
        self.assertEqual(response.context["user"].profile.unread_notifications_count, 0)

        # Step 6: User uses "remove all read" to clean up
        response = self.client.post(reverse("webview:notifications:remove_all_read"))
        self.assertEqual(response.status_code, 302)  # Redirect for non-HTMX

        # Step 7: Notification center is now empty
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertContains(response, "You don't have any notifications yet.")

        # Verify notifications were actually deleted
        remaining_notifications = Notification.objects.filter(user=self.user).count()
        self.assertEqual(remaining_notifications, 0)

    def test_user_navigates_paginated_notifications(self) -> None:
        """
        User story: User with many notifications browses through pages

        1. User receives many notifications (more than one page)
        2. User goes to notification center, sees pagination
        3. User navigates to page 2, sees different notifications
        4. User marks notification on page 2 as read
        5. User returns to page 1, sees consistent state
        6. Badge count reflects changes accurately
        """
        # Step 1: Create many notifications (more than paginate_by = 10)
        notifications = []
        for i in range(15):
            notification = Notification.objects.create_for_user(
                user=self.user,
                title=f"Notification {i + 1:02d}",
                message=f"Message content for notification {i + 1}",
            )
            notifications.append(notification)

        # Verify all are unread
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.context["user"].profile.unread_notifications_count, 15
        )

        # Step 2: User goes to notification center, sees pagination
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)

        # Should see newest 10 notifications (15, 14, 13, ..., 06)
        self.assertContains(response, "Notification 15")
        self.assertContains(response, "Notification 06")
        self.assertNotContains(response, "Notification 05")  # Should be on page 2

        # Step 3: User navigates to page 2
        response = self.client.get(reverse("webview:notifications:center") + "?page=2")
        self.assertEqual(response.status_code, 200)

        # Should see older notifications (05, 04, 03, 02, 01)
        self.assertContains(response, "Notification 05")
        self.assertContains(response, "Notification 01")
        self.assertNotContains(response, "Notification 06")  # Should be on page 1

        # Step 4: User marks notification on page 2 as read
        # Get the first notification (oldest one, should be on page 2)
        first_notification = notifications[0]  # "Notification 01"
        response = self.client.post(
            reverse("webview:notifications:toggle_read", args=[first_notification.id]),
            data={"page": "2"},  # Preserve current page
        )
        self.assertEqual(response.status_code, 302)

        # Step 5: User returns to page 1, sees consistent state
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)

        # Should still see page 1 notifications
        self.assertContains(response, "Notification 15")
        self.assertContains(response, "Notification 06")

        # Step 6: Badge count reflects the one notification marked as read
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(
            response.context["user"].profile.unread_notifications_count, 14
        )

        first_notification.refresh_from_db()
        self.assertTrue(first_notification.is_read)

    def test_user_works_without_javascript(self) -> None:
        """
        User story: User with JavaScript disabled can still manage notifications

        1. User (no JS) receives notifications
        2. User navigates to notification center
        3. User marks notification as read - gets redirected to same page
        4. User uses bulk operations - gets redirected appropriately
        5. User stays on current page throughout operations
        """
        # Step 1: User receives notifications
        notification1 = Notification.objects.create_for_user(
            user=self.user, title="First Notification", message="First message"
        )
        notification2 = Notification.objects.create_for_user(
            user=self.user, title="Second Notification", message="Second message"
        )

        # Step 2: User navigates to notification center
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "First Notification")
        self.assertContains(response, "Second Notification")

        # Step 3: User marks notification as read without HTMX - gets redirected
        response = self.client.post(
            reverse("webview:notifications:toggle_read", args=[notification1.id]),
            data={"page": "1"},  # Simulate page preservation
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("notifications", response.url)
        self.assertIn("page=1", response.url)

        # Follow the redirect and verify state
        response = self.client.get(response.url)
        self.assertEqual(response.status_code, 200)

        # Verify notification was marked as read
        notification1.refresh_from_db()
        self.assertTrue(notification1.is_read)

        # Step 4: User uses "mark all as read" - gets redirected appropriately
        response = self.client.post(
            reverse("webview:notifications:mark_all_read"), data={"page": "1"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("notifications", response.url)

        # Follow redirect and verify all are read
        response = self.client.get(response.url)
        self.assertEqual(response.status_code, 200)

        notification2.refresh_from_db()
        self.assertTrue(notification2.is_read)

        # Step 5: User removes all read notifications
        response = self.client.post(reverse("webview:notifications:remove_all_read"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("notifications", response.url)

        # Follow redirect - should show empty state
        response = self.client.get(response.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "You don't have any notifications yet.")

    def test_user_security_boundaries_enforced(self) -> None:
        """
        User story: System properly enforces security boundaries

        1. User A receives notifications
        2. User B cannot access User A's notifications
        3. User B cannot modify User A's notifications
        4. Anonymous users are redirected to login
        """
        # Step 1: User A receives notifications
        notification = Notification.objects.create_for_user(
            user=self.user,
            title="Private Notification",
            message="This should only be visible to the owner",
        )

        # Step 2: User B cannot access User A's notifications
        other_client = Client()
        other_client.login(username="otheruser", password="testpass")

        # Other user's notification center should not show User A's notifications
        response = other_client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Private Notification")
        self.assertContains(response, "You don't have any notifications yet.")

        # Step 3: User B cannot modify User A's notifications
        response = other_client.post(
            reverse("webview:notifications:toggle_read", args=[notification.id])
        )
        self.assertEqual(response.status_code, 404)  # Should not find the notification

        # Step 4: Anonymous users are redirected to login
        anonymous_client = Client()

        response = anonymous_client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 302)  # Redirect to login
        self.assertIn("login", response.url)

        response = anonymous_client.post(
            reverse("webview:notifications:toggle_read", args=[notification.id])
        )
        self.assertEqual(response.status_code, 302)  # Redirect to login
        self.assertIn("login", response.url)

    def test_user_sees_helpful_empty_state(self) -> None:
        """
        User story: User sees appropriate messages for various empty states
        """
        # Step 1: New user has no notifications
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "You don't have any notifications yet.")

        # Should not show bulk operation buttons when empty
        self.assertNotContains(response, "Mark all as read")
        self.assertNotContains(response, "Remove read notifications")

        # Step 2: User gets notifications, then removes them all
        notification = Notification.objects.create_for_user(
            user=self.user,
            title="Temporary Notification",
            message="This will be removed",
        )

        # Mark as read and remove
        self.client.post(
            reverse("webview:notifications:toggle_read", args=[notification.id])
        )
        self.client.post(reverse("webview:notifications:remove_all_read"))

        # Step 3: Should see empty state again
        response = self.client.get(reverse("webview:notifications:center"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "You don't have any notifications yet.")

        # Verify notification was actually deleted
        self.assertFalse(Notification.objects.filter(user=self.user).exists())

        # Badge should show no unread notifications
        response = self.client.get(reverse("webview:suggestions_view"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"].profile.unread_notifications_count, 0)
