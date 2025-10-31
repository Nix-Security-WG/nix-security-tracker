import logging

import pgpubsub
from django.contrib.auth.models import User

from shared.channels import CVEDerivationClusterProposalNotificationChannel
from shared.models.linkage import CVEDerivationClusterProposal
from webview.models import Notification

logger = logging.getLogger(__name__)


def create_package_subscription_notifications(
    suggestion: CVEDerivationClusterProposal,
) -> None:
    """
    Create notifications for users subscribed to packages affected by the suggestion.
    """
    # Extract all affected package names from the suggestion
    affected_packages = list(
        suggestion.derivations.values_list("attribute", flat=True).distinct()
    )

    if not affected_packages:
        logger.debug(f"No packages found for suggestion {suggestion.pk}")
        return

    # Find users subscribed to ANY of these packages
    subscribed_users = User.objects.filter(
        profile__package_subscriptions__overlap=affected_packages
    ).select_related("profile")

    if not subscribed_users.exists():
        logger.debug(f"No subscribed users found for packages: {affected_packages}")
        return

    logger.info(
        f"Creating notifications for {subscribed_users.count()} users for CVE {suggestion.cve.cve_id}"
    )

    for user in subscribed_users:
        # Find which of their subscribed packages are actually affected
        user_affected_packages = [
            pkg
            for pkg in user.profile.package_subscriptions
            if pkg in affected_packages
        ]

        # Create notification
        try:
            Notification.objects.create_for_user(
                user=user,
                title=f"New security suggestion affects: {', '.join(user_affected_packages)}",
                message=f"CVE {suggestion.cve.cve_id} may affect packages you're subscribed to. "
                f"Affected packages: {', '.join(user_affected_packages)}. ",
            )
            logger.debug(
                f"Created notification for user {user.username} for packages: {user_affected_packages}"
            )
        except Exception as e:
            logger.error(f"Failed to create notification for user {user.username}: {e}")


@pgpubsub.post_insert_listener(CVEDerivationClusterProposalNotificationChannel)
def notify_subscribed_users_following_suggestion_insert(
    old: CVEDerivationClusterProposal, new: CVEDerivationClusterProposal
) -> None:
    """
    Notify users subscribed to packages when a new security suggestion is created.
    """
    try:
        create_package_subscription_notifications(new)
    except Exception as e:
        logger.error(
            f"Failed to create package subscription notifications for suggestion {new.pk}: {e}"
        )
