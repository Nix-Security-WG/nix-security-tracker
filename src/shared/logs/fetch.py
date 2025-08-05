from typing import cast

from django.contrib.auth.models import User
from django.db.models import (
    BigIntegerField,
    Case,
    OuterRef,
    Q,
    Subquery,
    Value,
    When,
)
from django.db.models.functions import Cast, Coalesce
from django.forms.models import model_to_dict
from pghistory.models import EventQuerySet

from shared.logs.raw_events import (
    Maintainer,
    RawEventType,
    RawMaintainerEvent,
    RawPackageEvent,
    RawStatusEvent,
)
from shared.models import (
    CVEDerivationClusterProposalStatusEvent,  # type: ignore
    MaintainersEditEvent,  # type: ignore
    PackageEditEvent,  # type: ignore
)


def _annotate_username(query: EventQuerySet) -> EventQuerySet:
    """Add username annotation to a query."""
    return query.annotate(
        username=Coalesce(
            Case(
                When(Q(pgh_context__isnull=True), then=Value("ADMIN")),
                When(
                    Q(pgh_context__metadata__contains={"user": None}),
                    then=Value("ANONYMOUS"),
                ),
                default=Subquery(
                    User.objects.filter(
                        id=Cast(
                            OuterRef("pgh_context__metadata__user"),
                            BigIntegerField(),
                        )
                    ).values("username")[:1]
                ),
            ),
            Value("REDACTED"),
        )
    )


def fetch_suggestion_events(suggestion_id: int) -> list[RawEventType]:
    """Fetch all raw events for a suggestion and return them sorted by timestamp."""
    all_events: list[RawEventType] = []

    # Fetch status events
    status_qs = _annotate_username(
        CVEDerivationClusterProposalStatusEvent.objects.prefetch_related(
            "pgh_context",
        )
        .exclude(pgh_label="insert")
        .filter(pgh_obj_id=suggestion_id)
    )

    for status_event in status_qs.all().iterator():
        all_events.append(
            RawStatusEvent(
                suggestion_id=status_event.pgh_obj_id,
                timestamp=status_event.pgh_created_at,
                username=status_event.username,
                action=status_event.pgh_label,
                status_value=status_event.status,
            )
        )

    # Fetch package events
    package_edit_qs = _annotate_username(
        PackageEditEvent.objects.filter(suggestion_id=suggestion_id)
    )

    for package_edit_event in package_edit_qs.all().iterator():
        all_events.append(
            RawPackageEvent(
                suggestion_id=package_edit_event.suggestion.id,
                timestamp=package_edit_event.pgh_created_at,
                username=package_edit_event.username,
                action=package_edit_event.pgh_label,
                package_attribute=package_edit_event.package_attribute,
            )
        )

    # Fetch maintainer events
    maintainer_qs = _annotate_username(
        MaintainersEditEvent.objects.prefetch_related(
            "pgh_context", "maintainer"
        ).filter(suggestion_id=suggestion_id)
    )

    for maintainer_event in maintainer_qs.all().iterator():
        all_events.append(
            RawMaintainerEvent(
                suggestion_id=maintainer_event.suggestion.id,
                timestamp=maintainer_event.pgh_created_at,
                username=maintainer_event.username,
                action=maintainer_event.pgh_label,
                maintainer=cast(Maintainer, model_to_dict(maintainer_event.maintainer)),
            )
        )

    return all_events
