from abc import ABC, abstractmethod
from datetime import datetime
from typing import Literal, TypedDict, cast

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
from pydantic import BaseModel

from shared.models import (
    CVEDerivationClusterProposalStatusEvent,  # type: ignore
    MaintainersEditEvent,  # type: ignore
    PackageEditEvent,  # type: ignore
)


class RawEvent(BaseModel, ABC):
    """Base class for raw events from the database."""

    suggestion_id: int
    timestamp: datetime
    username: str

    @abstractmethod
    def is_canceled_by(
        self, other: "RawEvent", time_threshold_seconds: int = 30
    ) -> bool:
        """Check if this event is canceled by another event.

        Must be implemented by subclasses to define specific cancellation logic.
        """
        pass

    def _basic_cancellation_check(
        self, other: "RawEvent", time_threshold_seconds: int = 30
    ) -> bool:
        """Helper method for common cancellation checks."""
        return (
            self.username == other.username
            and self.suggestion_id == other.suggestion_id
            and (other.timestamp - self.timestamp).total_seconds()
            <= time_threshold_seconds
        )


class RawStatusEvent(RawEvent):
    """Raw status change event."""

    action: Literal["insert", "update"]
    status_value: str

    def is_canceled_by(
        self, other: "RawEvent", time_threshold_seconds: int = 30
    ) -> bool:
        """Status events don't cancel each other currently."""
        return False


class RawPackageEvent(RawEvent):
    """Raw package change event."""

    action: Literal["package.add", "package.remove"]
    package_attribute: str

    def is_canceled_by(
        self, other: "RawEvent", time_threshold_seconds: int = 30
    ) -> bool:
        """Check if this package event is canceled by another package event."""
        if not self._basic_cancellation_check(other, time_threshold_seconds):
            return False

        if isinstance(other, RawPackageEvent):
            return self.package_attribute == other.package_attribute and {
                self.action,
                other.action,
            } == {"package.add", "package.remove"}

        return False


class Maintainer(TypedDict):
    name: str
    email: str | None
    github: str
    matrix: str | None
    github_id: int


class RawMaintainerEvent(RawEvent):
    """Raw maintainer change event."""

    action: Literal["maintainers.add", "maintainers.remove"]
    maintainer: Maintainer

    def is_canceled_by(
        self, other: "RawEvent", time_threshold_seconds: int = 30
    ) -> bool:
        """Check if this maintainer event is canceled by another maintainer event."""
        if not self._basic_cancellation_check(other, time_threshold_seconds):
            return False

        if isinstance(other, RawMaintainerEvent):
            return self.maintainer["github_id"] == other.maintainer["github_id"] and {
                self.action,
                other.action,
            } == {
                "maintainers.add",
                "maintainers.remove",
            }

        return False


RawEventType = RawStatusEvent | RawPackageEvent | RawMaintainerEvent


class EventFetcher:
    """Fetches raw events from the database for a suggestion."""

    def _annotate_username(self, query: EventQuerySet) -> EventQuerySet:
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

    def fetch_suggestion_events(self, suggestion_id: int) -> list[RawEventType]:
        """Fetch all raw events for a suggestion and return them sorted by timestamp."""
        all_events: list[RawEventType] = []

        # Fetch status events
        status_qs = self._annotate_username(
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
        package_edit_qs = self._annotate_username(
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
        maintainer_qs = self._annotate_username(
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
                    maintainer=cast(
                        Maintainer, model_to_dict(maintainer_event.maintainer)
                    ),
                )
            )

        return all_events
