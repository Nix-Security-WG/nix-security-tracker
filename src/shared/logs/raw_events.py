from abc import ABC, abstractmethod
from datetime import datetime
from typing import Literal, TypedDict

from pydantic import BaseModel


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

    def precedes_close_related_event(
        self, other: "RawEvent", time_threshold_seconds: int = 30
    ) -> bool:
        """Checks the event is followed by one related to the same suggestion by the same user within a give time window"""
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
        """Status events don't cancel each other."""
        return False


class RawPackageEvent(RawEvent):
    """Raw package change event."""

    action: Literal["package.add", "package.remove"]
    package_attribute: str

    def is_canceled_by(
        self, other: "RawEvent", time_threshold_seconds: int = 30
    ) -> bool:
        """Check if this package event is canceled by another package event."""
        if not self.precedes_close_related_event(other, time_threshold_seconds):
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
        if not self.precedes_close_related_event(other, time_threshold_seconds):
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
