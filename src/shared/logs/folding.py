from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from shared.logs.raw_events import (
    Maintainer,
    RawEventType,
    RawMaintainerEvent,
    RawPackageEvent,
    RawStatusEvent,
)


class FoldedEvent(BaseModel):
    """Base class for folded events that can represent single or bulk operations."""

    suggestion_id: int
    timestamp: datetime  # Timestamp of the most recent event of the collection
    username: str


class FoldedStatusEvent(FoldedEvent):
    """A folded status change event (always singular)."""

    action: Literal["insert", "update"]
    status_value: str


class FoldedPackageEvent(FoldedEvent):
    """A folded package event that can represent single or bulk operations."""

    action: Literal["package.add", "package.remove"]
    package_names: list[str]  # Always a list, even for single packages


class FoldedMaintainerEvent(FoldedEvent):
    """A folded maintainer event that can represent single or bulk operations."""

    action: Literal["maintainers.add", "maintainers.remove"]
    maintainers: list[Maintainer]  # Always a list, even for single maintainers


FoldedEventType = FoldedStatusEvent | FoldedPackageEvent | FoldedMaintainerEvent


def fold_events(sorted_events: list[RawEventType]) -> list[FoldedEventType]:
    """
    Fold consecutive events of the same type from the same user into bulk operations.
    """
    folded_events = []
    accumulator = None

    for event in sorted_events:
        if isinstance(event, RawPackageEvent):
            if not accumulator:
                # Start new package accumulator
                accumulator = FoldedPackageEvent(
                    suggestion_id=event.suggestion_id,
                    timestamp=event.timestamp,
                    username=event.username,
                    action=event.action,
                    package_names=[event.package_attribute],
                )
            elif (
                isinstance(accumulator, FoldedPackageEvent)
                and event.action == accumulator.action
                and event.username == accumulator.username
                and event.suggestion_id == accumulator.suggestion_id
            ):
                # Continue accumulating packages
                accumulator.package_names.append(event.package_attribute)
                accumulator.timestamp = event.timestamp
            else:
                # End current accumulator, start new one
                folded_events.append(accumulator)
                accumulator = FoldedPackageEvent(
                    suggestion_id=event.suggestion_id,
                    timestamp=event.timestamp,
                    username=event.username,
                    action=event.action,
                    package_names=[event.package_attribute],
                )

        elif isinstance(event, RawMaintainerEvent):
            if not accumulator:
                # Start new maintainer accumulator
                accumulator = FoldedMaintainerEvent(
                    suggestion_id=event.suggestion_id,
                    timestamp=event.timestamp,
                    username=event.username,
                    action=event.action,
                    maintainers=[event.maintainer],
                )
            elif (
                isinstance(accumulator, FoldedMaintainerEvent)
                and event.action == accumulator.action
                and event.username == accumulator.username
                and event.suggestion_id == accumulator.suggestion_id
            ):
                # Continue accumulating maintainers
                accumulator.maintainers.append(event.maintainer)
                accumulator.timestamp = event.timestamp
            else:
                # End current accumulator, start new one
                folded_events.append(accumulator)
                accumulator = FoldedMaintainerEvent(
                    suggestion_id=event.suggestion_id,
                    timestamp=event.timestamp,
                    username=event.username,
                    action=event.action,
                    maintainers=[event.maintainer],
                )

        else:  # RawStatusEvent or other non-foldable events
            # Flush any accumulator
            if accumulator:
                folded_events.append(accumulator)
                accumulator = None

            # Add status event (always singular)
            if isinstance(event, RawStatusEvent):
                folded_events.append(
                    FoldedStatusEvent(
                        suggestion_id=event.suggestion_id,
                        timestamp=event.timestamp,
                        username=event.username,
                        action=event.action,
                        status_value=event.status_value,
                    )
                )

    # Don't forget the final accumulator
    if accumulator:
        folded_events.append(accumulator)

    return folded_events
