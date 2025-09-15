from abc import ABC
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from shared.logs.events import (
    Maintainer,
    RawEventType,
    RawMaintainerEvent,
    RawPackageEvent,
    RawStatusEvent,
    sort_events_chronologically,
)


class FoldedEvent(BaseModel, ABC):
    """Base class for folded events that can represent single or bulk operations."""

    suggestion_id: int
    timestamp: datetime  # Timestamp of the most recent event of the collection
    username: str


class FoldedStatusEvent(FoldedEvent):
    """A folded status change event (always singular)."""

    action: Literal["insert", "update"]
    # TODO This should eventually be restricted to the few literal values a
    # suggestion status can have
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


def batch_events(
    events: list[RawEventType], sort: bool = False
) -> list[FoldedEventType]:
    """
    Batch consecutive events of the same type from the same user into bulk operations.
    Events must be sorted chronologically. Use the sort flag if not.
    """
    folded_events = []
    accumulator = None

    events = sort_events_chronologically(events) if sort else events

    for event in events:
        if isinstance(event, RawPackageEvent):
            if (
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
                if accumulator:
                    folded_events.append(accumulator)
                accumulator = FoldedPackageEvent(
                    suggestion_id=event.suggestion_id,
                    timestamp=event.timestamp,
                    username=event.username,
                    action=event.action,
                    package_names=[event.package_attribute],
                )

        elif isinstance(event, RawMaintainerEvent):
            if (
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
                if accumulator:
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

    if accumulator:
        folded_events.append(accumulator)

    return folded_events
