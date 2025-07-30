from collections.abc import Iterator

from shared.logs.raw_events import RawEventType


class EventCollection:
    """
    A collection of raw events that provides filtering and manipulation capabilities.
    This class is agnostic to the source of events (suggestions, users, etc.)
    """

    def __init__(self, events: list[RawEventType], _skip_sort: bool = False) -> None:
        """Initialize with a list of raw events, optionally skipping sort if already sorted."""
        if _skip_sort:
            self._events = events
        else:
            self._events = sorted(events, key=lambda event: event.timestamp)

    @property
    def events(self) -> list[RawEventType]:
        """Get the current list of events."""
        return self._events.copy()

    def __len__(self) -> int:
        """Return the number of events in the collection."""
        return len(self._events)

    def __iter__(self) -> Iterator[RawEventType]:
        """Make the collection iterable."""
        return iter(self._events)

    def remove_canceling_events(
        self, time_threshold_seconds: int = 30
    ) -> "EventCollection":
        """Remove consecutive events that cancel each other out within a time window."""
        filtered_events = []
        i = 0

        while i < len(self._events):
            if i + 1 < len(self._events) and self._events[i].is_canceled_by(
                self._events[i + 1], time_threshold_seconds
            ):
                # Skip both events
                i += 2
            else:
                # Keep this event
                filtered_events.append(self._events[i])
                i += 1

        # Skip sorting since filtered_events maintains chronological order
        return EventCollection(filtered_events, _skip_sort=True)
