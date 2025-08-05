from shared.logs.raw_events import RawEventType


def sort_events_chronologically(events: list[RawEventType]) -> list[RawEventType]:
    """
    Sort a list of raw events chronologically by their timestamp.
    """
    return sorted(events, key=lambda event: event.timestamp)


def remove_canceling_events(
    events: list[RawEventType], time_threshold_seconds: int = 30, pre_sort: bool = False
) -> list[RawEventType]:
    """
    Remove consecutive events that cancel each other out within a time window.
    """
    filtered_events = []
    i = 0

    events = sort_events_chronologically(events) if pre_sort else events

    while i < len(events):
        if i + 1 < len(events) and events[i].is_canceled_by(
            events[i + 1], time_threshold_seconds
        ):
            # Skip both events
            i += 2
        else:
            # Keep this event
            filtered_events.append(events[i])
            i += 1

    return filtered_events
