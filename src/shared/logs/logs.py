from datetime import datetime
from typing import Any, Literal, cast

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
from webview.templatetags.viewutils import Maintainer


class ChangeEvent(BaseModel):
    """
    The common structure of a suggestion change event (except the `action`
    field, which is omitted here because of a Pydantic limitation: we want to
    make `action` more precise in the child classes using `Literal`, but
    Pydantic doesn't allow to override typed field dicts with more precise
    types).
    """

    suggestion_id: int
    timestamp: datetime
    # Might be "ANONYMOUS" in some special cases (deleted user for example) or
    # "ADMIN"
    username: str


class SuggestionChangeEvent(ChangeEvent):
    """
    A general change event for a suggestion.
    """

    action: Literal["insert", "update"]
    status_value: str


class PackageChangeEvent(ChangeEvent):
    """
    A package list change event for a suggestion.
    """

    action: Literal["package.add", "package.remove"]
    package_attribute: str
    # The following field is there to satisfy typechecking when collapsing
    # similar events together in get_dict. IMO this is a bit dirty as a
    # PackageChangeEvent is supposed to be singular.
    # TODO Find a better solution to distinguish singular package change events
    # and a constructed merged entry that combines several
    package_names: list[str] | None = None


class MaintainerChangeEvent(ChangeEvent):
    """
    A maintainer change event for a suggestion.
    """

    action: Literal["maintainers.add", "maintainers.remove"]
    maintainer: Maintainer


ConcreteChangeEvent = PackageChangeEvent | SuggestionChangeEvent | MaintainerChangeEvent


class SuggestionActivityLog:
    """
    This class provides a unified view for the activity log entries of a
    suggestion, convertible to a simple dict that can be used on the front-end.

    Under the hood, there are different types of log entries with different shapes:

    - insertion or status change
    - package edits (addition or removal)
    - maintainer edits (addition or removal)

    Those three correspond to different models in the base.
    SuggestionActivityLog provides facilities to aggregate those logs in one
    unified list of dicts.
    """

    def _annotate_username(self, query: EventQuerySet) -> EventQuerySet:
        return query.annotate(
            username=Coalesce(
                Case(
                    # An empty context means that the action took place
                    # from a management command executed by a superadmin.
                    When(Q(pgh_context__isnull=True), then=Value("ADMIN")),
                    # NOTE(alejandrosame): These operations shouldn't be anonymous,
                    # but leaving this case explicitly tagged as anonymous user to avoid
                    # confusion with DELETED users.
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
                # If user doesn't exist, we assume they were deleted
                # from the database at their request.
                Value("REDACTED"),
            )
        )

    def get_raw_events(
        self, suggestion_ids: list[int | None]
    ) -> list[ConcreteChangeEvent]:
        """
        Combine the different types of events related to a list of suggestions
        in a single list and order them by timestamp. Multiple log entries
        constituting one logical edit from the user aren't aggregated in this
        method. This is left to `get_dict`.
        """

        raw_events = []

        status_qs = self._annotate_username(
            CVEDerivationClusterProposalStatusEvent.objects.prefetch_related(
                "pgh_context",
            )
            .exclude(
                # Ignore insertion entry
                pgh_label="insert",
            )
            .filter(pgh_obj_id__in=suggestion_ids)
        )

        for status_event in status_qs.all().iterator():
            raw_events.append(
                SuggestionChangeEvent(
                    suggestion_id=status_event.pgh_obj_id,
                    timestamp=status_event.pgh_created_at,
                    username=status_event.username,
                    action=status_event.pgh_label,
                    status_value=status_event.status,
                )
            )

        package_edit_qs = self._annotate_username(
            PackageEditEvent.objects.filter(suggestion__in=suggestion_ids)
        )

        for package_edit_event in package_edit_qs.all().iterator():
            raw_events.append(
                PackageChangeEvent(
                    suggestion_id=package_edit_event.suggestion.id,
                    timestamp=package_edit_event.pgh_created_at,
                    username=package_edit_event.username,
                    action=package_edit_event.pgh_label,
                    package_attribute=package_edit_event.package_attribute,
                )
            )

        maintainer_qs = self._annotate_username(
            MaintainersEditEvent.objects.prefetch_related(
                "pgh_context", "maintainer"
            ).filter(suggestion__in=suggestion_ids)
        )

        for maintainer_event in maintainer_qs.all().iterator():
            raw_events.append(
                MaintainerChangeEvent(
                    suggestion_id=maintainer_event.suggestion.id,
                    timestamp=maintainer_event.pgh_created_at,
                    username=maintainer_event.username,
                    action=maintainer_event.pgh_label,
                    # TODO: we should use Pydantic model for maintainers and
                    # friends as well, at some point
                    maintainer=cast(
                        Maintainer, model_to_dict(maintainer_event.maintainer)
                    ),
                )
            )

        return sorted(raw_events, key=lambda event: event.timestamp)

    def _remove_canceling_events(
        self,
        events: list[ConcreteChangeEvent],
        time_threshold_seconds: int = 30,
    ) -> list[ConcreteChangeEvent]:
        """Remove consecutive events that cancel each other out within a time window."""

        filtered_events = []
        i = 0

        while i < len(events):
            if i + 1 < len(events) and self._events_cancel_each_other(
                events[i], events[i + 1], time_threshold_seconds
            ):
                # Skip both events
                i += 2
            else:
                # Keep this event
                filtered_events.append(events[i])
                i += 1

        return filtered_events

    def _events_cancel_each_other(
        self,
        event1: ConcreteChangeEvent,
        event2: ConcreteChangeEvent,
        time_threshold_seconds: int,
    ) -> bool:
        """Check if two consecutive events cancel each other."""
        # Same user, same suggestion, within time threshold
        if (
            event1.username != event2.username
            or event1.suggestion_id != event2.suggestion_id
            or (event2.timestamp - event1.timestamp).total_seconds()
            > time_threshold_seconds
        ):
            return False

        # Check for canceling pairs
        if isinstance(event1, MaintainerChangeEvent) and isinstance(
            event2, MaintainerChangeEvent
        ):
            return event1.maintainer["github_id"] == event2.maintainer[
                "github_id"
            ] and {event1.action, event2.action} == {
                "maintainers.add",
                "maintainers.remove",
            }

        if isinstance(event1, PackageChangeEvent) and isinstance(
            event2, PackageChangeEvent
        ):
            return event1.package_attribute == event2.package_attribute and {
                event1.action,
                event2.action,
            } == {"package.add", "package.remove"}

        return False

    def get_dict(
        self, suggestion_ids: list[int | None]
    ) -> dict[int, list[dict[str, Any]]]:
        """
        Aggregate the different types of events related to a given suggestion in
        a unified list of dicts, ordered by timestamp and with bulk actions
        grouped together.
        """

        raw_events = self.get_raw_events(suggestion_ids)

        # Cancellation pass - remove events that cancel each other within a given time window (5 min by default)
        filtered_events = self._remove_canceling_events(raw_events)

        grouped_activity_log: dict[
            int,
            list[ConcreteChangeEvent],
        ] = {}

        for event in filtered_events:
            suggestion_id = event.suggestion_id

            if suggestion_id in grouped_activity_log:
                grouped_activity_log[suggestion_id].append(event)
            else:
                grouped_activity_log[suggestion_id] = [event]

        # Second pass to fold repeated package actions by user,
        # needed because with htmx we're sending item-wise changes that we still want to display in bulk
        folded_activity_log: dict[int, list[dict[str, Any]]] = {}

        for suggestion_id, events in grouped_activity_log.items():
            suggestion_log: list[ConcreteChangeEvent] = []

            accumulator = None
            for event in events:
                # Bulk events that are subject to folding are currently
                # - package editions
                # - maintainers editions (soon to be logged) TODO
                if event.action.startswith("package") and isinstance(
                    event, PackageChangeEvent
                ):
                    if not accumulator:
                        # New batch
                        accumulator = event
                        accumulator.package_names = [event.package_attribute]
                    else:
                        if (
                            event.action == accumulator.action
                            and event.username == accumulator.username
                        ):
                            # Continuing batch
                            if accumulator.package_names is None:
                                # Should never happen
                                accumulator.package_names = [event.package_attribute]
                            else:
                                accumulator.package_names.append(
                                    event.package_attribute
                                )
                            # Keep latest timestamp
                            accumulator.timestamp = event.timestamp
                        else:
                            # Ending batch
                            suggestion_log.append(accumulator)
                            accumulator = event
                            accumulator.package_names = [event.package_attribute]
                else:
                    if accumulator:
                        suggestion_log.append(accumulator)
                        accumulator = None
                    suggestion_log.append(event)

            if accumulator:
                suggestion_log.append(accumulator)

            folded_activity_log[suggestion_id] = [
                event.model_dump() for event in suggestion_log
            ]

        return folded_activity_log
