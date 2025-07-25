from datetime import datetime
from typing import Any, Literal, cast

from django.contrib.auth.models import User
from django.contrib.postgres.aggregates import ArrayAgg
from django.db.models import (
    BigIntegerField,
    Case,
    Count,
    OuterRef,
    Q,
    Subquery,
    Value,
    When,
)
from django.db.models.functions import Cast, Coalesce, Concat, JSONObject, Replace
from django.forms.models import model_to_dict
from pghistory.models import EventQuerySet
from pydantic import BaseModel

from shared.models import (
    CVEDerivationClusterProposalStatusEvent,  # type: ignore
    DerivationClusterProposalLinkEvent,  # type: ignore
    MaintainersEditEvent,  # type: ignore
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


class PackageData(BaseModel):
    """
    A package in a package change event.
    """

    name: str
    attribute: str


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

    action: Literal["derivations.add", "derivations.remove"]
    package_count: int
    package_names: list[PackageData]


class MaintainerChangeEvent(ChangeEvent):
    """
    A maintainer change event for a suggestion.
    """

    action: Literal["maintainers.add", "maintainers.remove"]
    maintainer: Maintainer


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
    ) -> list[PackageChangeEvent | SuggestionChangeEvent]:
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

        package_qs = self._annotate_username(
            DerivationClusterProposalLinkEvent.objects.prefetch_related(
                "pgh_context", "derivation"
            )
            .exclude(
                # Ignore insertion entry
                pgh_created_at=Subquery(
                    DerivationClusterProposalLinkEvent.objects.filter(
                        proposal_id=OuterRef("proposal_id")
                    )
                    .order_by("pgh_created_at")
                    .values("pgh_created_at")[:1]
                )
            )
            .filter(proposal_id__in=suggestion_ids)
        ).annotate(
            package_names=ArrayAgg(
                JSONObject(
                    name="derivation__name",
                    attribute=Replace(
                        "derivation__attribute",  # type: ignore
                        Concat(Value("."), "derivation__system"),  # type: ignore
                        Value(""),
                    ),
                ),
                distinct=True,
            ),
            package_count=Count("derivation__name", distinct=True),
        )

        for package_event in package_qs.all().iterator():
            raw_events.append(
                PackageChangeEvent(
                    suggestion_id=package_event.proposal_id,
                    timestamp=package_event.pgh_created_at,
                    username=package_event.username,
                    action=package_event.pgh_label,
                    package_names=package_event.package_names,
                    package_count=package_event.package_count,
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

    def get_dict(
        self, suggestion_ids: list[int | None]
    ) -> dict[int, list[dict[str, Any]]]:
        """
        Aggregate the different types of events related to a given suggestion in
        a unified list of dicts, ordered by timestamp and with bulk actions
        grouped together.
        """

        raw_events = self.get_raw_events(suggestion_ids)

        grouped_activity_log: dict[
            int, list[PackageChangeEvent | SuggestionChangeEvent]
        ] = {}

        for event in raw_events:
            suggestion_id = event.suggestion_id

            if suggestion_id in grouped_activity_log:
                grouped_activity_log[suggestion_id].append(event)
            else:
                grouped_activity_log[suggestion_id] = [event]

        # Second pass to fold repeated package actions by user,
        # needed because with htmx we're sending item-wise changes that we still want to display in bulk
        folded_activity_log: dict[int, list[dict[str, Any]]] = {}

        for suggestion_id, events in grouped_activity_log.items():
            suggestion_log: list[PackageChangeEvent | SuggestionChangeEvent] = []

            accumulator = None
            for event in events:
                # Bulk events that are subject to folding are currently
                # - package editions
                # - maintainers editions (soon to be logged)
                if event.action.startswith("derivations"):
                    if not accumulator:
                        accumulator = event
                    else:
                        if (
                            event.action == accumulator.action
                            and event.username == accumulator.username
                        ):
                            # For now, this is the only remaining possibility,
                            # but we'll add maintainer edits soon.
                            if event.action.startswith("derivations"):
                                accumulator.package_names = (
                                    accumulator.package_names + event.package_names
                                )
                                accumulator.package_count = (
                                    accumulator.package_count + event.package_count
                                )
                            # Keep latest timestamp
                            accumulator.timestamp = event.timestamp
                        else:
                            suggestion_log.append(accumulator)
                            accumulator = event
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
