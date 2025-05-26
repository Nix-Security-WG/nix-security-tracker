import logging
from typing import Any

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
from pghistory.models import EventQuerySet

from shared.models import (
    CVEDerivationClusterProposalStatusEvent,  # type: ignore
    DerivationClusterProposalLinkEvent,  # type: ignore
)

logger = logging.getLogger(__name__)


class SuggestionActivityLog:
    """
    This class provides a unified view for the activity log entires of a
    suggestion, convertible to a simple dict that can be used on the front-end.

    Under the hood, there are different types of log entries with shapes:

    - insertion or status change
    - package edits (addition or removal)
    - maintainer edits (addition or removal)

    Those three correspond to different models in the base.
    SuggestionActivityLog provides facilities to aggregate those logs in one
    unified list of dicts.

    The precise schema and example outputs are described in the documentation of
    the `get_dict` method.
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

    def get_raw_events(self, suggestion_ids: list[str | None]) -> list[dict[str, Any]]:
        """
        Combine the different types of events related to a list of suggestions
        in a single list and order them by timestamp. Multiple log entries
        constituting one logical edit from the user aren't aggregated in this
        method. This is left to `get_dict`.

        See `get_dict` for the schema of the output.
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
                {
                    "suggestion_id": status_event.pgh_obj_id,
                    "timestamp": status_event.pgh_created_at,
                    "username": status_event.username,
                    "action": status_event.pgh_label,
                    "status_value": status_event.status,
                }
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
                {
                    "suggestion_id": package_event.proposal_id,
                    "timestamp": package_event.pgh_created_at,
                    "username": package_event.username,
                    "action": package_event.pgh_label,
                    "package_names": package_event.package_names,
                    "package_count": package_event.package_count,
                }
            )

        return sorted(raw_events, key=lambda event: event["timestamp"])

    def get_dict(
        self, suggestion_ids: list[str | None]
    ) -> dict[str | None, dict[str, Any]]:
        """
        Aggregate the different types of events related to a given suggestion in
        a unified list of dicts, ordered by timestamp and with bulk actions
        grouped together.

        ## Example of dict output

        ```
        [{'action': 'derivations.remove',
          'package_count': 6,
          'package_names': ['{"name": "onnxruntime-1.15.1", "attribute": "onnxruntime"}',
                            '{"name": "python3.10-onnx-1.14.1", "attribute": "python310Packages.onnx"}',
                            '{"name": "python3.10-onnxconverter-common-1.14.0", "attribute": "python310Packages.onnxconverter-common"}',
                            '{"name": "python3.10-onnxmltools-1.11.2", "attribute": "python310Packages.onnxmltools"}',
                            '{"name": "python3.10-onnxruntime-1.15.1", "attribute": "python310Packages.onnxruntime"}',
                            '{"name": "python3.10-onnxruntime-tools-1.7.0", "attribute": "python310Packages.onnxruntime-tools"}'],
          'suggestion_id': 121,
          'timestamp': datetime.datetime(2024, 12, 6, 11, 59, 6, 668316, tzinfo=datetime.timezone.utc),
          'username': 'ANONYMOUS'},
         {'action': 'derivations.remove',
          'package_count': 1,
          'package_names': ['{"name": "perl5.36.3-GSSAPI-0.28", "attribute": "perl536Packages.GSSAPI"}'],
          'suggestion_id': 11,
          'timestamp': datetime.datetime(2024, 12, 5, 16, 15, 7, 899037, tzinfo=datetime.timezone.utc),
          'username': 'ANONYMOUS'},
         {'action': 'update',
          'status_value': 'accepted',
          'suggestion_id': 11,
          'timestamp': datetime.datetime(2024, 12, 5, 16, 14, 19, 520312, tzinfo=datetime.timezone.utc),
          'username': 'ANONYMOUS'}]
        ```

        ## Schema

        Here is the schema of the dict returned by this method.

        All events have the following fields defined:

        ```
        suggestion_id: int
        timestamp: datetime
        action: str
        username: str
        ```

        If `action` is `insert` or `update`, the dict will have the additional
        fields:

        ```
        status_value: str
        ```

        If `action` is `derivations.*`, the dict will have the additional
        fields:

        ```
        package_names: list[dict[str, str]] # a package name is {"name": str, "attribute": str}
        package_count: int
        ```

        TODO: add maintainer edits to the schema once they're logged.
        """

        raw_events = self.get_raw_events(suggestion_ids)

        grouped_activity_log = {}

        for event in raw_events:
            suggestion_id = event.get("suggestion_id")

            if suggestion_id in grouped_activity_log:
                grouped_activity_log[suggestion_id].append(event)
            else:
                grouped_activity_log[suggestion_id] = [event]

        # Second pass to fold repeated package actions by user,
        # needed because with htmx we're sending item-wise changes that we still want to display in bulk
        folded_activity_log = {}
        for suggestion_id, events in grouped_activity_log.items():
            suggestion_log = []

            accumulator = None
            for event in events:
                # Bulk events that are subject to folding are currently
                # - package editions
                # - maintainers editions (soon to be logged)
                if event["action"].startswith("derivations"):
                    if not accumulator:
                        accumulator = event
                    else:
                        if (
                            event["action"] == accumulator["action"]
                            and event["username"] == accumulator["username"]
                        ):
                            # For now, this is the only remaining possibility,
                            # but we'll add maintainer edits soon.
                            if event["action"].startswith("derivations"):
                                accumulator["package_names"] = (
                                    accumulator["package_names"]
                                    + event["package_names"]
                                )
                                accumulator["package_count"] = (
                                    accumulator["package_count"]
                                    + event["package_count"]
                                )

                            accumulator["timestamp"] = event[
                                "timestamp"
                            ]  # Keep latest timestamp
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

            folded_activity_log[suggestion_id] = suggestion_log

        return folded_activity_log
