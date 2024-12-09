import datetime
import typing
from typing import Any, TypedDict

from django.contrib.auth.models import User
from django.contrib.postgres.aggregates import ArrayAgg
from django.db.models import (
    BigIntegerField,
    Case,
    Count,
    F,
    OuterRef,
    Q,
    Subquery,
    Value,
    When,
)
from django.db.models.functions import Cast, Coalesce
from pghistory.models import EventQuerySet

from shared.models import (
    CVEDerivationClusterProposalStatusEvent,  # type: ignore
    DerivationClusterProposalLinkEvent,  # type: ignore
)

if typing.TYPE_CHECKING:
    from django.db.models.query import ValuesQuerySet


class ActivityLogEntry(TypedDict):
    action: str
    package_count: int
    package_name: list[str]
    status_value: str
    suggestion_id: str | None
    timestamp: datetime.datetime
    username: str


class SuggestionActivityLog:
    """
    Example of queryset output:
    ```
    [{'action': 'derivations.remove',
      'package_count': 7,
      'package_names': ['apparmor-kernel-patches-3.1.6',
                        'kernelshark-2.2.1',
                        'linux-gpib-kernel-4.3.6',
                        'linux-kernel-latest-htmldocs-6.9.3',
                        'zfs-kernel-2.1.15-6.1.92',
                        'zfs-kernel-2.2.4-6.1.92',
                        'zfs-kernel-2.2.4-6.8.11'],
      'status_value': 'NOT_A_STATUS_CHANGE',
      'suggestion_id': 121,
      'timestamp': datetime.datetime(2024, 12, 6, 11, 59, 6, 668316, tzinfo=datetime.timezone.utc),
      'username': 'ANONYMOUS'},
     {'action': 'derivations.remove',
      'package_count': 1,
      'package_names': ['SPIRV-LLVM-Translator-16.0.0'],
      'status_value': 'NOT_A_STATUS_CHANGE',
      'suggestion_id': 11,
      'timestamp': datetime.datetime(2024, 12, 5, 16, 15, 7, 899037, tzinfo=datetime.timezone.utc),
      'username': 'ANONYMOUS'},
     {'action': 'update',
      'package_count': 0,
      'package_names': [],
      'status_value': 'accepted',
      'suggestion_id': 11,
      'timestamp': datetime.datetime(2024, 12, 5, 16, 14, 19, 520312, tzinfo=datetime.timezone.utc),
      'username': 'ANONYMOUS'}]
    ```
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

    def get_queryset(
        self, suggestion_ids: list[str | None]
    ) -> "ValuesQuerySet[Any, dict[str, Any]]":
        fields = [
            "suggestion_id",
            "timestamp",
            "username",
            "action",
            "status_value",
            "package_names",
            "package_count",
        ]

        status_qs = (
            self._annotate_username(
                CVEDerivationClusterProposalStatusEvent.objects.prefetch_related(
                    "pgh_context",
                )
                .exclude(
                    # Ignore insertion entry
                    pgh_label="insert",
                )
                .filter(pgh_obj_id__in=suggestion_ids)
            )
            .annotate(
                suggestion_id=Cast(F("pgh_obj_id"), BigIntegerField()),
                timestamp=F("pgh_created_at"),
                action=F("pgh_label"),
                status_value=F("status"),
                package_names=Value("{}"),
                package_count=Value(0),
            )
            .values(*fields)
        )

        package_qs = (
            self._annotate_username(
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
                .annotate(dummy_group_by_value=Value(1))
                .values("dummy_group_by_value")
                # NOTE(alejandrosame): Doing annotate "dummy_group_by_value" is a hack shared in
                # the Django forum. Another user there complains about Django's decision to add the
                # primary key by default when doing automated groupings. We hit here the same problem.
                # Reference: https://forum.djangoproject.com/t/excess-group-by-columns-causing-problems-with-window-functions/26865/1
            )
            .annotate(
                suggestion_id=Cast(F("proposal_id"), BigIntegerField()),
                timestamp=F("pgh_created_at"),
                action=F("pgh_label"),
                status_value=Value("NOT_A_STATUS_CHANGE"),
                package_names=ArrayAgg("derivation__name", distinct=True),
                package_count=Count("derivation__name", distinct=True),
            )
            .values(*fields)
        )

        return status_qs.union(package_qs).order_by("timestamp")

    def get_dict(
        self, suggestion_ids: list[str | None]
    ) -> dict[str | None, ActivityLogEntry]:
        qs = self.get_queryset(suggestion_ids)

        grouped_activity_log = {}

        for event in qs.all().iterator():
            suggestion_id = event.get("suggestion_id")

            if suggestion_id in grouped_activity_log:
                grouped_activity_log[suggestion_id].append(event)
            else:
                grouped_activity_log[suggestion_id] = [event]

        # Second pass to fold repeated package actions by user
        folded_activity_log = {}
        for suggestion_id, events in grouped_activity_log.items():
            suggestion_log = []

            accumulator = None
            for event in events:
                if not event["action"].startswith("derivations."):
                    if accumulator:
                        suggestion_log.append(accumulator)
                        accumulator = None
                    suggestion_log.append(event)
                else:
                    if not accumulator:
                        accumulator = event
                    else:
                        if (
                            event["action"] == accumulator["action"]
                            and event["username"] == accumulator["username"]
                        ):
                            accumulator["package_names"] = (
                                accumulator["package_names"] + event["package_names"]
                            )
                            accumulator["package_count"] = (
                                accumulator["package_count"] + event["package_count"]
                            )
                            accumulator["timestamp"] = event[
                                "timestamp"
                            ]  # Keep latest timestamp
                        else:
                            suggestion_log.append(accumulator)
                            accumulator = event

            if accumulator:
                suggestion_log.append(accumulator)

            folded_activity_log[suggestion_id] = suggestion_log

        return folded_activity_log
