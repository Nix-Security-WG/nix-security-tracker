import logging
import re
import typing
from typing import Any, cast

from django.core.validators import RegexValidator
from django.db import transaction
from django.urls import reverse

from shared.github import create_gh_issue, fetch_user_info
from shared.listeners.cache_issues import CachedNixpkgsIssuePayload
from shared.listeners.cache_suggestions import apply_package_edits, maintainers_list
from shared.logs.batches import batch_events
from shared.logs.events import remove_canceling_events
from shared.logs.fetchers import fetch_suggestion_events
from shared.models.cached import CachedSuggestions

if typing.TYPE_CHECKING:
    # prevent typecheck from failing on some historic type
    # https://stackoverflow.com/questions/60271481/django-mypy-valuesqueryset-type-hint
    from django.db.models.query import ValuesQuerySet

from django.db.models import (
    Case,
    F,
    Value,
    When,
)
from django.db.models.manager import BaseManager
from django.db.models.query import QuerySet
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseForbidden,
    HttpResponseNotAllowed,
)
from django.middleware.csrf import get_token
from django.shortcuts import get_object_or_404, redirect
from django.template.loader import render_to_string
from django.views.generic import DetailView, ListView, TemplateView

from shared.auth import can_publish_github_issue
from shared.models import (
    CveRecord,
    IssueStatus,
    NixChannel,
    NixMaintainer,
    NixpkgsIssue,
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    MaintainersEdit,
    PackageEdit,
)

logger = logging.getLogger(__name__)


class HomeView(TemplateView):
    template_name = "home_view.html"


class NixpkgsIssueView(DetailView):
    template_name = "issue_detail.html"
    model = NixpkgsIssue

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        validator = CveRecord._meta.get_field("cve_id").validators[0]
        if isinstance(validator, RegexValidator):
            self.pattern = re.compile(validator.regex)
        else:
            raise TypeError("Expected RegexValidator for CveRecord.cve_id")

    def get_object(self, queryset: QuerySet | None = None) -> NixpkgsIssue:
        issue = cast(
            NixpkgsIssue, get_object_or_404(self.model, code=self.kwargs.get("code"))
        )
        issue.cached_payload = CachedNixpkgsIssuePayload(**issue.cached.payload)  # type: ignore
        return issue


class NixpkgsIssueListView(ListView):
    template_name = "issue_list.html"
    model = NixpkgsIssue
    paginate_by = 10

    # TODO Because of how issue codes and cached issues are generated (post save / post insert), it is not trivial to ensure new issues get their code filled up in the cached issue (unless `manage regenerate_cached_issues` is run by hand). Since the view needs the issue code, for now, the cached issue is passed as an additional field instead of being the returned object.
    def get_queryset(self) -> BaseManager[NixpkgsIssue]:
        issues = NixpkgsIssue.objects.all().order_by("-created")
        for issue in issues:
            issue.cached_payload = CachedNixpkgsIssuePayload(**issue.cached.payload)  # type: ignore
        return issues

    def get_context_data(self, **kwargs: Any) -> Any:
        context = super().get_context_data(**kwargs)
        context["adjusted_elided_page_range"] = context[
            "paginator"
        ].get_elided_page_range(context["page_obj"].number)
        return context


class NixderivationPerChannelView(ListView):
    template_name = "affected_list.html"
    context_object_name = "affected_list"
    paginate_by = 4

    def _get_ordered_channels(self) -> "ValuesQuerySet[NixChannel, Any]":
        custom_order = Case(
            When(state=NixChannel.ChannelState.STABLE, then=Value(1)),
            When(state=NixChannel.ChannelState.UNSTABLE, then=Value(2)),
            When(state=NixChannel.ChannelState.DEPRECATED, then=Value(3)),
            default=Value(4),
        )

        ordered_channels = (
            NixChannel.objects.alias(custom_order=custom_order)
            .filter(custom_order__lt=4)
            .order_by("custom_order", "channel_branch")
            .values_list("channel_branch", flat=True)
        )

        return ordered_channels

    def get_queryset(self) -> Any:
        channel_filter_value = self.kwargs["channel"]
        channel = get_object_or_404(NixChannel, channel_branch=channel_filter_value)

        return (
            NixpkgsIssue.objects.prefetch_related(
                "cve", "derivations", "derivations__parent_evaluation"
            )
            .values(issue_id=F("id"), issue_code=F("code"), issue_status=F("status"))
            .filter(issue_status=IssueStatus.AFFECTED)
            .annotate(
                cve_id=F("cve__id"),
                cve_code=F("cve__cve_id"),
                cve_state=F("cve__state"),
                drv_id=F("derivations__id"),
                drv_name=F("derivations__name"),
                drv_system=F("derivations__system"),
                drv_path=F("derivations__derivation_path"),
                channel_id=F("derivations__parent_evaluation__channel_id"),
            )
            .filter(channel_id=channel.channel_branch)
        )

    def get_context_data(self, **kwargs: Any) -> Any:
        context = super().get_context_data(**kwargs)
        context["channels"] = self._get_ordered_channels()
        context["current_channel"] = self.kwargs["channel"]
        context["adjusted_elided_page_range"] = context[
            "paginator"
        ].get_elided_page_range(context["page_obj"].number)

        context["headers"] = ["ID", "PLATFORM", "ISSUE", "CVE", "CVE STATE"]

        return context


class SuggestionListView(ListView):
    template_name = "suggestion_list.html"
    model = CachedSuggestions
    paginate_by = 10
    context_object_name = "objects"

    status_route_dict = {
        CVEDerivationClusterProposal.Status.PENDING.value: "/suggestions",
        CVEDerivationClusterProposal.Status.ACCEPTED.value: "/drafts",
        CVEDerivationClusterProposal.Status.REJECTED.value: "/dismissed",
        CVEDerivationClusterProposal.Status.PUBLISHED.value: "/issues",
    }

    # Determines how the list is filtered for and some control elements that
    # only are shown depending on the context.
    status_filter: CVEDerivationClusterProposal.Status = (
        CVEDerivationClusterProposal.Status.PENDING
    )

    def get_context_data(self, **kwargs: Any) -> Any:
        context = super().get_context_data(**kwargs)

        context["status_filter"] = self.status_filter

        for obj in context["object_list"]:
            raw_events = fetch_suggestion_events(obj.proposal_id)
            obj.activity_log = batch_events(
                remove_canceling_events(raw_events, sort=True)
            )

        context["adjusted_elided_page_range"] = context[
            "paginator"
        ].get_elided_page_range(context["page_obj"].number)
        return context

    def get_queryset(self) -> Any:
        queryset = (
            super()
            .get_queryset()
            # TODO: order by timestamp of last update/creation descending
            .filter(proposal__status=self.status_filter)
            .order_by("-proposal__updated_at", "-proposal__created_at")
        )
        return queryset

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.user or not can_publish_github_issue(request.user):
            return HttpResponseForbidden()

        # We want to provide graceful fallback for important workflows, when users have JavaScript disabled
        js_enabled: bool = "no-js" not in request.POST
        undo_status_change: bool = "undo-status-change" in request.POST
        suggestion_id = request.POST.get("suggestion_id")
        new_status = request.POST.get("new_status")
        current_page = request.POST.get("page", "1")
        suggestion = get_object_or_404(CVEDerivationClusterProposal, id=suggestion_id)

        # Activity log
        raw_events = fetch_suggestion_events(suggestion.pk)
        activity_log = batch_events(remove_canceling_events(raw_events, sort=True))

        cached_suggestion = get_object_or_404(
            CachedSuggestions, proposal_id=suggestion_id
        )
        status_change = new_status and suggestion.status != new_status
        # When clicking "Publish issue", we want to open a tab with the GitHub
        # issue in the response. We need to pass the issue's link to the
        # component, which is thus stored here (only when `status_change` is
        # true and `new_status = "published"`).
        gh_issue_link = None

        # Issue on the tracker that is defined after publishing
        tracker_issue = None

        def suggestion_view_context() -> dict:
            """
            Creates a proper context for the `suggestion` view. Since this is
            used at least in two different code paths, this is factored out in
            this function.
            """
            return {
                "cached_suggestion": cached_suggestion.payload,
                "suggestion": suggestion,
                "activity_log": activity_log,
                "status_filter": self.status_filter,
                "user": request.user,
                # This only matters in a non-JS environment
                "page_obj": None,
                "csrf_token": get_token(request),
            }

        # We only have to modify derivations when they are editable
        package_changes_made = False
        if not (
            self.status_filter == CVEDerivationClusterProposal.Status.REJECTED
            or undo_status_change
        ):
            # Handle package selection changes via PackageEdit tracking
            original_attributes = set(cached_suggestion.payload["original_packages"])
            selected_attributes = set(request.POST.getlist("attribute"))

            # Find packages that should be removed (no derivations selected)
            packages_to_remove = original_attributes - selected_attributes
            packages_to_restore = original_attributes & selected_attributes
            package_changes_made = bool(packages_to_remove or packages_to_restore)

            with transaction.atomic():
                # Apply removals
                for package_attr in packages_to_remove:
                    edit, created = suggestion.package_edits.get_or_create(
                        package_attribute=package_attr,
                        defaults={"edit_type": PackageEdit.EditType.REMOVE},
                    )
                    if not created and edit.edit_type != PackageEdit.EditType.REMOVE:
                        edit.edit_type = PackageEdit.EditType.REMOVE
                        edit.save()

                # Apply restorations (remove REMOVE edits)
                for package_attr in packages_to_restore:
                    suggestion.package_edits.filter(
                        package_attribute=package_attr,
                        edit_type=PackageEdit.EditType.REMOVE,
                    ).delete()

                # Update cached suggestion's package list
                cached_suggestion.payload["packages"] = apply_package_edits(
                    cached_suggestion.payload["original_packages"],
                    suggestion.package_edits.all(),
                )
                cached_suggestion.save()

        # We only update the status if one of the status change buttons or undo
        # button was clicked.
        # We handle the case of "published" separately: publication implies a
        # series of fallible actions that we want to handle in a properly
        # sequenced transaction.
        if status_change and new_status != "published":
            if new_status == "rejected":
                suggestion.status = CVEDerivationClusterProposal.Status.REJECTED
            elif new_status == "accepted":
                suggestion.status = CVEDerivationClusterProposal.Status.ACCEPTED
            # there's no UI for returning a suggestion back to pending state,
            # but this is an additional safeguard to prevent that from happening
            #                                vvvvvvvvvvvvvvvvvv
            elif new_status == "pending" and undo_status_change:
                suggestion.status = CVEDerivationClusterProposal.Status.PENDING

            suggestion.save()

        if status_change and new_status == "published":
            try:
                with transaction.atomic():
                    tracker_issue = suggestion.create_nixpkgs_issue()
                    tracker_issue_link = request.build_absolute_uri(
                        reverse("webview:issue_detail", args=[tracker_issue.code])
                    )
                    gh_issue_link = create_gh_issue(
                        cached_suggestion, tracker_issue_link
                    ).html_url
                    suggestion.status = CVEDerivationClusterProposal.Status.PUBLISHED
                    suggestion.save()
            except Exception as e:
                logger.error(f"Failed to publish issue: {e}")
                snippet = render_to_string(
                    "components/suggestion_state_error_wrapper.html",
                    {
                        "suggestion": suggestion_view_context(),
                        "suggestion_state_error": {
                            "suggestion_id": suggestion.pk,
                            "title": cached_suggestion.payload["title"],
                            "target_status": "published",
                        },
                    },
                )
                return HttpResponse(snippet)

        if js_enabled:
            # Clicking on the undo button will return the original suggestion
            # tile again, so that the page looks like before the action.
            if undo_status_change:
                # Fetch fresh activity log for undo status change
                raw_events = fetch_suggestion_events(suggestion.pk)
                fresh_activity_log = batch_events(
                    remove_canceling_events(raw_events, sort=True)
                )

                snippet = render_to_string(
                    "components/suggestion.html",
                    {
                        "cached_suggestion": cached_suggestion.payload,
                        "suggestion": suggestion,
                        "activity_log": fresh_activity_log,
                        "status_filter": self.status_filter,
                        "user": request.user,
                        # This only matters in a non-JS environment
                        "page_obj": None,
                        "csrf_token": get_token(request),
                    },
                )
                activity_log_oob_html = get_activity_log_oob_response(suggestion)
                return HttpResponse(snippet + activity_log_oob_html)
            elif status_change:
                if suggestion.status == "published":
                    if tracker_issue:
                        changed_suggestion_link = f"/issues/{tracker_issue.code}"
                    else:
                        changed_suggestion_link = "/issues"
                else:
                    changed_suggestion_link = f"{self.status_route_dict[suggestion.status]}#suggestion-{suggestion.pk}"
                snippet = render_to_string(
                    "components/suggestion_state_changed.html",
                    {
                        "suggestion_id": suggestion.pk,
                        "title": cached_suggestion.payload["title"],
                        "status": suggestion.status,
                        "old_status": self.status_filter,
                        "changed_suggestion_link": changed_suggestion_link,
                        "gh_issue_link": gh_issue_link,
                        "csrf_token": get_token(request),
                    },
                )
                return HttpResponse(snippet)
            else:
                # A package was checked/unchecked and we hx-swap="none" on these.
                if package_changes_made:
                    activity_log_oob_html = get_activity_log_oob_response(suggestion)
                    return HttpResponse(activity_log_oob_html)
                return HttpResponse(status=200)
        else:
            # Just reload the page
            return redirect(f"{request.path}?page={current_page}")


class SelectableMaintainerView(TemplateView):
    template_name = "components/selectable_maintainer.html"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # Only allow POST requests
        if request.method != "POST":
            return HttpResponseNotAllowed(["POST"])
        return super().dispatch(request, *args, **kwargs)

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.user or not can_publish_github_issue(request.user):
            return HttpResponseForbidden()

        suggestion_id = request.POST.get("suggestion_id")
        suggestion = get_object_or_404(CVEDerivationClusterProposal, id=suggestion_id)
        cached_suggestion = get_object_or_404(
            CachedSuggestions, proposal_id=suggestion_id
        )
        edit_maintainer_id = request.POST.get("edit_maintainer_id")
        # Which states allow for maintainer editing
        editable = (
            suggestion.status == CVEDerivationClusterProposal.Status.ACCEPTED
            or suggestion.status == CVEDerivationClusterProposal.Status.PENDING
        )

        if not editable:
            logger.error(
                f"Tried to edit maintainers on a suggestion whose status doesn't allow for maintainer edition (status: {suggestion.status})"
            )
            return HttpResponseForbidden()

        if not edit_maintainer_id:
            # Unprocessable Entity seems to be the more appropriate status code
            # for missing parameters (the request is well-formed at the protocol
            # level but some semantic precondition failed)
            logger.error("Missing edit_maintainer_id in request for maintainer edition")
            return HttpResponse(status=422)

        # When clicking the button to the left of a maintainer, there are two
        # cases:
        #
        # 1. The maintainer is currently in the list of maintainers: the button
        #    was a remove button, and we should remove the maintainer from the
        #    list.
        # 2. The maintainer is not in the list of maintainers: the button was
        #    an add button, and we should add the maintainer to the list.
        #
        # The button basically works as a toggle. Both cases have themselves two
        # sub-cases, depending on the existence of a prior edit:
        #
        # 1. Removal
        #    a) there was no prior edit, in which case we add a new "remove" edit
        #    b) there was a prior "add" edit, in which case we remove the "add" edit from the list (meaning
        #    the maintainer wasn't part of the list originally)
        # 2. Addition
        #    a) there was no prior edit, in which case we add a new "add" edit
        #    b) there was a prior "remove" edit (undo/add back case), in which case we remove the edit from the
        #    list
        #
        # Note that in both cases, if there was a prior edit, we always remove
        # it from the list (1b and 2b).
        #
        # Also note that for now add edits are unimplemented on the front-end
        # (but addition as undoing a removal is).
        with transaction.atomic():
            edit = suggestion.maintainers_edits.filter(
                maintainer__github_id=edit_maintainer_id
            )
            # case 1b and 2b
            if edit.exists():
                edit_object = edit.first()
                maintainer = edit_object.maintainer
                deleted = edit_object.edit_type == MaintainersEdit.EditType.ADD
                edit.delete()
                suggestion.save()
            # case 1a and 2a
            else:
                maintainer = get_object_or_404(
                    NixMaintainer, github_id=edit_maintainer_id
                )
                was_there = any(
                    str(m["github_id"]) == edit_maintainer_id
                    for m in cached_suggestion.payload["maintainers"]
                )
                edit_type = (
                    MaintainersEdit.EditType.REMOVE
                    if was_there
                    else MaintainersEdit.EditType.ADD
                )
                deleted = was_there
                edit = MaintainersEdit(
                    edit_type=edit_type,
                    maintainer=maintainer,
                    suggestion=suggestion,
                )
                edit.save()

            # Recompute the maintainer list for the cached suggestion
            cached_suggestion.payload["maintainers"] = maintainers_list(
                cached_suggestion.payload["packages"],
                suggestion.maintainers_edits.all(),
            )
            cached_suggestion.save()

            # Generate activity log OOB response for HTMX update
            activity_log_oob_html = get_activity_log_oob_response(suggestion)

            # Render the selectable maintainer component with activity log update
            maintainer_html = render_to_string(
                "components/selectable_maintainer.html",
                {
                    "maintainer": maintainer,
                    "deleted": deleted,
                },
            )

            return HttpResponse(maintainer_html + activity_log_oob_html)


class AddMaintainerView(TemplateView):
    template_name = "components/add_maintainer.html"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # Only allow POST requests
        if request.method != "POST":
            return HttpResponseNotAllowed(["POST"])
        return super().dispatch(request, *args, **kwargs)

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.user or not can_publish_github_issue(request.user):
            return HttpResponseForbidden()

        suggestion_id = request.POST.get("suggestion_id")
        suggestion = get_object_or_404(CVEDerivationClusterProposal, id=suggestion_id)
        cached_suggestion = get_object_or_404(
            CachedSuggestions, proposal_id=suggestion_id
        )
        new_maintainer_github_handle = request.POST.get("new_maintainer_github_handle")

        # Which states allow for maintainer editing
        editable = (
            suggestion.status == CVEDerivationClusterProposal.Status.ACCEPTED
            or suggestion.status == CVEDerivationClusterProposal.Status.PENDING
        )

        if not editable:
            logger.error(
                f"Tried to add maintainers on a suggestion whose status doesn't allow for maintainer edition (status: {suggestion.status})"
            )
            return HttpResponseForbidden()

        if not new_maintainer_github_handle:
            logger.error(
                "Missing new maintainer github handle in request for maintainer addition"
            )
            return self.render_to_response(
                {
                    "error_msg": "Missing GitHub handle for new maintainer",
                }
            )

        # Check if the maintainer is already part of the suggestion
        if any(
            str(m["github"]) == new_maintainer_github_handle
            for m in cached_suggestion.payload["maintainers"]
        ):
            return self.render_to_response(
                {
                    "error_msg": "Already a maintainer",
                }
            )

        maintainer = NixMaintainer.objects.filter(
            github=new_maintainer_github_handle
        ).first()

        if not maintainer:
            # Try to fetch maintainer info from GitHub API and create if found
            gh_user = fetch_user_info(new_maintainer_github_handle)
            if gh_user:
                maintainer, created = NixMaintainer.objects.update_or_create(
                    github_id=gh_user["id"],
                    defaults={
                        "github": gh_user["login"],
                        "name": gh_user.get("name"),
                        "email": gh_user.get("email"),
                    },
                )
            else:
                return self.render_to_response(
                    {
                        "error_msg": "Could not fetch maintainer from GitHub",
                    }
                )

        with transaction.atomic():
            edit = suggestion.maintainers_edits.filter(
                maintainer__github=new_maintainer_github_handle
            )
            if edit.exists():
                # NOTE We assume there is at most one edit for a given maintainer
                edit_object = edit.first()
                if edit_object.edit_type == MaintainersEdit.EditType.ADD:
                    # The maintainer is already an extra maintainer, we return an error message for the user.
                    return self.render_to_response(
                        {
                            "error_msg": "Already added as an extra maintainer",
                        }
                    )
                elif edit_object.edit_type == MaintainersEdit.EditType.REMOVE:
                    # NOTE An else would have sufficed but this is in case someday we have more than ADD and REMOVE edit types
                    edit.delete()
                    suggestion.save()
                else:
                    logger.error("Unexpected maintainer edit status")
                    return HttpResponse(status=422)
            else:
                edit = MaintainersEdit(
                    edit_type=MaintainersEdit.EditType.ADD,
                    maintainer=maintainer,
                    suggestion=suggestion,
                )
                edit.save()

            # Recompute the maintainer list for the cached suggestion
            maintainers = maintainers_list(
                cached_suggestion.payload["packages"],
                suggestion.maintainers_edits.all(),
            )
            cached_suggestion.payload["maintainers"] = maintainers
            cached_suggestion.save()

            maintainer_add_html = render_to_string("components/add_maintainer.html", {})
            maintainers_list_html = render_to_string(
                "components/maintainers_list.html",
                {
                    "maintainers": maintainers,
                    "selectable": True,
                    "suggestion_id": cached_suggestion.pk,
                    "oob_update": True,
                },
            )

            # Generate activity log OOB response for HTMX update
            activity_log_oob_html = get_activity_log_oob_response(suggestion)

            return HttpResponse(
                maintainers_list_html + maintainer_add_html + activity_log_oob_html
            )


def get_activity_log_oob_response(suggestion: CVEDerivationClusterProposal) -> str:
    """
    Generate HTMX out-of-band response for activity log updates.
    Returns HTML string with hx-swap-oob attribute for updating the activity log.
    """
    # Fetch and process activity log events
    raw_events = fetch_suggestion_events(suggestion.pk)
    activity_log = batch_events(remove_canceling_events(raw_events, sort=True))

    # Render the activity log component
    return render_to_string(
        "components/suggestion_activity_log.html",
        {
            "suggestion": suggestion,
            "activity_log": activity_log,
            "oob_update": True,
        },
    )
