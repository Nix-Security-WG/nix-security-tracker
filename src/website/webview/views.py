import logging
import re
import typing
from collections.abc import Callable
from itertools import chain
from typing import Any, cast

from django.core.validators import RegexValidator
from django.db import transaction
from django.urls import reverse
from shared.github import create_gh_issue
from shared.listeners.cache_suggestions import maintainers_list
from shared.logs import SuggestionActivityLog
from shared.models.cached import CachedSuggestions

if typing.TYPE_CHECKING:
    # prevent typecheck from failing on some historic type
    # https://stackoverflow.com/questions/60271481/django-mypy-valuesqueryset-type-hint
    from django.db.models.query import ValuesQuerySet

from django.contrib.auth.decorators import login_required
from django.contrib.postgres.aggregates import ArrayAgg
from django.contrib.postgres.search import (
    SearchQuery,
    SearchRank,
)
from django.core.paginator import Page
from django.db.models import (
    Case,
    Count,
    F,
    Max,
    Q,
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
    HttpResponseRedirect,
)
from django.middleware.csrf import get_token
from django.shortcuts import get_object_or_404, redirect
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.views.generic import DetailView, ListView, TemplateView
from shared.auth import isadmin, ismaintainer
from shared.models import (
    AffectedProduct,
    Container,
    CveRecord,
    IssueStatus,
    NixChannel,
    NixDerivation,
    NixMaintainer,
    NixpkgsIssue,
)
from shared.models.linkage import CVEDerivationClusterProposal, MaintainersEdit
from webview.forms import NixpkgsIssueForm
from webview.paginators import CustomCountPaginator

logger = logging.getLogger(__name__)


class HomeView(TemplateView):
    template_name = "home_view.html"


@method_decorator(login_required, name="dispatch")
class TriageView(TemplateView):
    template_name = "triage_view.html"
    # Pagination parameters
    paginate_by = 10
    pages_on_each_side = 2
    pages_on_ends = 1

    def _cve_efficient_filter(self, search_cves: str) -> BaseManager[Container]:
        """
        To efficiently count is best to filter all relevant m2m related fields
        disregarding their order. Otherwise, the count and paginator will
        force grouping (which is costly in this case) twice.
        """

        container_from_description_matches = (
            Container.descriptions.through.objects.filter(
                description__search_vector=search_cves
            ).values("container_id")
        )
        affectedproduct_from_cpe_matches = AffectedProduct.cpes.through.objects.filter(
            cpe__search_vector=search_cves
        ).values("affectedproduct_id")
        affectedproduct_matches = AffectedProduct.objects.filter(
            search_vector=search_cves
        ).values("id")
        affectedproduct_from_own_and_cpe_matches = affectedproduct_matches.union(
            affectedproduct_from_cpe_matches
        )
        container_from_affectedproduct_matches = (
            Container.affected.through.objects.filter(
                affectedproduct_id__in=affectedproduct_from_own_and_cpe_matches
            ).values("container_id")
        )
        container_from_own_matches = Container.objects.filter(
            search_vector=search_cves
        ).values("id")
        filtered_containers = Container.objects.filter(
            id__in=container_from_own_matches.union(
                container_from_affectedproduct_matches,
                container_from_description_matches,
            )
        )
        return filtered_containers

    def _get_cve_qs(
        self, search_cves: str | None
    ) -> tuple["ValuesQuerySet[Container, dict[str, Any]]", Callable[[], int]]:
        if search_cves:
            search_query = SearchQuery(search_cves)
            # Check https://www.postgresql.org/docs/current/textsearch-controls.html#TEXTSEARCH-RANKING
            # for the meaning of normalization values.
            norm_value = Value(1)
            cve_qs = (
                Container.objects.prefetch_related(
                    "descriptions", "affected", "affected__cpes"
                )
                .filter(
                    Q(search_vector=search_cves)
                    | Q(descriptions__search_vector=search_cves)
                    | Q(affected__search_vector=search_cves)
                    | Q(affected__cpes__search_vector=search_cves)
                )
                .annotate(
                    rank_container=Case(
                        When(
                            Q(search_vector=search_cves),
                            then=SearchRank(
                                F("search_vector"),
                                search_query,
                                normalization=norm_value,
                            ),
                        ),
                        default=Value(0.0),
                    ),
                    rank_affected=Case(
                        When(
                            Q(affected__search_vector=search_cves),
                            then=SearchRank(
                                F("affected__search_vector"),
                                search_query,
                                normalization=norm_value,
                            ),
                        ),
                        default=Value(0.0),
                    ),
                    rank_cpes=Case(
                        When(
                            Q(affected__cpes__search_vector=search_cves),
                            then=SearchRank(
                                F("affected__cpes__search_vector"),
                                search_query,
                                normalization=norm_value,
                            ),
                        ),
                        default=Value(0.0),
                    ),
                    rank_descriptions=Case(
                        When(
                            Q(descriptions__search_vector=search_cves),
                            then=SearchRank(
                                F("descriptions__search_vector"),
                                search_query,
                                normalization=norm_value,
                            ),
                        ),
                        default=Value(0.0),
                    ),
                )
                .values("id")
                .annotate(
                    max_rank_container=Max("rank_container"),
                    max_rank_affected=Max("rank_affected"),
                    max_rank_cpes=Max("rank_cpes"),
                    max_rank_descriptions=Max("rank_descriptions"),
                    title=Max("title"),
                    cve_id=Max("cve__id"),
                    cve_id_code=Max("cve__cve_id"),
                    descriptions=ArrayAgg("descriptions__value"),
                    affected_product=Max("affected__product"),
                    affected_package_name=Max("affected__package_name"),
                    affected_repo=Max("affected__repo"),
                    affected_vendor=Max("affected__vendor"),
                    affected_cpes=ArrayAgg("affected__cpes__name"),
                )
                .order_by(
                    "-max_rank_container",
                    "-max_rank_affected",
                    "-max_rank_cpes",
                    "-max_rank_descriptions",
                    "id",
                )
            )

            cve_count_function = self._cve_efficient_filter(
                search_cves=search_cves
            ).count

            return cve_qs, cve_count_function
        else:
            cve_qs = (
                Container.objects.values("id")
                .annotate(
                    title=Max("title"),
                    cve_id=Max("cve__id"),
                    cve_id_code=Max("cve__cve_id"),
                    descriptions=ArrayAgg("descriptions__value"),
                    affected_product=Max("affected__product"),
                    affected_package_name=Max("affected__package_name"),
                    affected_repo=Max("affected__repo"),
                    affected_vendor=Max("affected__vendor"),
                    affected_cpes=ArrayAgg("affected__cpes__name"),
                )
                .order_by("-cve__cve_id")
            )

            cve_count_function = Container.objects.values("id").count

            return cve_qs, cve_count_function

    def _get_pkg_qs(
        self, search_pkgs: str | None
    ) -> tuple["ValuesQuerySet[NixDerivation, dict[str, Any]]", Callable[[], int]]:
        if search_pkgs:
            # Do a 2-rank search to prevent description contents from penalizing hits on "name" and "attribute"
            search_query = SearchQuery(search_pkgs)
            # Check https://www.postgresql.org/docs/current/textsearch-controls.html#TEXTSEARCH-RANKING
            # for the meaning of normalization values.
            norm_value = Value(1)
            pkg_qs = (
                NixDerivation.objects.prefetch_related("metadata")
                .filter(
                    Q(search_vector=search_pkgs)
                    | Q(metadata__search_vector=search_pkgs)
                )
                .annotate(
                    rank_pkg=Case(
                        When(
                            Q(search_vector=search_pkgs),
                            then=SearchRank(
                                F("search_vector"),
                                search_query,
                                normalization=norm_value,
                            ),
                        ),
                        default=Value(0.0),
                    ),
                    rank_description=Case(
                        When(
                            Q(metadata__search_vector=search_pkgs),
                            then=SearchRank(
                                F("metadata__search_vector"),
                                search_query,
                                normalization=norm_value,
                            ),
                        ),
                        default=Value(0.0),
                    ),
                )
                .values("name")
                .annotate(
                    pkg_count=Count("name"),
                    ids=ArrayAgg("id", ordering="id"),
                    attributes=ArrayAgg("attribute", ordering="id"),
                    description=Max("metadata__description"),
                    max_rank_pkg=Max("rank_pkg"),
                    max_rank_description=Max("rank_description"),
                )
                .order_by(
                    "-max_rank_pkg",
                    "-max_rank_description",
                    "name",
                )
            )

            # There's no need for a separate efficient query in the case of pkg aggregation
            # because the related field is a o2m instead of several m2m related fields.
            pkg_count_function = pkg_qs.count

            return pkg_qs, pkg_count_function
        else:
            pkg_qs = (
                NixDerivation.objects.values("name")
                .annotate(
                    pkg_count=Count("name"),
                    ids=ArrayAgg("id", ordering="id"),
                    attributes=ArrayAgg("attribute", ordering="id"),
                    description=Max("metadata__description"),
                )
                .order_by("name")
            )
            pkg_count_function = NixDerivation.objects.values("name").distinct().count

            return pkg_qs, pkg_count_function

    def _get_cve_page(
        self, search_cves: str | None, cve_page_number: int
    ) -> tuple[Page, CustomCountPaginator]:
        cve_qs, cve_count_function = self._get_cve_qs(search_cves)
        cve_paginator = CustomCountPaginator(
            cve_qs, self.paginate_by, custom_count=cve_count_function
        )
        cve_page = cve_paginator.get_page(cve_page_number)
        return cve_page, cve_paginator

    def _get_pkg_page(
        self, search_pkgs: str | None, pkg_page_number: int
    ) -> tuple[Page, CustomCountPaginator]:
        pkg_qs, pkg_count_function = self._get_pkg_qs(search_pkgs)
        pkg_paginator = CustomCountPaginator(
            pkg_qs, self.paginate_by, custom_count=pkg_count_function
        )
        pkg_page = pkg_paginator.get_page(pkg_page_number)
        return pkg_page, pkg_paginator

    def _map_cve_ids(self, cve_objects: str) -> list[int]:
        return [obj["cve_id"] for obj in cve_objects]  # type: ignore

    def _map_pkg_ids(self, pkg_objects: str) -> list[int]:
        return [_id for obj in pkg_objects for _id in obj["ids"]]  # type: ignore

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        # FIXME: we always search for both CVEs and packages simultaneously if both queries are provided,
        # even if one of them was already done and the query hasn't changed. this needs optimisation.
        context = super().get_context_data(**kwargs)

        search_cves = self.request.GET.get("search_cves")
        search_pkgs = self.request.GET.get("search_pkgs")
        cve_page_number = int(self.request.GET.get("cve_page", 1))
        pkg_page_number = int(self.request.GET.get("pkg_page", 1))

        cve_page, cve_paginator = self._get_cve_page(search_cves, cve_page_number)
        pkg_page, pkg_paginator = self._get_pkg_page(search_pkgs, pkg_page_number)

        context["cve_page"] = cve_page
        context["pkg_page"] = pkg_page

        context["cve_paginator_range"] = cve_paginator.get_elided_page_range(  # type: ignore
            cve_page_number,
            on_each_side=self.pages_on_each_side,
            on_ends=self.pages_on_ends,
        )
        context["pkg_paginator_range"] = pkg_paginator.get_elided_page_range(  # type: ignore
            pkg_page_number,
            on_each_side=self.pages_on_each_side,
            on_ends=self.pages_on_ends,
        )

        context["search_cves"] = search_cves
        context["search_pkgs"] = search_pkgs

        return context

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        context = self.get_context_data(**kwargs)

        # Init form
        context["form"] = NixpkgsIssueForm(
            cve_ids=self._map_cve_ids(context["cve_page"].object_list),  # type: ignore
            pkg_ids=self._map_pkg_ids(context["pkg_page"].object_list),  # type: ignore
        )

        return self.render_to_response(context)

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        context = self.get_context_data(**kwargs)

        # Fill form to validate
        context["form"] = NixpkgsIssueForm(
            self.request.POST,
            cve_ids=self._map_cve_ids(context["cve_page"].object_list),  # type: ignore
            pkg_ids=self._map_pkg_ids(context["pkg_page"].object_list),  # type: ignore
        )

        if context["form"].is_valid():
            context["form"].save()
            # Redirect to same page with an empty context
            return HttpResponseRedirect(self.request.path_info)

        # Render with form feedback
        return self.render_to_response(context)


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
        derivations = issue.derivations.all()  # type: ignore
        for drv in derivations:
            result = self.get_cves_for_derivation(drv)
            drv.known_cves = result

        issue.derivations_with_cves = derivations  # type: ignore

        return issue

    def get_cves_for_derivation(self, drv: Any) -> QuerySet | None:
        known_vulnerabilities = drv.metadata.known_vulnerabilities
        if not known_vulnerabilities:
            return None
        cves = [s for s in known_vulnerabilities if self.pattern.match(s)]
        existing_cves = Container.objects.filter(cve__cve_id__in=cves)
        return existing_cves or None


class NixpkgsIssueListView(ListView):
    template_name = "issue_list.html"
    model = NixpkgsIssue
    paginate_by = 10

    def get_queryset(self) -> BaseManager[NixpkgsIssue]:
        return NixpkgsIssue.objects.all()

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

        suggestion_ids = [obj.proposal_id for obj in context["object_list"]]

        grouped_activity_log = SuggestionActivityLog().get_dict(
            suggestion_ids=suggestion_ids
        )

        for obj in context["object_list"]:
            obj.activity_log = []
            if obj.proposal_id in grouped_activity_log:
                obj.activity_log = grouped_activity_log[obj.proposal_id]

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
        if not request.user or not (
            isadmin(request.user) or ismaintainer(request.user)
        ):
            return HttpResponseForbidden()

        # We want to provide graceful fallback for important workflows, when users have JavaScript disabled
        js_enabled: bool = "no-js" not in request.POST
        undo_status_change: bool = "undo-status-change" in request.POST
        suggestion_id = request.POST.get("suggestion_id")
        new_status = request.POST.get("new_status")
        current_page = request.POST.get("page", "1")
        suggestion = get_object_or_404(CVEDerivationClusterProposal, id=suggestion_id)
        activity_log = (
            SuggestionActivityLog()
            .get_dict(suggestion_ids=[suggestion.pk])
            .get(suggestion.pk, [])
        )
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
        if not (
            self.status_filter == CVEDerivationClusterProposal.Status.REJECTED
            or undo_status_change
        ):
            selected_derivations = [
                str.split(",") for str in request.POST.getlist("derivation_ids")
            ]
            selected_derivations = set(map(int, chain(*selected_derivations)))
            # We only allow for removal of derivations here, not for additions
            derivation_ids_to_keep = set(
                suggestion.derivations.filter(id__in=selected_derivations).values_list(
                    "id", flat=True
                )
            )
            suggestion.derivations.set(derivation_ids_to_keep)

            # TODO: this is quite slow and bad.
            # we are getting the JSON here and then sending it back.
            # a more optimal way to do it is to perform the raw SQL query directly on pgsql
            # something along the lines of:
            # UPDATE SET payload = payload -# {an list of indices to remove contained in this list} WHERE proposal_id = proposal_id
            # the problem is that computing the list of indices is pretty hard.
            # this seems to encourage to move the payload format to an dict of derivation id → derivation contents
            # this way, we already know which IDs to remove.
            # this is left as future work.
            new_packages = {
                pname: v
                for pname, v in cached_suggestion.payload["packages"].items()
                if any(did in selected_derivations for did in v["derivation_ids"])
            }
            cached_suggestion.payload["packages"] = new_packages
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
                snippet = render_to_string(
                    "components/suggestion.html",
                    suggestion_view_context(),
                )
                return HttpResponse(snippet)
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
        if not request.user or not (
            isadmin(request.user) or ismaintainer(request.user)
        ):
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

            return self.render_to_response(
                {
                    "maintainer": maintainer,
                    "deleted": deleted,
                }
            )
