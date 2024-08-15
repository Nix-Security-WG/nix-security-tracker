import re
import typing
from collections.abc import Callable
from typing import Any

if typing.TYPE_CHECKING:
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
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.generic import DetailView, ListView, TemplateView
from shared.models import (
    AffectedProduct,
    Container,
    CveRecord,
    NixDerivation,
    NixpkgsIssue,
)

from webview.forms import NixpkgsIssueForm
from webview.paginators import CustomCountPaginator


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

    pattern = re.compile(CveRecord._meta.get_field("cve_id").validators[0].regex)

    def get_object(self, queryset: Any = None) -> Any:
        issue = get_object_or_404(self.model, code=self.kwargs.get("code"))
        derivations = issue.derivations.all()  # type: ignore
        for drv in derivations:
            result = self.get_cves_for_derivation(drv)
            drv.known_cves = result

        issue.derivations_with_cves = derivations  # type: ignore

        return issue

    def get_cves_for_derivation(self, drv: Any) -> Any:
        known_vulnerabilities = drv.metadata.known_vulnerabilities
        if not known_vulnerabilities:
            return None
        cves = [s for s in known_vulnerabilities if self.pattern.match(s)]
        existing_cves = Container.objects.filter(cve__cve_id__in=cves)
        if not existing_cves:
            return None
        else:
            return existing_cves


class NixpkgsIssueListView(ListView):
    template_name = "issue_list.html"
    model = NixpkgsIssue

    def get_queryset(self) -> BaseManager[NixpkgsIssue]:
        return NixpkgsIssue.objects.all()
