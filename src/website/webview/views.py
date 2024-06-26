import re
from typing import Any

from django.contrib.postgres.search import SearchVector
from django.core.paginator import Paginator
from django.db.models import Q
from django.db.models.manager import BaseManager
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, render
from django.views.generic import DetailView, ListView, TemplateView
from shared.models import (
    Container,
    CveRecord,
    LinkageCandidate,
    NixDerivation,
    NixpkgsIssue,
)


class HomeView(TemplateView):
    template_name = "home_view.html"


def triage_candidate_view(request: HttpRequest) -> HttpResponse:
    """
    Return the triage view of a candidate record linkage.

    In this view logic we are only interested in showing
    CVEs and packages specified by candidate records.
    """
    template_name = "triage_candidate_view.html"

    next_candidates = LinkageCandidate.objects.values_list(
        "derivation_id", flat=True
    ).distinct()[:2]
    print(next_candidates)
    if len(next_candidates) == 0:
        context = {
            "cve_list": None,
            "pkg": None,
            "next_pkg_id": None,
        }
        return render(request, template_name, context)

    print(next_candidates[0])
    print(dir(next_candidates[0]))

    candidates = (
        LinkageCandidate.objects.prefetch_related("container", "derivation")
        .filter(derivation_id=next_candidates[0])
        .values_list("container_id", flat=True)
    )

    cve_objects = (
        Container.objects.prefetch_related("descriptions", "affected", "cve")
        .filter(id__in=candidates)
        .order_by("id", "-date_public")
        .all()
    )
    pkg = NixDerivation.objects.prefetch_related("metadata").get(id=next_candidates[0])
    print(pkg)

    context = {
        "cve_list": cve_objects,
        "pkg": pkg,
        "next_pkg_id": None if len(next_candidates) == 1 else next_candidates[1],
    }

    return render(request, template_name, context)


def triage_view(request: HttpRequest) -> HttpResponse:
    template_name = "triage_view.html"
    paginate_by = 25

    cve_qs = (
        Container.objects.prefetch_related("descriptions", "affected", "cve")
        .exclude(title="")
        .order_by("id", "-date_public")
    )
    pkg_qs = NixDerivation.objects.prefetch_related("metadata").order_by("id")
    cve_objects = cve_qs.all()
    pkg_objects = pkg_qs.all()

    # Fetch query parameters
    search_cves = request.GET.get("search_cves")
    search_pkgs = request.GET.get("search_pkgs")

    if search_cves:
        cve_objects = cve_qs.filter(
            Q(search_vector=search_cves)
            | Q(descriptions__search_vector=search_cves)
            | Q(affected__search_vector=search_cves)
            | Q(affected__cpes__search_vector=search_cves)
        ).distinct("id")

    if search_pkgs:
        pkg_objects = (
            pkg_qs.annotate(
                search=SearchVector(
                    "attribute",
                    "name",
                    "system",
                    "metadata__name",
                    "metadata__description",
                )
            )
            .filter(search=search_pkgs)
            .distinct("id")
        )

    # Paginators
    cve_paginator = Paginator(cve_objects, paginate_by)
    cve_page_number = 1  # request.GET.get('page_cves', 1)
    cve_page_objects = cve_paginator.get_page(cve_page_number)

    pkg_paginator = Paginator(pkg_objects, paginate_by)
    pkg_page_number = 1  # request.GET.get('page_pkgs', 1)
    pkg_page_objects = pkg_paginator.get_page(pkg_page_number)

    context = {
        "cve_list": cve_page_objects,
        "pkg_list": pkg_page_objects,
        "search_cves": search_cves,
        "search_pkgs": search_pkgs,
    }

    return render(request, template_name, context)


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
