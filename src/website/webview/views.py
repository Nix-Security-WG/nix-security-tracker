import re
from typing import Any

from django.db.models.manager import BaseManager
from django.shortcuts import get_object_or_404
from django.views.generic import DetailView, ListView, TemplateView
from shared.models import Container, CveRecord, NixpkgsIssue
from django.contrib.postgres.search import SearchVector


class HomeView(TemplateView):
    template_name = "home_view.html"


class TriageView(ListView):
    template_name = "triage_view.html"
    model = Container
    paginate_by = 25

    def get_queryset(self):
        qs = (
            Container.objects.prefetch_related("descriptions", "affected", "cve")
            .exclude(title="")
            .order_by("id", "-date_public")
        )
        search_query = self.request.GET.get("search_query")
        if not search_query:
            return qs.all()
        else:
            return (
                qs.annotate(
                    search=SearchVector(
                        "title",
                        "descriptions__value",
                        "affected__vendor",
                        "affected__product",
                        "affected__package_name",
                        "affected__repo",
                        "affected__cpes__name",
                    )
                )
                .filter(search=search_query)
                .distinct("id")
            )


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
