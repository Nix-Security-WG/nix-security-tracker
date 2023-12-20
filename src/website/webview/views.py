import re
from typing import Any

from django.db.models import F
from django.db.models.manager import BaseManager
from django.shortcuts import get_object_or_404
from django.views.generic import DetailView, ListView, TemplateView
from shared.models import Container, CveRecord, IssueStatus, NixChannel, NixpkgsIssue


class HomeView(TemplateView):
    template_name = "home_view.html"


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


class NixderivationPerChannelView(ListView):
    template_name = "affected_list.html"
    context_object_name = "affected_list"
    paginate_by = 4

    def get_queryset(self) -> Any:
        channel_filter_value = self.kwargs["channel"]
        channel = get_object_or_404(NixChannel, channel_branch=channel_filter_value)

        return (
            NixpkgsIssue.objects.values(
                issue_id=F("id"), issue_code=F("code"), issue_status=F("status")
            )
            .filter(issue_status=IssueStatus.AFFECTED)
            .annotate(
                cve_id=F("cve__id"),
                cve_code=F("cve__cve_id"),
                cve_state=F("cve__state"),
                drv_id=F("derivations__id"),
                drv_name=F("derivations__name"),
                drv_system=F("derivations__system__system_double"),
                drv_path=F("derivations__derivation_path"),
                channel_id=F("derivations__parent_evaluation__channel_id"),
            )
            .filter(channel_id=channel.channel_branch)
        )

    def get_context_data(self, **kwargs: Any) -> Any:
        context = super().get_context_data(**kwargs)
        context["channels"] = ["NIXOS-UNSTABLE", "NIXOS-23.11", "NIXOS-23.05"]
        context["current_channel"] = self.kwargs["channel"].upper()
        context["adjusted_elided_page_range"] = context[
            "paginator"
        ].get_elided_page_range(context["page_obj"].number)

        context["headers"] = ["ID", "PLATFORM", "ISSUE", "CVE", "CVE STATE"]

        return context
