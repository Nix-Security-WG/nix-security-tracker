import re
from typing import Any

from django import forms
from django.db.models.manager import BaseManager
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.generic import DetailView, ListView
from shared.models import (
    Container,
    CveRecord,
    NixDerivation,
    NixDerivationMeta,
    NixpkgsIssue,
)


class HomeView(ListView):
    template_name = "home_view.html"

    def get_queryset(self) -> BaseManager[NixDerivationMeta]:
        return NixDerivationMeta.objects.all()


class NixDerivationsView(DetailView):
    template_name = "derivation_detail.html"
    model = NixDerivation

    def get_object(self, queryset: Any = None) -> Any:
        meta = get_object_or_404(self.model, id=self.kwargs.get("id"))
        return meta


class SelectForm(forms.Form):
    code = forms.CharField()
    link = forms.CharField()


class LinkIssuesView(DetailView):
    template_name = "link_issues_detail.html"
    model = NixDerivation

    def get_object(self, queryset: Any = None) -> Any:
        drv = get_object_or_404(self.model, id=self.kwargs.get("id"))
        drv.all_issues = NixpkgsIssue.objects.all()  # type: ignore
        return drv

    def post(self, request: Any, id: Any) -> Any:  # type: ignore
        form = SelectForm(request.POST)
        if form.is_valid():
            val = form.cleaned_data.get("link")
            code = form.cleaned_data.get("code")
            print(val)
            drv = get_object_or_404(self.model, id=id)
            issue = get_object_or_404(NixpkgsIssue, code=code)
            if val == "link":
                issue.derivations.add(drv)
            else:
                issue.derivations.remove(drv)

        response = redirect(reverse("webview:link_issues_detail", kwargs={"id": id}))
        response.status_code = 302
        return response


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
