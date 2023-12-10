from django.shortcuts import get_object_or_404
from django.views.generic import DetailView, ListView, TemplateView
from shared.models import NixpkgsIssue


class HomeView(TemplateView):
    template_name = "home_view.html"


class NixpkgsIssueView(DetailView):
    template_name = "issue_detail.html"
    model = NixpkgsIssue

    def get_object(self, queryset=None):
        return get_object_or_404(self.model, **{"code": self.kwargs.get("code")})


class NixpkgsIssueListView(ListView):
    template_name = "issue_list.html"
    model = NixpkgsIssue

    def get_queryset(self):
        return NixpkgsIssue.objects.all()
