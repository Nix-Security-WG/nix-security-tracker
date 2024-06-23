from django.urls import path, re_path

from webview.views import HomeView, NixpkgsIssueListView, NixpkgsIssueView, TriageView

app_name = "webview"


urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path("triage/", TriageView.as_view(), name="triage_view"),
    path("issues/", NixpkgsIssueListView.as_view(), name="issue_list"),
    re_path(
        r"^issues/(?P<code>NIXPKGS-[0-9]{4}-[0-9]{4,19})$",
        NixpkgsIssueView.as_view(),
        name="issue_detail",
    ),
]
