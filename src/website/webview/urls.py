from django.urls import path, re_path

from webview.views import (
    HomeView,
    LinkIssuesView,
    NixDerivationsView,
    NixpkgsIssueListView,
    NixpkgsIssueView,
)

app_name = "webview"


urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path("issues/", NixpkgsIssueListView.as_view(), name="issue_list"),
    re_path(
        r"^issues/(?P<code>NIXPKGS-[0-9]{4}-[0-9]{4,19})$",
        NixpkgsIssueView.as_view(),
        name="issue_detail",
    ),
    path("derivations/<id>", NixDerivationsView.as_view(), name="derivation_detail"),
    path("link-issues/<id>", LinkIssuesView.as_view(), name="link_issues_detail"),
]
