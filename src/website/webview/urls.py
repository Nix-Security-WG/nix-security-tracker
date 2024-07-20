from django.urls import path, re_path
from shared.auth.github_webhook import handle_github_hook

from webview.views import HomeView, NixpkgsIssueListView, NixpkgsIssueView

app_name = "webview"


urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path("issues/", NixpkgsIssueListView.as_view(), name="issue_list"),
    re_path(
        r"^issues/(?P<code>NIXPKGS-[0-9]{4}-[0-9]{4,19})$",
        NixpkgsIssueView.as_view(),
        name="issue_detail",
    ),
    path("github-webhook/", handle_github_hook, name="github_webhook"),
]
