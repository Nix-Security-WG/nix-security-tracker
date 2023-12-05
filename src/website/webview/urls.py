from django.urls import path, re_path

from webview.views import HomeView, NixpkgsIssueView, NixpkgsIssueListView

app_name = "webview"


urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path("issues", NixpkgsIssueListView.as_view(), name="issue_list"),
    re_path(
        r"^issue/(?P<code>NIXPKGS-[0-9]{4}-[0-9]{4,19})$",
        NixpkgsIssueView.as_view(),
        name="issue_detail",
    ),
]
