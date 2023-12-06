from django.urls import path, re_path

from webview.views import HomeView, NixpkgsIssueView, NixpkgsIssueListView
from webview.feeds import AtomNixpkgsIssueFeed, RssNixpkgsIssueFeed  # type: ignore

app_name = "webview"


urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path("issues/", NixpkgsIssueListView.as_view(), name="issue_list"),
    re_path(
        r"^issues/(?P<code>NIXPKGS-[0-9]{4}-[0-9]{4,19})$",
        NixpkgsIssueView.as_view(),
        name="issue_detail",
    ),
    re_path(
        r"^issues/(?P<code>NIXPKGS-[0-9]{4}-[0-9]{4,19})/rss/$",
        RssNixpkgsIssueFeed(),
        name="issue_feed_rss",
    ),
    re_path(
        r"^issues/(?P<code>NIXPKGS-[0-9]{4}-[0-9]{4,19})/atom/$",
        AtomNixpkgsIssueFeed(),
        name="issue_feed_atom",
    ),
]
