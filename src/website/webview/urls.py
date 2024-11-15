from django.urls import path, re_path
from django.views.generic.base import RedirectView
from shared.auth.github_webhook import handle_github_hook

from webview.views import (
    DismissedListView,
    DraftListView,
    HomeView,
    NixderivationPerChannelView,
    NixpkgsIssueListView,
    NixpkgsIssueView,
    SuggestionListView,
    TriageView,
)

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
    path("github-webhook/", handle_github_hook, name="github_webhook"),
    re_path(
        "^affected/(?P<channel>(nixos|nixpkgs)-.*)$",
        NixderivationPerChannelView.as_view(),
        name="affected_list_per_channel",
    ),
    # TODO: We may want to put an overview page here
    path(
        "affected/",
        RedirectView.as_view(url="nixos-unstable", permanent=True),
        name="affected_list",
    ),
    # TODO: clean up the file names
    # TODO: this should probably be something like
    #       suggestions/queue
    #       suggestions/dismissed
    #       suggestions/selected
    path("suggestions/", SuggestionListView.as_view(), name="suggestions_view"),
    path("dismissed/", DismissedListView.as_view(), name="dismissed_view"),
    path("selected/", DraftListView.as_view(), name="selected_view"),
]
