from django.urls import include, path, re_path
from django.views.generic.base import RedirectView

from shared.auth.github_webhook import handle_github_hook
from shared.models.linkage import (
    CVEDerivationClusterProposal,
)
from webview.views import (
    AddMaintainerView,
    HomeView,
    NixderivationPerChannelView,
    NixpkgsIssueListView,
    NixpkgsIssueView,
    SelectableMaintainerView,
    SuggestionListView,
)

app_name = "webview"


urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path("notifications/", include("webview.notifications.urls")),
    path("subscriptions/", include("webview.subscriptions.urls")),
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
    #       suggestions/drafts
    path(
        "suggestions/",
        SuggestionListView.as_view(
            status_filter=CVEDerivationClusterProposal.Status.PENDING
        ),
        name="suggestions_view",
    ),
    # This is a POST endpoint only, handling maintainers edit requests.
    path(
        "edit_maintainers/",
        SelectableMaintainerView.as_view(),
        name="edit_maintainers",
    ),
    path(
        "add_maintainer/",
        AddMaintainerView.as_view(),
        name="add_maintainer",
    ),
    path(
        "dismissed/",
        SuggestionListView.as_view(
            status_filter=CVEDerivationClusterProposal.Status.REJECTED
        ),
        name="dismissed_view",
    ),
    path(
        "drafts/",
        SuggestionListView.as_view(
            status_filter=CVEDerivationClusterProposal.Status.ACCEPTED
        ),
        name="drafts_view",
    ),
]
