from django.contrib.syndication.views import Feed
from django.urls import reverse
from django.utils.feedgenerator import Atom1Feed

from shared.models import NixpkgsIssue


class RssNixpkgsIssueFeed(Feed):
    description_template = "templates/issue_feed.html"

    def get_object(self, request, code):
        return NixpkgsIssue.objects.get(code=code)

    def title(self, obj):
        return "Issue %s" % obj.code

    def link(self, obj):
        # TODO: make the class compatible with get_absolute_url
        # return obj.get_absolute_url()
        return reverse("webview:issue_detail", args=[obj.code])

    def item_link(self, obj):
        return reverse("webview:issue_detail", args=[obj.code])

    def description(self, obj):
        return "Recent update for issue %s" % obj.code

    def items(self, obj):
        return NixpkgsIssue.objects.filter(code=obj.code).order_by("code")[:30]


class AtomNixpkgsIssueFeed(RssNixpkgsIssueFeed):
    feed_type = Atom1Feed
    subtitle = RssNixpkgsIssueFeed.description
