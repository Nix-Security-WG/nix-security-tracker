import logging
from urllib.parse import quote

from django.conf import settings
from github import Auth, Github
from github.Issue import Issue as GithubIssue
from webview.templatetags.viewutils import severity_badge

from shared.models import CachedSuggestions

logger = logging.getLogger(__name__)


def get_gh(per_page: int = 30) -> Github:
    """
    Initialize a GitHub API connection
    """

    gh_auth = Auth.AppAuth(
        settings.GH_CLIENT_ID, settings.GH_APP_PRIVATE_KEY
    ).get_installation_auth(settings.GH_APP_INSTALLATION_ID)
    logger.info("Successfully authenticated with GitHub.")

    return Github(auth=gh_auth, per_page=per_page)


def create_gh_issue(
    cached_suggestion: CachedSuggestions,
    tracker_issue_uri: str,
    github: Github = get_gh(),
) -> GithubIssue:
    """
    Creates a GitHub issue for the given suggestion on the Nixpkgs repository,
    given a link to the corresponding NixpkgsIssue on the tracker side.

    The tracker issue URI could be derived automatically from NixpkgsIssue here,
    but it's more annoying to build without a request object at hand, so we
    leave it to the caller.
    """

    def mention(maintainer: str) -> str:
        """
        Convert a maintainer to a GitHub mention with a leading `@`. If the
        setting GH_ISSUES_PING_MAINTAINERS is set to False, this mention is
        escaped with backticks to prevent actually pinging the maintainers.
        """
        if settings.GH_ISSUES_PING_MAINTAINERS:
            return f"@{maintainer}"
        else:
            return f"`@{maintainer}`"

    def cvss_details() -> str:
        severity = severity_badge(cached_suggestion.payload["metrics"])
        if severity:
            metric = severity["metric"]
            return f"""
<details>
<summary>CVSS {metric['vectorString']}</summary>

- CVSS version: {metric['version']}
- Attack vector (AV): {metric['attackVector']}
- Attack complexity (AC): {metric['attackComplexity']}
- Privileges required (PR): {metric['privilegesRequired']}
- User interaction (UI): {metric['userInteraction']}
- Scope (S): {metric['scope']}
- Confidentiality impact (C): {metric['confidentialityImpact']}
- Integrity impact (I): {metric['integrityImpact']}
- Availability impact (A): {metric['availabilityImpact']}
</details>"""
        else:
            return ""

    def maintainers() -> str:
        # We need to query for the latest username of each maintainer, because
        # those might have changed since they were written out in Nixpkgs; since
        # we have the user id (which is stable), we can ask the GitHub API
        maintainers_list = [
            get_maintainer_username(maintainer, github)
            for maintainer in cached_suggestion.payload["maintainers"]
            if "github_id" in maintainer and "github" in maintainer
        ]

        if maintainers_list:
            maintainers_joined = ", ".join(mention(m) for m in maintainers_list)
            return f"- affected package maintainers: cc {maintainers_joined}\n"
        else:
            return ""

    def affected_nix_packages() -> str:
        packages = []

        for attribute_name, pkg in cached_suggestion.payload["packages"].items():
            versions = []
            for major_channel, version_data in pkg["versions"]:
                if version_data["major_version"]:
                    versions.append(f"{version_data['major_version']}@{major_channel}")

            versions_details = f" ({", ".join(versions)})" if versions else ""
            packages.append(f"- `{attribute_name}`{versions_details}")

        return f"""
<details>
<summary>Affected packages</summary>

{ "\n".join(packages) }
</details>"""

    repo = github.get_repo(f"{settings.GH_ORGANIZATION}/{settings.GH_ISSUES_REPO}")
    title = cached_suggestion.payload["title"]

    body = f"""\
- [{cached_suggestion.payload['cve_id']}](https://nvd.nist.gov/vuln/detail/{quote(cached_suggestion.payload['cve_id'])})
- [Nixpkgs security tracker issue]({tracker_issue_uri})
{maintainers()}
## Description

{cached_suggestion.payload['description']}
{cvss_details()}
{affected_nix_packages()}"""

    return repo.create_issue(title=title, body=body, labels=settings.GH_ISSUES_LABELS)


def get_maintainer_username(maintainer: dict, github: Github = get_gh()) -> str:
    """
    Get the current GitHub username of a maintainer given their user ID. If the
    request failed, fallback to the github handle stored in the maintainer
    object that comes from Nixpkgs, which might be out of date.
    # TODO: Cache the mapping, e.g. on initial sync and when receiving GitHub events
    # on username change, or simply when doing these calls for resolving the user ID.
    """
    try:
        return github.get_user_by_id(maintainer["github_id"]).login
    except Exception as e:
        logger.error(
            f"Couldn't retrieve the GitHub username for maintainer {maintainer["github_id"]}, fallback to {maintainer["github"]}: {e}"
        )
        return maintainer["github"]
