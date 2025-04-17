import logging
from os import environ as env

from github import Auth, Github
from github.Issue import Issue as GithubIssue
from urllib.parse import quote
from tracker.settings import (
    GH_ISSUES_REPO,
    GH_ORGANIZATION,
    GH_ISSUES_PING_MAINTAINERS,
    get_secret,
)
from shared.models import CachedSuggestions
from webview.templatetags.viewutils import severity_badge

logger = logging.getLogger(__name__)


def get_gh(per_page: int = 30) -> Github:
    """
    Initialize a GitHub API connection, using credentials when available.
    """

    credentials_dir = env.get("CREDENTIALS_DIRECTORY")

    gh_auth: Auth.Auth | None = None

    if credentials_dir is None:
        logger.warning("No credentials directory available, using unauthenticated API.")
    else:
        logger.info(f"Using credentials directory: {credentials_dir}")

        try:
            with open(f"{credentials_dir}/GH_TOKEN", encoding="utf-8") as f:
                gh_auth = Auth.Token(f.read().rstrip("\n"))
                logger.info("Using GitHub Token to connect to the API.")
        except FileNotFoundError:
            logger.debug(
                "No specific token was found, trying the GitHub application JWT generation method..."
            )

        try:
            with open(f"{credentials_dir}/GH_APP_PRIVATE_KEY", encoding="utf-8") as f:
                gh_auth = Auth.AppAuth(
                    get_secret("GH_CLIENT_ID"), f.read()
                ).get_installation_auth(int(get_secret("GH_APP_INSTALLATION_ID")))
        except FileNotFoundError:
            logger.warning(
                "No token available in the credentials directory, "
                "using unauthenticated API."
            )

    return Github(auth=gh_auth, per_page=per_page)


def create_gh_issue(
    cached_suggestion: CachedSuggestions, tracker_issue_uri: str, github=get_gh()
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
        if GH_ISSUES_PING_MAINTAINERS:
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
        # We need to query for the latest username of each maintainers, because
        # those might have changed since they were written out in Nixpkgs; since we
        # have the user id (which is stable), we can ask the GitHub API
        maintainers_list = [
            get_maintainer_username(maintainer, github)
            for maintainer in cached_suggestion.all_maintainers
            if "github_id" in maintainer and "github" in maintainer
        ]

        if maintainers_list:
            maintainers_joined = ", ".join(mention(m) for m in maintainers_list)
            return f"- affected package maintainers: cc {maintainers_joined}\n"
        else:
            return ""

    repo = github.get_repo(f"{GH_ORGANIZATION}/{GH_ISSUES_REPO}")
    title = cached_suggestion.payload["title"]
    logger.error("all maintainers: %s", cached_suggestion.all_maintainers)

    body = f"""\
- [{cached_suggestion.payload['cve_id']}](https://nvd.nist.gov/vuln/detail/{quote(cached_suggestion.payload['cve_id'])})
- [Nix security tracker issue]({tracker_issue_uri})
{maintainers()}
## Description

{cached_suggestion.payload['description']}
{cvss_details()}"""

    return repo.create_issue(title, body)


def get_maintainer_username(maintainer: dict, github=get_gh()) -> str:
    """
    Get the current GitHub username of a maintainer given their user ID. If the
    request failed, fallback to the github handle stored in the maintainer
    object that comes from Nixpkgs, which might be out of date.
    """
    try:
        return github.get_user_by_id(maintainer["github_id"]).login
    except Exception as e:
        logger.error(
            f"Couldn't retrieve the GitHub username for maintainer {maintainer["github_id"]}, fallback to {maintainer["github"]}: {e}"
        )
        return maintainer["github"]
