import logging
from os import environ as env

from github import Auth, Github
from github.Issue import Issue as GithubIssue
from urllib.parse import quote
from django.urls import reverse
from tracker.settings import GH_ISSUES_REPO, GH_ORGANIZATION, get_secret
from shared.models import CachedSuggestions, NixpkgsIssue
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

def create_gh_issue(cached_suggestion: CachedSuggestions, tracker_issue_uri:
                    str, github = get_gh()) -> GithubIssue:
    """
    Create a GitHub issue for the given suggestion, given a link to the
    corresponding NixpkgsIssue on the tracker side, on the nixpkgs repository.

    The tracker issue URI could be derived automatically from NixpkgsIssue here,
    but it's more annoying to build without a request object at hand, so we
    leave it to the caller.
    """

    repo = github.get_repo(f"{GH_ORGANIZATION}/{GH_ISSUES_REPO}")
    title = cached_suggestion.payload['title']
    severity = severity_badge(cached_suggestion.payload['metrics'])

    details = ""

    if severity:
        metric = severity['metric']
        details = f"""
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

    body = f"""\
[{cached_suggestion.payload['cve_id']}](https://nvd.nist.gov/vuln/detail/{quote(cached_suggestion.payload['cve_id'])})

[Vulnerability tracker issue]({tracker_issue_uri})

## Description

{cached_suggestion.payload['description']}
{details}"""

    repo.create_issue(title, body)
