import logging
from os import environ as env

from github import Auth, Github

logger = logging.getLogger(__name__)


def get_gh(per_page: int = 30) -> Github:
    """
    Initialize a GitHub API connection, using credentials when available.
    """

    credentials_dir = env.get("CREDENTIALS_DIRECTORY")

    gh_auth: Auth.Auth | None = None

    if credentials_dir is None:
        logger.warn("No credentials directory available, using unauthenticated API.")
    else:
        logger.warn(f"Using credentials directory: {credentials_dir}")

        try:
            with open(f"{credentials_dir}/GH_TOKEN", encoding="utf-8") as f:
                gh_auth = Auth.Token(f.read().rstrip("\n"))
                logger.warn("Using GitHub Token to connect to the API.")
        except FileNotFoundError:
            logger.warn(
                "No token available in the credentials directory, "
                "using unauthenticated API."
            )

    return Github(auth=gh_auth, per_page=per_page)
