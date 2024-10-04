import logging
import time
from os import environ as env

import jwt
from github import Auth, Github
from tracker.settings import get_secret

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
                payload = {
                    "iat": int(time.time()),
                    "exp": int(time.time()) + 600,
                    "iss": get_secret("GH_CLIENT_ID"),
                }
                gh_auth = Auth.Token(jwt.encode(payload, f.read(), algorithm="RS256"))
        except FileNotFoundError:
            logger.warning(
                "No token available in the credentials directory, "
                "using unauthenticated API."
            )

    return Github(auth=gh_auth, per_page=per_page)
