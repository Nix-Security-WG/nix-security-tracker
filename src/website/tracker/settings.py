"""
Django settings for tracker project.

Generated by 'django-admin startproject' using Django 4.2.4.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

import importlib.util
import sys
from os import environ as env
from pathlib import Path

import dj_database_url
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


def get_secret(name: str, encoding: str = "utf-8") -> str:
    credentials_dir = env.get("CREDENTIALS_DIRECTORY")

    if credentials_dir is None:
        raise RuntimeError("No credentials directory available.")

    try:
        with open(f"{credentials_dir}/{name}", encoding=encoding) as f:
            secret = f.read().removesuffix("\n")
    except FileNotFoundError:
        raise RuntimeError(f"No secret named {name} found in {credentials_dir}.")

    return secret


## GlitchTip setup

if "GLITCHTIP_DSN" in env:
    sentry_sdk.init(
        dsn=get_secret("GLITCHTIP_DSN"),
        integrations=[DjangoIntegration()],
        auto_session_tracking=False,
        traces_sample_rate=0,
    )

## Channel setup
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": list(filter(None, [env.get("REDIS_UNIX_SOCKET")])),
        },
    },
}

## Logging settings
# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {process:d} {thread:d} {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname} {message}",
            "style": "{",
        },
    },
    "filters": {
        "require_debug_true": {
            "()": "django.utils.log.RequireDebugTrue",
        },
    },
    "handlers": {
        "console": {
            "level": "DEBUG" if DEBUG else "INFO",
            "filters": ["require_debug_true"],
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "mail_admins": {
            "level": "ERROR",
            "class": "django.utils.log.AdminEmailHandler",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "propagate": True,
        },
        "django.request": {
            "handlers": ["mail_admins"],
            "level": "ERROR",
            "propagate": False,
        },
        "django.db.backends": {
            "level": "INFO" if "LOG_DB_QUERIES" not in env else "DEBUG",
            "handlers": ["console"],
        },
        "shared": {
            "handlers": ["console", "mail_admins"],
            "level": "DEBUG" if DEBUG else "INFO",
            "filters": [],
        },
    },
}
## Evaluation settings

GIT_CLONE_URL = "https://github.com/NixOS/nixpkgs"
# This is the path where a local checkout of Nixpkgs
# will be instantiated for this application's needs.
# By default, in the root of this Git repository.
LOCAL_NIXPKGS_CHECKOUT = (BASE_DIR / ".." / ".." / "nixpkgs").resolve()
# Evaluation concurrency
# Do not go overboard with this, as Nixpkgs evaluation
# is _very_ expensive.
# The more cores you have, the more RAM you will consume.
# TODO(raitobezarius): implement fine-grained tuning on `nix-eval-jobs`.
MAX_PARALLEL_EVALUATION = 3
# Where are stored the evaluation gc roots directory
EVALUATION_GC_ROOTS_DIRECTORY: str = str(
    Path(BASE_DIR / ".." / ".." / "nixpkgs-gc-roots").resolve()
)
# Where are the stderr of each `nix-eval-jobs` stored.
EVALUATION_LOGS_DIRECTORY: str = str(
    Path(BASE_DIR / ".." / ".." / "nixpkgs-evaluation-logs").resolve()
)
CVE_CACHE_DIR: str = str(Path(BASE_DIR / ".." / ".." / "cve-cache").resolve())
# This can be tuned for your specific deployment,
# this is used to wait for an evaluation slot to be available
# It should be around the average evaluation time on your machine.
# in seconds.
# By default: 25 minutes.
DEFAULT_SLEEP_WAITING_FOR_EVALUATION_SLOT = 25 * 60

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = get_secret("SECRET_KEY")

ALLOWED_HOSTS = []

# Application definition
ASGI_APPLICATION = "tracker.asgi.application"
INSTALLED_APPS = [
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.humanize",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_filters",
    "debug_toolbar",
    # AllAuth config
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.github",
    "channels",
    "pgpubsub",
    "pgtrigger",
    "pghistory",
    "pghistory.admin",
    "rest_framework",
    "shared",
    "webview",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "debug_toolbar.middleware.DebugToolbarMiddleware",
    # Allauth account middleware
    "allauth.account.middleware.AccountMiddleware",
    "pghistory.middleware.HistoryMiddleware",
]

ROOT_URLCONF = "tracker.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "shared/templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "tracker.wsgi.application"

## Realtime events configuration

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {}
DATABASES["default"] = dj_database_url.config(conn_max_age=600, conn_health_checks=True)

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": f"django.contrib.auth.password_validation.{v}"}
    for v in [
        "UserAttributeSimilarityValidator",
        "MinimumLengthValidator",
        "CommonPasswordValidator",
        "NumericPasswordValidator",
    ]
]

AUTHENTICATION_BACKENDS = [
    # Needed to login by username in Django admin, regardless of `allauth`
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]

SOCIALACCOUNT_PROVIDERS = {
    "github": {
        "SCOPE": [
            "read:user",
            "read:org",
        ],
        "APPS": [
            {
                "client_id": get_secret("GH_CLIENT_ID"),
                "secret": get_secret("GH_SECRET"),
                "key": "",
            }
        ],
    }
}

REST_FRAMEWORK = {
    "DEFAULT_FILTER_BACKENDS": ["django_filters.rest_framework.DjangoFilterBackend"]
}

SITE_ID = 1

ACCOUNT_EMAIL_VERIFICATION = "none"

# TODO: make configurable so one can log in locally
LOGIN_REDIRECT_URL = "webview:home"

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = "en-gb"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# needed for debug_toolbar
INTERNAL_IPS = [
    "127.0.0.1",
    "[::1]",
]

# Github auth settings
GH_ORGANIZATION = "NixOS"
GH_COMMITTERS_TEAM = "nixpkgs-committers"
GH_SECURITY_TEAM = "security"
# Repository to post issues to
GH_ISSUES_REPO = "nixpkgs"
# This will be synced with GH_COMMITTERS_TEAM in GH_ORGANIZATION.
DB_COMMITTERS_TEAM = "committers"
# This will be synced with GH_SECURITY_TEAM in GH_ORGANIZATION
DB_SECURITY_TEAM = "security_team"

GH_WEBHOOK_SECRET = get_secret("GH_WEBHOOK_SECRET")

TEST_RUNNER = "tracker.test_runner.CustomTestRunner"

# Make history log immutable by default
PGHISTORY_APPEND_ONLY = True
PGHISTORY_ADMIN_MODEL = "pghistory.MiddlewareEvents"

# Customization via user settings
# This must be at the end, as it must be able to override the above
user_settings_file = env.get("USER_SETTINGS_FILE", None)
if user_settings_file is not None:
    spec = importlib.util.spec_from_file_location("user_settings", user_settings_file)
    if spec is None or spec.loader is None:
        raise RuntimeError("User settings specification failed!")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules["user_settings"] = module
    from user_settings import *  # noqa: F403 # pyright: ignore [reportMissingImports]

# Settings side-effect, must be after the loading of ALL settings, including user ones.

# Ensure the following directories exist.
Path(EVALUATION_GC_ROOTS_DIRECTORY).mkdir(exist_ok=True)
Path(EVALUATION_LOGS_DIRECTORY).mkdir(exist_ok=True)
