from typing import Any, TypedDict

from django import template
from django.utils.html import format_html
from django.utils.safestring import SafeString
from shared.models.cve import Severity

register = template.Library()


class VersionInfo(TypedDict):
    major_version: str | None
    uniform_versions: bool
    sub_branches: list[tuple[str, str]]


class PackageDict(TypedDict):
    items: dict[str, dict[str, VersionInfo]]


class PackageListContext(TypedDict):
    packages: PackageDict


class SuggestionStateButtonContext(TypedDict):
    suggestion_id: str
    state: str
    label: str
    style: str


@register.filter
def getitem(dictionary: dict, key: str) -> Any | None:
    return dictionary.get(key)


@register.filter
def getdrvname(drv: dict) -> str:
    hash = drv["drv_path"].split("-")[0].split("/")[-1]
    name = drv["drv_name"]
    return f"{name} {hash[:8]}"


@register.simple_tag
def severity_badge(severity: Severity) -> SafeString:
    """Renders a severity badge with the given severity level.

    Args:
        severity: The severity level to display

    Returns:
        HTML markup for the severity badge

    Example:
        {% severity_badge "HIGH" %}
    """

    # TODO Once https://github.com/Nix-Security-WG/nix-security-tracker/issues/284
    # is fixed, display actual severity information with a combined metric (e.g.
    # "9.1" and a textual representiation like "Critical")
    display_text = "No severity data"

    return format_html('<div class="severity {}">{}</div>', severity, display_text)


@register.inclusion_tag("components/nixpkgs_package_list.html")
def nixpkgs_package_list(packages: PackageDict) -> PackageListContext:
    """Renders the nixpkgs package list.

    Args:
        packages: Dictionary of package attributes and their channel versions

    Returns:
        Context dictionary for the template

    Example:
        {% package_list package_dict %}
    """
    return {"packages": packages}


@register.inclusion_tag("components/suggestion_state_button.html")
def suggestion_state_button(
    suggestion_id: str, state: str, label: str, style: str
) -> SuggestionStateButtonContext:
    return {
        "suggestion_id": suggestion_id,
        "state": state,
        "label": label,
        "style": style,
    }
