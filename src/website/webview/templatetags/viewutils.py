import datetime
from collections import OrderedDict
from typing import Any, TypedDict

from django import template
from django.template.context import Context
from django.utils.html import format_html
from django.utils.safestring import SafeString
from shared.models.cve import AffectedProduct, Severity
from shared.models.linkage import (
    CVEDerivationClusterProposal,
)

register = template.Library()


class VersionInfo(TypedDict):
    major_version: str | None
    uniform_versions: bool
    sub_branches: list[tuple[str, str]]


class Package(TypedDict):
    items: dict[str, str | list[str] | VersionInfo]


class PackageContext(TypedDict):
    attribute_name: str
    pdata: Package


class PackageList(TypedDict):
    items: dict[str, Package]


class PackageListContext(TypedDict):
    packages: PackageList


class AffectedContext(TypedDict):
    affected: list[AffectedProduct]


class SuggestionActivityLog(TypedDict):
    suggestion: CVEDerivationClusterProposal


@register.filter
def getitem(dictionary: dict, key: str) -> Any | None:
    return dictionary.get(key)


@register.filter
def getdrvname(drv: dict) -> str:
    hash = drv["drv_path"].split("-")[0].split("/")[-1]
    name = drv["drv_name"]
    return f"{name} {hash[:8]}"


@register.filter
def iso(date: datetime.datetime) -> str:
    return date.replace(microsecond=0).isoformat()


@register.filter
def last_key(od: OrderedDict) -> Any | None:
    try:
        return next(reversed(od))
    except StopIteration:
        return None


@register.filter
def last_user(od: OrderedDict) -> str | None:
    try:
        _, entry = next(reversed(od.items()))
        return entry[0]["user"]
    except StopIteration:
        return None


@register.inclusion_tag("components/suggestion.html", takes_context=True)
def suggestion(
    context: Context, suggestion: CVEDerivationClusterProposal, cached_suggestion: dict
) -> dict:
    return {
        "suggestion": suggestion,
        "cached_suggestion": cached_suggestion,
        "status_filter": context["status_filter"],
        "page_obj": context["page_obj"],
    }


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
    display_texts = {
        "NONE": "No severity data",
        "LOW": "Low",
        "MEDIUM": "Medium",
        "HIGH": "High",
        "CRITICAL": "Critical",
    }

    return format_html(
        '<div class="severity {}">{}</div>', severity, display_texts[severity]
    )


@register.inclusion_tag("components/nixpkgs_package.html")
def nixpkgs_package(attribute_name: str, pdata: Package) -> PackageContext:
    return {"attribute_name": attribute_name, "pdata": pdata}


@register.inclusion_tag("components/selectable_nixpkgs_package_list.html")
def selectable_nixpkgs_package_list(packages: PackageList) -> PackageListContext:
    """Renders the nixpkgs package list with additional checkboxes to have packages selectable.

    Args:
        packages: Dictionary of package attributes and their channel versions

    Returns:
        Context dictionary for the template

    Example:
        {% package_list package_dict %}
    """
    return {"packages": packages}


@register.inclusion_tag("components/nixpkgs_package_list.html")
def nixpkgs_package_list(packages: PackageList) -> PackageListContext:
    """Renders the nixpkgs package list.

    Args:
        packages: Dictionary of package attributes and their channel versions

    Returns:
        Context dictionary for the template

    Example:
        {% package_list package_dict %}
    """
    return {"packages": packages}


@register.inclusion_tag("components/affected_products.html")
def affected_products(affected: list[AffectedProduct]) -> AffectedContext:
    return {"affected": affected}


@register.inclusion_tag("components/suggestion_activity_log.html")
def suggestion_activity_log(
    suggestion: CVEDerivationClusterProposal,
) -> SuggestionActivityLog:
    return {"suggestion": suggestion}
