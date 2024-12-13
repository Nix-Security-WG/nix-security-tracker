import datetime
import json
from typing import Any, TypedDict, cast

from django import template
from django.template.context import Context
from shared.auth import isadmin, ismaintainer
from shared.listeners.cache_suggestions import parse_drv_name
from shared.models.cve import AffectedProduct
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


class DerivationFields(TypedDict):
    attribute: str
    name: str


class PackageContext(TypedDict):
    attribute_name: str
    pdata: Package


class PackageList(TypedDict):
    items: dict[str, Package]


class PackageListContext(TypedDict):
    packages: PackageList
    user_is_allowed_to_select: bool


class AffectedContext(TypedDict):
    affected: list[AffectedProduct]


class SuggestionActivityLog(TypedDict):
    suggestion: CVEDerivationClusterProposal
    activity_log: dict


class Maintainer(TypedDict):
    name: str
    email: str
    github: str
    matrix: str
    github_id: int


@register.filter
def getitem(dictionary: dict, key: str) -> Any | None:
    return dictionary.get(key)


@register.filter
def getdrvname(drv: dict) -> str:
    hash = drv["drv_path"].split("-")[0].split("/")[-1]
    name = drv["drv_name"]
    return f"{name} {hash[:8]}"


@register.inclusion_tag("components/severity_badge.html")
def severity_badge(metrics: list[dict]) -> dict:
    """
    For now we return the first metric that has a sane looking raw JSON field.
    """
    for m in metrics:
        if "raw_cvss_json" in m and "baseSeverity" in m.get("raw_cvss_json", {}):
            return {"metric": m["raw_cvss_json"]}
    return {}


@register.filter
def iso(date: datetime.datetime) -> str:
    return date.replace(microsecond=0).isoformat()


@register.filter
def last_entry(log: list) -> Any | None:
    try:
        return next(reversed(log))
    except StopIteration:
        return None


@register.filter
def versioned_package_name(package_entry: str) -> str:
    fields: DerivationFields = json.loads(package_entry)

    _, version = parse_drv_name(fields["name"])
    return f"pkgs.{fields["attribute"]} {version}"


def is_admin(user: Any) -> bool:
    if user is None or user.is_anonymous:
        return False
    else:
        return isadmin(user)


@register.filter
def is_maintainer(user: Any) -> bool:
    if user is None or user.is_anonymous:
        return False
    else:
        return ismaintainer(user)


@register.filter
def is_maintainer_or_admin(user: Any) -> bool:
    return is_maintainer(user) or is_admin(user)


@register.inclusion_tag("components/suggestion.html", takes_context=True)
def suggestion(
    context: Context,
    suggestion: CVEDerivationClusterProposal,
    cached_suggestion: dict,
    activity_log: dict,
) -> dict:
    return {
        "suggestion": suggestion,
        "cached_suggestion": cached_suggestion,
        "activity_log": activity_log,
        "status_filter": context["status_filter"],
        "page_obj": context["page_obj"],
        "user": context["user"],
    }


@register.inclusion_tag("components/nixpkgs_package.html")
def nixpkgs_package(attribute_name: str, pdata: Package) -> PackageContext:
    return {"attribute_name": attribute_name, "pdata": pdata}


@register.inclusion_tag("components/selectable_nixpkgs_package_list.html")
def selectable_nixpkgs_package_list(
    packages: PackageList, user_is_allowed_to_select: bool
) -> PackageListContext:
    """Renders the nixpkgs package list with additional checkboxes to have packages selectable.

    Args:
        packages: Dictionary of package attributes and their channel versions

    Returns:
        Context dictionary for the template

    Example:
        {% package_list package_dict %}
    """
    return {
        "packages": packages,
        "user_is_allowed_to_select": user_is_allowed_to_select,
    }


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
    return {
        "packages": packages,
        "user_is_allowed_to_select": False,
    }


@register.inclusion_tag("components/affected_products.html")
def affected_products(affected: list[AffectedProduct]) -> AffectedContext:
    return {"affected": affected}


@register.inclusion_tag("components/suggestion_activity_log.html")
def suggestion_activity_log(
    suggestion: CVEDerivationClusterProposal,
    activity_log: dict,
) -> SuggestionActivityLog:
    return {"suggestion": suggestion, "activity_log": activity_log}


@register.inclusion_tag("components/maintainers_list.html")
def maintainers_list(
    packages: PackageList,
) -> dict[str, list[Maintainer]]:
    maintainers = [
        maintainer
        for _, package in packages.items()
        for maintainer in package["maintainers"]
    ]
    github_ids = set()
    unique_maintainers = [
        cast(Maintainer, m)
        for m in maintainers
        if m["github_id"] not in github_ids and not github_ids.add(m["github_id"])
    ]
    return {"maintainers": unique_maintainers}
