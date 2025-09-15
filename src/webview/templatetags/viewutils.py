import datetime
from typing import Any, TypedDict

from django import template
from django.template.context import Context

from shared.auth import isadmin, ismaintainer
from shared.listeners.cache_issues import CachedNixpkgsIssuePayload
from shared.listeners.cache_suggestions import parse_drv_name
from shared.logs.batches import FoldedEventType
from shared.logs.events import Maintainer
from shared.models.cve import AffectedProduct
from shared.models.linkage import (
    CVEDerivationClusterProposal,
)
from webview.models import Notification

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
    selectable: bool


class AffectedContext(TypedDict):
    affected: list[AffectedProduct]


class SuggestionActivityLog(TypedDict):
    suggestion: CVEDerivationClusterProposal
    activity_log: dict
    oob_update: bool


class MaintainerContext(TypedDict):
    maintainer: Maintainer


class SelectableMaintainerContext(TypedDict):
    maintainer: Maintainer
    deleted: bool


class AddMaintainerContext(TypedDict):
    error_msg: str | None


class MaintainersListContext(TypedDict):
    maintainers: list[Maintainer]
    selectable: bool


class EditableMaintainersListContext(TypedDict):
    maintainers: list[Maintainer]
    selectable: bool
    suggestion_id: int
    oob_update: bool


class NotificationContext(TypedDict):
    notification: Notification
    current_page: (
        int | None
    )  # For no-js compatibility in multi-page notification center
    new_unread_count: int | None  # For oob update of unread notifications counter


class NotificationsBadgeContext(TypedDict):
    count: int
    oob_update: bool | None


@register.filter
def getitem(dictionary: dict, key: str) -> Any | None:
    return dictionary.get(key)


@register.filter
def getdrvname(drv: dict) -> str:
    hash = drv["drv_path"].split("-")[0].split("/")[-1]
    name = drv["drv_name"]
    return f"{name} {hash[:8]}"


@register.inclusion_tag("notifications/components/notification.html")
def notification(
    notification: Notification,
    current_page: int | None = None,
    new_unread_count: int | None = None,
) -> NotificationContext:
    return {
        "notification": notification,
        "current_page": current_page,
        "new_unread_count": new_unread_count,
    }


@register.inclusion_tag("notifications/components/notifications_badge.html")
def notifications_badge(
    count: int, oob_update: bool | None = None
) -> NotificationsBadgeContext:
    return {"count": count, "oob_update": oob_update}


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
def versioned_package_name(package_entry: dict[str, Any]) -> str:
    _, version = parse_drv_name(package_entry["name"])
    return f"pkgs.{package_entry['attribute']} {version}"


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
    activity_log: list[FoldedEventType],
) -> dict:
    return {
        "suggestion": suggestion,
        "cached_suggestion": cached_suggestion,
        "activity_log": activity_log,
        "status_filter": context["status_filter"],
        "page_obj": context["page_obj"],
        "user": context["user"],
    }


@register.inclusion_tag("components/issue.html", takes_context=True)
def issue(
    context: Context,
    issue: CachedNixpkgsIssuePayload,
    show_permalink: bool = False,
) -> dict:
    return {
        "issue": issue,
        "show_permalink": show_permalink,
        "page_obj": context.get("page_obj", None),
    }


@register.inclusion_tag("components/nixpkgs_package.html")
def nixpkgs_package(attribute_name: str, pdata: Package) -> PackageContext:
    return {"attribute_name": attribute_name, "pdata": pdata}


@register.inclusion_tag("components/nixpkgs_package_list.html")
def selectable_nixpkgs_package_list(packages: PackageList) -> PackageListContext:
    """Renders the nixpkgs package list with additional checkboxes to have packages selectable.

    Args:
        packages: Dictionary of package attributes and their channel versions

    Returns:
        Context dictionary for the template

    Example:
        {% selectable_nixpkgs_package_list package_dict %}
    """
    return {
        "packages": packages,
        "selectable": True,
    }


@register.inclusion_tag("components/nixpkgs_package_list.html")
def nixpkgs_package_list(packages: PackageList) -> PackageListContext:
    """Renders the nixpkgs package list.

    Args:
        packages: Dictionary of package attributes and their channel versions

    Returns:
        Context dictionary for the template

    Example:
        {% nixpkgs_package_list package_dict %}
    """
    return {
        "packages": packages,
        "selectable": False,
    }


@register.inclusion_tag("components/affected_products.html")
def affected_products(affected: list[AffectedProduct]) -> AffectedContext:
    return {"affected": affected}


@register.inclusion_tag("components/suggestion_activity_log.html")
def suggestion_activity_log(
    suggestion: CVEDerivationClusterProposal,
    activity_log: dict,
    oob_update: bool = False,
) -> SuggestionActivityLog:
    return {
        "suggestion": suggestion,
        "activity_log": activity_log,
        "oob_update": oob_update,
    }


@register.inclusion_tag("components/maintainers_list.html")
def maintainers_list(
    maintainers: list[Maintainer],
) -> MaintainersListContext:
    return {
        "maintainers": maintainers,
        "selectable": False,
    }


@register.inclusion_tag("components/maintainers_list.html", takes_context=True)
def selectable_maintainers_list(
    context: Context,
    maintainers: list[Maintainer],
    suggestion_id: int,
    oob_update: bool = False,
) -> EditableMaintainersListContext:
    user = context.get("user")
    selectable = is_maintainer_or_admin(user)
    return {
        "maintainers": maintainers,
        "selectable": selectable,
        "suggestion_id": suggestion_id,
        "oob_update": oob_update,
    }


@register.inclusion_tag("components/maintainer.html")
def maintainer(
    maintainer: Maintainer,
) -> MaintainerContext:
    return {"maintainer": maintainer}


@register.inclusion_tag("components/selectable_maintainer.html")
def selectable_maintainer(
    maintainer: Maintainer,
    deleted: bool = False,
) -> SelectableMaintainerContext:
    return {"maintainer": maintainer, "deleted": deleted}


@register.inclusion_tag("components/add_maintainer.html")
def add_maintainer(
    error_msg: str | None = None,
) -> AddMaintainerContext:
    return {"error_msg": error_msg}
