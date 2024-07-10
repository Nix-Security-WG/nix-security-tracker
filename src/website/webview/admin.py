# Register your models here.

import logging
from collections.abc import Callable
from typing import Any

from django import forms
from django.apps import apps
from django.contrib import admin
from django.db import models
from django.db.models import CharField, ForeignKey, ManyToManyField, TextField
from shared.auth import isadmin, ismaintainer
from shared.models import (
    Container,
    CveRecord,
    Description,
    NixDerivation,
    NixDerivationMeta,
    NixpkgsIssue,
)
from tracker.admin import custom_admin_site

admin_site = custom_admin_site
logger = logging.getLogger(__name__)


# Mixins
class CustomAdminPermissionsMixin:
    def has_view_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        if not request.user.is_authenticated:
            return False

        return isadmin(request.user)

    def has_change_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        if not request.user.is_authenticated:
            return False

        return isadmin(request.user)

    def has_add_permission(self, request: Any) -> bool:
        if not request.user.is_authenticated:
            return False

        return isadmin(request.user)

    def has_delete_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        if not request.user.is_authenticated:
            return False

        return isadmin(request.user)

    def has_module_permission(self, request: Any) -> bool:
        if not request.user.is_authenticated:
            return False

        return isadmin(request.user)


class MaintainerPermissionsMixin(CustomAdminPermissionsMixin):
    def has_view_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        if not request.user.is_authenticated:
            return False

        return isadmin(request.user) or ismaintainer(request.user)

    def has_change_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        if not request.user.is_authenticated:
            return False

        return isadmin(request.user) or ismaintainer(request.user)

    def has_add_permission(self, request: Any) -> bool:
        if not request.user.is_authenticated:
            return False

        return isadmin(request.user) or ismaintainer(request.user)

    def has_delete_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        if not request.user.is_authenticated:
            return False

        return isadmin(request.user) or ismaintainer(request.user)

    def has_module_permission(self, request: Any) -> bool:
        if not request.user.is_authenticated:
            return False

        return isadmin(request.user) or ismaintainer(request.user)


class ReadOnlyMixin:
    """
    Make all fields read-only.
    No idea why it has to be done this way, but it works.
    """

    model: type[models.Model]

    def get_fields(self, request: object, obj: models.Model | None = None) -> list[str]:
        return [field.name for field in self.model._meta.fields]

    def get_readonly_fields(
        self, request: object, obj: models.Model | None = None
    ) -> list[str]:
        # existing objects are read-only
        if obj:
            return self.get_fields(request, obj)
        # all fields, except automatic ones, are writeable on creation (for debugging)
        else:
            return [
                field.name
                for field in self.model._meta.fields
                if (
                    isinstance(field, models.AutoField)
                    or (isinstance(field, models.DateTimeField) and field.auto_now_add)
                )
            ]


class AutocompleteMixin:
    """
    Make all relation fields autocomplete fields to avoid hanging on large relations.
    This requires setting search fields on the related models.
    """

    def __init__(self, model: type[models.Model], admin_site: Any) -> None:
        super().__init__(model, admin_site)  # type: ignore
        self.set_autocomplete_fields(model)

    def set_autocomplete_fields(self, model: type[models.Model]) -> None:
        for field in model._meta.get_fields():
            if isinstance(field, ForeignKey | ManyToManyField):
                # Update autocomplete_fields
                self.autocomplete_fields = list(
                    getattr(self, "autocomplete_fields", [])
                )
                if field.name not in self.autocomplete_fields:
                    self.autocomplete_fields.append(field.name)

                # Add search_fields to the referenced models
                related_model = field.remote_field.model
                related_admin = admin_site._registry.get(related_model)
                if not related_admin:
                    logger.warning("Missing model admin for %s", related_model)
                else:
                    self.set_search_fields(related_model, related_admin)

    def set_search_fields(
        self,
        model: type[models.Model],
        admin_class: type[admin.ModelAdmin] | admin.ModelAdmin,
    ) -> None:
        search_fields = [
            field.name
            for field in model._meta.get_fields()
            if isinstance(field, CharField | TextField)
        ]
        if search_fields == []:
            search_fields = ["__str__"]

        admin_class.search_fields = list(getattr(admin_class, "search_fields", []))
        if not admin_class.search_fields:
            admin_class.search_fields = search_fields


def override(model_class: type[Any]) -> Callable[[type[Any]], type[Any]]:
    def decorator(admin_class: type[Any]) -> type[Any]:
        if admin_site.is_registered(model_class):
            admin_site.unregister(model_class)
        admin_site.register(model_class, admin_class)
        return model_class

    return decorator


# Register all models from the 'shared' app
shared_app_config = apps.get_app_config("shared")
shared_models = shared_app_config.get_models()
for model in shared_models:
    modeladmin = type(
        f"{model.__name__}Admin",
        (
            AutocompleteMixin,
            CustomAdminPermissionsMixin,
            admin.ModelAdmin,
        ),
        {},
    )

    admin_site.register(model, modeladmin)


@override(NixDerivationMeta)
class NixDerivationMetaAdmin(
    ReadOnlyMixin, AutocompleteMixin, MaintainerPermissionsMixin, admin.ModelAdmin
):
    search_fields = ["known_vulnerabilities"]

    def get_queryset(self, request: Any) -> Any:
        """Limit elements shown for pkg maintainer"""
        queryset = NixDerivationMeta.objects

        if (
            request.user.is_authenticated
            and not isadmin(request.user)
            and ismaintainer(request.user)
        ):
            # Limit elements shown for pkg maintainer
            queryset = (
                NixDerivationMeta.objects.prefetch_related("maintainers")
                .filter(
                    maintainers__github=request.user.username  # type: ignore
                )
                .distinct()
            )

        return queryset


@override(Container)
class ContainerAdmin(
    ReadOnlyMixin, AutocompleteMixin, MaintainerPermissionsMixin, admin.ModelAdmin
):
    search_fields = ["title"]

    def get_search_results(
        self, request: Any, queryset: Any, search_term: str
    ) -> tuple[Any, bool]:
        queryset, use_distinct = super().get_search_results(
            request, queryset, search_term
        )

        if search_term:
            # allow search in nested CVE objectss
            queryset |= self.model.objects.filter(cve__cve_id__icontains=search_term)
            use_distinct = True

        return queryset, use_distinct


@override(NixpkgsIssue)
class NixpkgsIssueAdmin(
    AutocompleteMixin, MaintainerPermissionsMixin, admin.ModelAdmin
):
    readonly_fields = ["code"]
    search_fields = ["code"]

    # TODO: check permission functions
    def has_view_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        return super().has_change_permission(request, obj)

    def has_change_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        return super().has_change_permission(request, obj)

    def has_add_permission(self, request: Any) -> bool:
        return super().has_add_permission(request)

    def has_delete_permission(
        self, request: Any, obj: models.Model | None = None
    ) -> bool:
        return super().has_delete_permission(request, obj)

    def has_module_permission(self, request: Any) -> bool:
        return super().has_module_permission(request)

    def get_queryset(self, request: Any) -> Any:
        queryset = NixpkgsIssue.objects

        if (
            request.user.is_authenticated
            and not isadmin(request.user)
            and ismaintainer(request.user)
        ):
            # Limit elements shown for pkg maintainer
            queryset = (
                NixpkgsIssue.objects.prefetch_related(
                    "derivations__metadata__maintainers"
                )
                .filter(
                    derivations__metadata__maintainers__github=request.user.username  # type: ignore
                )
                .distinct()
            )

        return queryset

    def get_form(
        self, request: Any, obj: models.Model | None = None, **kwargs: Any
    ) -> type[forms.ModelForm]:
        """
        NOTE(alejandrosame): Why monkey patch the `form.clean` method?

        The cleaner way to add the `is_pkg_maintainer` check is to set a custom
        `NixpkgsIssueForm` that provides the extra logic below in it's `clean`
        method (calling `super().clean()` to inherit default validation).

        This custom form class can then be returned by the `get_form` method
        by being created by a factory function that links the request to check
        the currently logged user.

        The problem with that approach here is that the corresponding view generated
        doesn't contain all the autocomplete logic that the default form has. This
        makes the form unusable in the frontend (the form will try to load all CVEs,
        descriptions and derivations to populate the option values in the select fields).

        By moneky patcing the extra clean logic the way it's done below, we can reuse
        the view logic in the admin interface. Alternatively, we'd have to recreate the
        `select2` widget used by the admin interface, which is not reusable. See [1] for
        an example on how to add `select2` functionality to a custom form.

        [1] https://michelenasti.com/2021/02/12/how-to-integrate-a-django_select2-component-in-django-admin.html
        """
        form = super().get_form(request, obj, **kwargs)
        orig_clean = form.clean

        if (
            request.user.is_authenticated
            and not isadmin(request.user)
            and ismaintainer(request.user)
        ):

            def new_clean(self: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
                cleaned_data = orig_clean(self, *args, **kwargs)
                derivations = cleaned_data.get("derivations")
                if derivations:
                    for derivation in derivations:
                        is_pkg_maintainer = derivation.metadata.maintainers.filter(
                            github=request.user.username
                        ).exists()
                        if not is_pkg_maintainer:
                            self.add_error(
                                "derivations",
                                "Cannot add issues that relate to derivations you do not maintain.",
                            )
                return cleaned_data

            form.clean = new_clean

        return form


@override(NixDerivation)
class NixDerivationAdmin(
    AutocompleteMixin, MaintainerPermissionsMixin, admin.ModelAdmin
):
    search_fields = ["name"]

    def get_queryset(self, request: Any) -> Any:
        queryset = NixDerivation.objects

        if (
            request.user.is_authenticated
            and not isadmin(request.user)
            and ismaintainer(request.user)
        ):
            # Limit elements shown for pkg maintainer
            queryset = (
                queryset.prefetch_related("metadata__maintainers")
                .filter(
                    metadata__maintainers__github=request.user.username  # type: ignore
                )
                .distinct()
            )

        return queryset


@override(CveRecord)
class CveRecordAdmin(AutocompleteMixin, MaintainerPermissionsMixin, admin.ModelAdmin):
    search_fields = ["cve_id"]


@override(Description)
class DescriptionAdmin(MaintainerPermissionsMixin, admin.ModelAdmin):
    search_fields = ["__str__"]
