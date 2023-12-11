# Register your models here.

from collections.abc import Callable
from typing import Any

from django.contrib import admin
from django.db import models
from django.db.models import CharField, ForeignKey, ManyToManyField, TextField
from shared.models import Container, NixDerivationMeta, NixpkgsIssue


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
                related_admin = admin.site._registry.get(related_model)
                if not related_admin:
                    related_admin = self.create_related_admin(related_model)
                self.set_search_fields(related_model, related_admin)

    def create_related_admin(self, related_model: type[models.Model]) -> type[Any]:
        related_admin = type(
            f"{related_model.__name__}Admin",
            (ReadOnlyMixin, AutocompleteMixin, admin.ModelAdmin),
            {},
        )
        admin.site.register(related_model, related_admin)
        return related_admin

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
        if admin.site.is_registered(model_class):
            admin.site.unregister(model_class)
        admin.site.register(model_class, admin_class)
        return model_class

    return decorator


@override(NixDerivationMeta)
class NixDerivationMetaAdmin(ReadOnlyMixin, AutocompleteMixin, admin.ModelAdmin):
    search_fields = ["known_vulnerabilities"]


@admin.register(Container)
class ContainerAdmin(ReadOnlyMixin, AutocompleteMixin, admin.ModelAdmin):
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


@admin.register(NixpkgsIssue)
class NixpkgsIssueAdmin(AutocompleteMixin, admin.ModelAdmin):
    readonly_fields = ["code"]
