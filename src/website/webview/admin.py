# Register your models here.

from typing import Type
from django.contrib import admin
from django.db.models import Model
from django.db.models import ForeignKey, ManyToManyField, CharField, TextField
from django.apps import apps

from shared.models import (
    NixpkgsIssue,
    Description,
    Container,
    CveRecord,
    Description,
    NixChannel,
    NixEvaluation,
    NixDerivation,
    NixDerivationMeta,
    NixDerivationOutput,
    NixStorePathOutput,
    NixMaintainer,
)


class ReadOnlyMixin:
    """
    Make all fields read-only.
    No idea why it has to be done this way, but it works.
    """

    model: Type[Model]

    def get_fields(self, request, obj=None):
        return [field.name for field in self.model._meta.fields]

    def get_readonly_fields(self, request, obj=None):
        return self.get_fields(request, obj)


class AutocompleteMixin:
    """
    Make all relation fields autocomplete fields to avoid hanging on large relations.
    This requires setting search fields on the related models.
    """

    def __init__(self, model, admin_site):
        super().__init__(model, admin_site)  # type: ignore
        self.set_autocomplete_fields(model)

    def set_autocomplete_fields(self, model):
        for field in model._meta.get_fields():
            if isinstance(field, (ForeignKey, ManyToManyField)):
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

    def create_related_admin(self, related_model):
        related_admin = type(
            f"{related_model.__name__}Admin",
            (ReadOnlyMixin, AutocompleteMixin, admin.ModelAdmin),
            {},
        )
        admin.site.register(related_model, related_admin)
        return related_admin

    def set_search_fields(self, model, admin_class):
        search_fields = [
            field.name
            for field in model._meta.get_fields()
            if isinstance(field, (CharField, TextField))
        ]
        if search_fields == []:
            search_fields = ["__str__"]

        admin_class.search_fields = list(getattr(admin_class, "search_fields", []))
        if not admin_class.search_fields:
            admin_class.search_fields = search_fields


def override(model_class):
    def decorator(admin_class):
        if admin.site.is_registered(model_class):
            admin.site.unregister(model_class)
        admin.site.register(model_class, admin_class)
        return model_class

    return decorator


@admin.register(NixpkgsIssue)
class NixpkgsIssueAdmin(AutocompleteMixin, admin.ModelAdmin):
    autocomplete_fields = ["description", "cve"]
    readonly_fields = ["code"]
    exclude = ["number"]
