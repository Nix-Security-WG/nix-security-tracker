# Register your models here.

from django.contrib import admin
from django.db.models import Q

from shared.models import (
    NixpkgsIssue,
    Description,
    CveRecord,
    NixChannel,
    NixEvaluation,
    NixDerivation,
    NixDerivationMeta,
    NixDerivationOutput,
    NixStorePathOutput,
    NixMaintainer,
)


admin.site.register(NixChannel)


@admin.register(Description)
class DescriptionAdmin(admin.ModelAdmin):
    search_fields = ["value", "media"]


@admin.register(NixpkgsIssue)
class NixpkgsIssueAdmin(admin.ModelAdmin):
    autocomplete_fields = ["description", "derivations"]
    readonly_fields = ["code"]
    exclude = ["number"]


@admin.register(NixStorePathOutput)
class NixStorePathOutputAdmin(admin.ModelAdmin):
    search_fields = ["output_name"]


@admin.register(NixMaintainer)
class NixMaintainerAdmin(admin.ModelAdmin):
    search_fields = ["github"]


@admin.register(NixDerivationOutput)
class NixDerivationOutputAdmin(admin.ModelAdmin):
    search_fields = ["outputs"]


class MaintainersFilter(admin.SimpleListFilter):
    title = "Maintainers"
    parameter_name = "no_maintainers"

    def lookups(self, request, model_admin):
        return (
            ("empty", "No maintainers"),
            ("non_empty", "Has maintainers"),
        )

    def queryset(self, request, queryset):
        if self.value() == "non_empty":
            return queryset.filter(~Q(maintainers=None))
        if self.value() == "empty":
            return queryset.filter(Q(maintainers=None))


@admin.register(NixDerivationMeta)
class NixDerivationMetaAdmin(admin.ModelAdmin):
    search_fields = ["description"]
    autocomplete_fields = ["maintainers"]
    readonly_fields = ["source_provenances"]
    list_filter = [MaintainersFilter]


@admin.register(NixDerivation)
class NixDerivationAdmin(admin.ModelAdmin):
    search_fields = ["attribute", "name"]
    autocomplete_fields = ["outputs", "metadata", "dependencies"]
    readonly_fields = ["outputs", "metadata", "dependencies"]

    def get_search_results(self, request, queryset, search_term):
        queryset, use_distinct = super().get_search_results(
            request, queryset, search_term
        )

        try:
            queryset |= self.model.objects.filter(id=int(search_term))
        except ValueError:
            pass

        return queryset, use_distinct
