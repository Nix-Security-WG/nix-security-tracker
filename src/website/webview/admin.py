# Register your models here.

from django.contrib import admin

from shared.models import (
    NixpkgsIssue,
    Description,
    CveRecord,
    NixChannel,
)


admin.site.register(NixChannel)


class CveRecordAdmin(admin.ModelAdmin):
    search_fields = ["cve_id"]


admin.site.register(CveRecord, CveRecordAdmin)


class DescriptionAdmin(admin.ModelAdmin):
    search_fields = ["value", "media"]


admin.site.register(Description, DescriptionAdmin)


class NixpkgsIssueAdmin(admin.ModelAdmin):
    autocomplete_fields = ["description", "cve"]
    readonly_fields = ["code"]
    exclude = ["number"]


admin.site.register(NixpkgsIssue, NixpkgsIssueAdmin)
