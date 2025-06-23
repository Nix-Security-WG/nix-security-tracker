from typing import Any

from django import forms

from shared.models import (
    Container,
    CveRecord,
    Description,
    NixDerivation,
    NixpkgsIssue,
)


class NixpkgsIssueForm(forms.ModelForm):
    template_name = "triage_issue_form_snippet.html"
    description_text = forms.CharField(widget=forms.Textarea)

    class Meta:  # type: ignore[override]
        model = NixpkgsIssue
        fields = [
            "cve",
            "derivations",
            "description_text",
            "status",
        ]
        error_messages = {
            "cve": {"required": "Please, select at least 1 CVE to create an issue."},
            "derivations": {
                "required": "Please, select at least 1 package to create an issue."
            },
        }

    def __init__(self, *args: Any, **kwargs: dict[str, Any]) -> None:
        self.cve_ids = kwargs.pop("cve_ids")
        self.pkg_ids = kwargs.pop("pkg_ids")

        super().__init__(*args, **kwargs)

        self.fields["description_text"].label = "Description"

        self.fields["cve"].choices = Container.objects.filter(
            id__in=self.cve_ids
        ).values_list("id", "id")
        self.fields["derivations"].choices = NixDerivation.objects.filter(
            id__in=self.pkg_ids
        ).values_list("id", "id")

    def save(self, *args: Any, **kwargs: dict[str, Any]) -> None:
        issue = NixpkgsIssue.objects.create(
            status=self.cleaned_data["status"],
            description=Description.objects.create(
                value=self.cleaned_data["description_text"]
            ),
        )
        issue.cve.set(CveRecord.objects.filter(id__in=self.cleaned_data["cve"]))
        issue.derivations.set(
            NixDerivation.objects.filter(id__in=self.cleaned_data["derivations"])
        )
        issue.save()
