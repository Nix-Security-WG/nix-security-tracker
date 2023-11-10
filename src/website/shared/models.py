from typing import Type

from django.core.validators import RegexValidator
from django.db import models
from django.utils.translation import gettext_lazy as _


def text_length(choices: Type[models.TextChoices]):
    return max(map(len, choices.values))


class Organization(models.Model):
    """Class representing an organization, use for assigners and requesters."""

    uuid = models.UUIDField(primary_key=True)
    short_name = models.CharField(max_length=32, null=True, default=None)


class CveRecord(models.Model):
    """Class representing a CVE record."""

    class RecordState(models.TextChoices):
        PUBLISHED = "PUBLISHED", _("PUBLISHED")
        REJECTED = "REJECTED", _("REJECTED")

    state = models.CharField(
        max_length=text_length(RecordState),
        choices=RecordState.choices,
        default=RecordState.PUBLISHED,
    )
    cve_id = models.CharField(
        max_length=32, validators=[RegexValidator(regex="^CVE-[0-9]{4}-[0-9]{4,19}$")]
    )
    assigner = models.ForeignKey(
        Organization, related_name="assigned", on_delete=models.CASCADE
    )
    requester = models.ForeignKey(
        Organization, related_name="requested", null=True, on_delete=models.SET_NULL
    )
    serial = models.PositiveIntegerField(default=1)

    date_updated = models.DateTimeField(null=True, default=None)
    date_reserved = models.DateTimeField(null=True, default=None)
    date_published = models.DateTimeField(null=True, default=None)

    local_timestamp = models.DateTimeField(auto_now_add=True)


class Product(models.Model):
    vendor = models.CharField(max_length=512)


class SupportingMedia(models.Model):
    _type = models.CharField(max_length=256)
    base64 = models.BooleanField(default=False)
    value = models.TextField()


class Description(models.Model):
    """
    Class representing a description, typically for a vulnerability
    or an impact scenario.
    """

    lang = models.CharField(
        max_length=16,
        validators=[
            RegexValidator(
                "^[A-Za-z]{2,4}([_-][A-Za-z]{4})?([_-]([A-Za-z]{2}|[0-9]{3}))?$"
            )
        ],
        default="en",
    )
    value = models.TextField()
    media = models.ManyToManyField(SupportingMedia)


class Tag(models.Model):
    """Class representing a tag related to a CVE record."""

    value = models.CharField(max_length=128)


class Reference(models.Model):
    """Class representing a reference."""

    url = models.CharField(max_length=2048)
    name = models.CharField(max_length=512)
    tags = models.ManyToManyField(Tag)


class ProblemType(models.Model):
    """Class representing a problem type."""

    cwe_id = models.CharField(
        max_length=9, validators=[RegexValidator("^CWE-[1-9][0-9]*$")], null=True
    )
    description = models.ManyToManyField(Description)
    _type = models.CharField(max_length=128, null=True)
    references = models.ManyToManyField(Reference)


class Impact(models.Model):
    """Class representing an impact of a CVE."""

    capec_id = models.CharField(
        max_length=11, validators=[RegexValidator("^CAPEC-[1-9][0-9]{0,4}$")]
    )
    description = models.ManyToManyField(Description)


class Metric(models.Model):
    """Class representing an impact information related to a CVE record."""

    format = models.CharField(max_length=64)
    scenarios = models.ManyToManyField(Description)
    content = models.JSONField()


class Event(models.Model):
    """Class representing an event related to a CVE record."""

    time = models.DateTimeField()
    description = models.ForeignKey(Description, on_delete=models.CASCADE)


class Credit(models.Model):
    """Class representing a credit information related to a CVE record."""

    class Type(models.TextChoices):
        FINDER = "finder", _("finder")
        REPORTER = "reporter", _("reporter")
        ANALYST = "analyst", _("analyst")
        COORDINATOR = "coordinator", _("coordinator")
        REMEDIATION_DEVELOPER = "remediation developer", _("remediation developer")
        REMEDIATION_REVIEWER = "remediation reviewer", _("remediation reviewer")
        REMEDIATION_VERIFIER = "remediation verifier", _("remediation_verifier")
        TOOL = "tool", _("tool")
        SPONSOR = "sponsor", _("sponsor")
        OTHER = "other", _("other")

    _type = models.CharField(
        max_length=text_length(Type), choices=Type.choices, default=Type.FINDER
    )
    user = models.ForeignKey(
        Organization, null=True, default=None, on_delete=models.SET_NULL
    )
    description = models.ForeignKey(Description, on_delete=models.CASCADE)


class Platform(models.Model):
    name = models.CharField(max_length=1024)


class Version(models.Model):
    class Status(models.TextChoices):
        AFFECTED = "affected", _("affected")
        UNAFFECTED = "unaffected", _("unaffected")
        UNKNOWN = "unknown", _("unknown")

    status = models.CharField(
        max_length=text_length(Status), choices=Status.choices, default=Status.UNKNOWN
    )
    version_type = models.CharField(max_length=128, null=True)
    version = models.CharField(max_length=1024, null=True)
    less_than = models.CharField(max_length=1024, null=True)
    less_equal = models.CharField(max_length=1024, null=True)


class AffectedProduct(models.Model):
    class Status(models.TextChoices):
        AFFECTED = "affected", _("affected")
        UNAFFECTED = "unaffected", _("unaffected")
        UNKNOWN = "unknown", _("unknown")

    vendor = models.CharField(max_length=512, null=True)
    product = models.CharField(max_length=2048, null=True)
    collection_url = models.CharField(max_length=2048, null=True, default=None)
    package_name = models.CharField(max_length=2048, null=True, default=None)
    platforms = models.ManyToManyField(Platform)
    repo = models.CharField(max_length=2048, null=True, default=None)
    default_status = models.CharField(
        max_length=text_length(Status), choices=Status.choices, default=Status.UNKNOWN
    )
    versions = models.ManyToManyField(Version)


class Container(models.Model):
    """Class representing a container (i.e. structured data) related to a CVE record."""

    class Type(models.TextChoices):
        CNA = "cna", _("CVE Numbering Authority")
        ADP = "adp", _("Authorized Data Publisher")

    _type = models.CharField(max_length=3, choices=Type.choices, default=Type.CNA)

    cve = models.ForeignKey(CveRecord, on_delete=models.CASCADE)

    provider = models.ForeignKey(Organization, on_delete=models.CASCADE)
    title = models.CharField(max_length=256, null=True, default=None)
    descriptions = models.ManyToManyField(Description)
    date_assigned = models.DateTimeField(null=True, default=None)
    date_public = models.DateTimeField(null=True, default=None)

    affected = models.ManyToManyField(AffectedProduct)
    problem_types = models.ManyToManyField(ProblemType)
    references = models.ManyToManyField(Reference)
    metrics = models.ManyToManyField(Metric)
    configurations = models.ManyToManyField(
        Description, related_name="container_configurations"
    )
    workarounds = models.ManyToManyField(
        Description, related_name="container_workarounds"
    )
    solutions = models.ManyToManyField(Description, related_name="container_solutions")
    exploits = models.ManyToManyField(Description, related_name="container_exploits")
    timeline = models.ManyToManyField(Event)
    tags = models.ManyToManyField(Tag)
    credits = models.ManyToManyField(Credit)
    source = models.JSONField(default=dict)


class Cpe(models.Model):
    name = models.CharField(
        max_length=2048,
        null=True,
        default=None,
        validators=[
            RegexValidator(
                "([c][pP][eE]:/[AHOaho]?(:[A-Za-z0-9._\\-~%]*){0,6})|(cpe:2\\.3:[aho*\\"
                "-](:(((\\?*|\\*?)([a-zA-Z0-9\\-._]|(\\\\[\\\\*?!\"#$%&'()+,/:;<=>@\\["
                "\\]\\^`{|}~]))+(\\?*|\\*?))|[*\\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}"
                '|[0-9]{3}))?)|[*\\-]))(:(((\\?*|\\*?)([a-zA-Z0-9\\-._]|(\\\\[\\\\*?!"'
                "#$%&'()+,/:;<=>@\\[\\]\\^`{|}~]))+(\\?*|\\*?))|[*\\-])){4})"
            )
        ],
    )

    # Reverse relations
    _product = models.ForeignKey(
        AffectedProduct, related_name="cpes", on_delete=models.CASCADE
    )


class Module(models.Model):
    name = models.CharField(max_length=4096)

    # Reverse relations
    _product = models.ForeignKey(
        AffectedProduct, related_name="modules", on_delete=models.CASCADE
    )


class ProgramFile(models.Model):
    name = models.CharField(max_length=1024)

    # Reverse relations
    _product = models.ForeignKey(
        AffectedProduct, related_name="program_files", on_delete=models.CASCADE
    )


class ProgramRoutine(models.Model):
    name = models.CharField(max_length=4096)

    # Reverse relations
    _product = models.ForeignKey(
        AffectedProduct, related_name="program_routines", on_delete=models.CASCADE
    )


###
#
# Nix related models
#
##


class NixIssue(models.Model):
    """The Nixpkgs version of a cve."""

    class IssueStatus(models.TextChoices):
        UNKNOWN = "U", _("unknown")
        AFFECTED = "A", _("affected")
        NOTAFFECTED = "NA", _("notaffected")
        NOTFORUS = "O", _("notforus")
        WONTFIX = "W", _("wontfix")

    cve = models.ManyToManyField(CveRecord)
    description = models.ForeignKey(Description, on_delete=models.PROTECT)
    status = models.CharField(
        max_length=text_length(IssueStatus),
        choices=IssueStatus.choices,
        default=IssueStatus.UNKNOWN,
    )


class NixEvent(models.Model):
    class EventType(models.TextChoices):
        ISSUED = "I", _("issue opened")
        PR_OPENED = "P", _("PR opened")
        PR_MERGED = "M", _("PR merged")

    issue = models.ForeignKey(NixIssue, on_delete=models.CASCADE)
    reference = models.TextField()


class NixAdvisory(models.Model):
    class AdvisoryStatus(models.TextChoices):
        DRAFT = "DRAFT", _("draft")
        RELEASED = "RELEASED", _("released")
        REVISED = "REVISED", _("revised")

    class AdvisorySeverity(models.TextChoices):
        UNKNOWN = "UNKNOWN", _("unknown")
        LOW = "LOW", _("low")
        MEDIUM = "MEDIUM", _("medium")
        HIGH = "HIGH", _("high")
        CRITICAL = "CRITICAL", _("critical")

    issues = models.ManyToManyField(NixIssue)
