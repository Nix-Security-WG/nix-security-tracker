import json
import re
from datetime import datetime
from typing import Any

from django.utils.timezone import make_aware
from requests import get

from shared import models


def make_organization(
    uuid: str | None, short_name: str | None = None
) -> models.Organization | None:
    if uuid is None:
        return None

    org, _ = models.Organization.objects.get_or_create(
        uuid=uuid, defaults={"short_name": short_name}
    )

    return org


def make_date(date: str | None) -> datetime | None:
    if date is None:
        return None

    time = datetime.fromisoformat(date)

    if time.tzinfo is None:
        return make_aware(time)

    return time


def make_media(data: dict[str, str]) -> models.SupportingMedia:
    ctx: dict[str, Any] = dict()
    ctx["_type"] = data["type"]
    ctx["base64"] = data["base64"]
    ctx["value"] = data["value"]

    return models.SupportingMedia.objects.create(**ctx)


def make_description(data: dict[str, Any]) -> models.Description:
    ctx: dict[str, Any] = dict()
    ctx["lang"] = data["lang"]
    ctx["value"] = data["value"]

    obj = models.Description.objects.create(**ctx)
    obj.media.set(map(make_media, data.get("supportingMedia", [])))

    return obj


def make_tag(name: str) -> models.Tag:
    obj, _ = models.Tag.objects.get_or_create(value=name)

    return obj


def make_reference(data: dict[str, Any]) -> models.Reference:
    ctx: dict[str, Any] = dict()
    ctx["url"] = data["url"]
    ctx["name"] = data.get("name", "")

    obj = models.Reference.objects.create(**ctx)
    obj.tags.set(map(make_tag, data.get("tags", [])))

    return obj


def make_problem_type(data: dict[str, Any]) -> models.ProblemType:
    ctx: dict[str, Any] = dict()
    ctx["cwe_id"] = data.get("cweId")
    ctx["_type"] = data.get("type")

    obj = models.ProblemType.objects.create(**ctx)
    obj.description.set(
        [make_description({"lang": data["lang"], "value": data["description"]})]
    )
    obj.references.set(map(make_reference, data.get("references", [])))

    return obj


def to_camel_case(name: str) -> str:
    """
    >>> to_camel_case("abc_def")
    abcDef
    """
    from re import sub

    s = sub(r"(_|-)+", " ", name).title().replace(" ", "")
    return "".join([s[0].lower(), s[1:]])


def make_metric(data: dict[str, Any]) -> models.Metric:
    ctx: dict[str, Any] = dict()
    ctx["format"] = "cvssV3_1"
    raw_cvss = data.get("cvssV3_1", {})
    ctx["raw_cvss_json"] = raw_cvss

    if raw_cvss:
        ctx["scope"] = raw_cvss.get("scope")
        ctx["vector_string"] = raw_cvss.get("vectorString")
        ctx["base_score"] = int(raw_cvss.get("baseScore"))

        vector_fields = (
            "attack_complexity",
            "attack_vector",
            "availability_impact",
            "confidentiality_impact",
            "integrity_impact",
            "privileges_required",
            "user_interaction",
        )

        for field in vector_fields:
            ctx[field] = raw_cvss.get(to_camel_case(field))

        # TODO: Parse vector string into the various elements
        # and verify conformance with the "parsed" fields for us.

    obj = models.Metric.objects.create(**ctx)
    obj.scenarios.set(map(make_description, data.get("scenarios", [])))

    return obj


def make_event(data: dict[str, Any]) -> models.Event:
    ctx: dict[str, Any] = dict()
    ctx["time"] = make_date(data["time"])
    ctx["description"] = make_description(data)

    return models.Event.objects.create(**ctx)


def make_credit(data: dict[str, Any]) -> models.Credit:
    ctx: dict[str, Any] = dict()
    ctx["_type"] = data.get("type", "finder")
    ctx["user"] = make_organization(uuid=data.get("user"))
    ctx["description"] = make_description(data)

    return models.Credit.objects.create(**ctx)


def make_platform(name: str) -> models.Platform:
    obj, _ = models.Platform.objects.get_or_create(name=name)

    return obj


def make_version(data: dict[str, Any]) -> models.Version:
    ctx: dict[str, Any] = dict()
    ctx["version"] = data.get("version")
    ctx["status"] = data.get("status", models.Version.Status.UNKNOWN)
    ctx["version_type"] = data.get("versionType")
    ctx["less_than"] = data.get("lessThan")
    ctx["less_equal"] = data.get("lessThanOrEqual")

    return models.Version.objects.create(**ctx)


def make_cpe(name: str) -> models.Cpe:
    obj, _ = models.Cpe.objects.get_or_create(name=name)

    return obj


def make_module(name: str) -> models.Module:
    obj, _ = models.Module.objects.get_or_create(name=name)

    return obj


def make_program_file(name: str) -> models.ProgramFile:
    obj, _ = models.ProgramFile.objects.get_or_create(name=name)

    return obj


def make_program_routine(name: str) -> models.ProgramRoutine:
    obj, _ = models.ProgramRoutine.objects.get_or_create(name=name)

    return obj


def make_affected_product(data: dict[str, Any]) -> models.AffectedProduct:
    ctx: dict[str, Any] = dict()
    ctx["vendor"] = data.get("vendor")
    ctx["product"] = data.get("product")
    ctx["collection_url"] = data.get("collectionURL")
    ctx["package_name"] = data.get("packageName")
    ctx["repo"] = data.get("repo")
    ctx["default_status"] = data.get(
        "defaultStatus", models.AffectedProduct.Status.UNKNOWN
    )

    obj = models.AffectedProduct.objects.create(**ctx)
    obj.platforms.set(map(make_platform, data.get("platforms", [])))
    obj.versions.set(map(make_version, data.get("versions", [])))
    obj.cpes.set(map(make_cpe, data.get("cpes", [])))
    obj.modules.set(map(make_module, data.get("modules", [])))
    obj.program_files.set(map(make_program_file, data.get("programFiles", [])))
    obj.program_routines.set(map(make_program_routine, data.get("programRoutines", [])))

    return obj


def make_cve_record(
    data: dict[str, Any], cve: models.CveRecord | None = None
) -> models.CveRecord:
    if cve is None:
        cve = models.CveRecord()

    cve.cve_id = data["cveId"]
    cve.state = data["state"]

    org = make_organization(
        uuid=data["assignerOrgId"], short_name=data.get("assignerShortName")
    )

    assert org is not None, "Organisation cannot be empty"

    cve.assigner = org
    cve.requester = make_organization(uuid=data.get("requesterUserId"))

    cve.date_reserved = make_date(data.get("dateReserved"))
    cve.date_updated = make_date(data.get("dateUpdated"))
    cve.date_published = make_date(data.get("datePublished"))
    cve.serial = data.get("serial", 1)

    return cve


def make_container(
    data: dict[str, Any], _type: str, cve: models.CveRecord
) -> models.Container:
    ctx: dict[str, Any] = {"_type": _type, "cve": cve}
    ctx["provider"] = make_organization(
        uuid=data["providerMetadata"].get("orgId"),
        short_name=data["providerMetadata"].get("shortName"),
    )
    ctx["title"] = data.get("title", "")

    if _type == models.Container.Type.CNA:
        ctx["date_assigned"] = make_date(data.get("dateAssigned"))

    ctx["date_public"] = make_date(data.get("datePublic"))
    ctx["source"] = data.get("source", dict())

    obj = models.Container.objects.create(**ctx)
    obj.descriptions.set(map(make_description, data.get("descriptions", [])))

    obj.affected.set(map(make_affected_product, data.get("affected", [])))
    # Map problem types from the terrible definition to our models
    problems = [
        desc
        for problem in data.get("problemTypes", [])
        for desc in problem.get("description", [])
    ]
    obj.problem_types.set(map(make_problem_type, problems))
    obj.references.set(map(make_reference, data.get("references", [])))
    obj.metrics.set(map(make_metric, data.get("metrics", [])))
    obj.configurations.set(map(make_description, data.get("configurations", [])))
    obj.workarounds.set(map(make_description, data.get("workarounds", [])))
    obj.solutions.set(map(make_description, data.get("solutions", [])))
    obj.exploits.set(map(make_description, data.get("exploits", [])))
    obj.timeline.set(map(make_event, data.get("timeline", [])))
    obj.tags.set(map(make_tag, data.get("tags", [])))
    obj.credits.set(map(make_credit, data.get("credits", [])))

    return obj


def make_cve(
    data: dict[str, Any],
    record: models.CveRecord | None = None,
    triaged: bool = False,
) -> models.CveRecord:
    cve = make_cve_record(data["cveMetadata"], cve=record)
    cve.triaged = triaged
    cve.save()

    if record is not None:
        # TODO: Remove stale data to prevent overgrowth
        pass

    make_container(data["containers"]["cna"], _type=models.Container.Type.CNA, cve=cve)

    for adp in data["containers"].get("adp", []):
        make_container(adp, _type=models.Container.Type.ADP, cve=cve)

    return cve


def fetch_cve_gh(cve_id: str) -> models.CveRecord | None:
    """Fetch a cve from the cvelistV5 github repository."""

    m = re.fullmatch(
        r"^CVE-(?P<year>[0-9]{4})-(?P<prefix>[0-9]{1,15})[0-9]{3}$", cve_id
    )

    if m is None:
        raise ValueError("Not a correct CVE Id")

    r = get(
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"
        f"{m.group('year')}/{m.group('prefix')}xxx/{cve_id}.json"
    )

    if r.status_code != 200:
        raise RuntimeError(f"Error during GET request: {r.status_code}\n{r.text}")

    data = json.loads(r.text)

    return make_cve(data)
