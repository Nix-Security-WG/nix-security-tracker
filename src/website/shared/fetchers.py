import json
import re
from datetime import datetime
from typing import Any, Dict, Optional

from django.utils.timezone import make_aware
from requests import get

from shared import models


def mkOrganization(
    uuid: Optional[str], short_name: Optional[str] = None
) -> Optional[models.Organization]:
    if uuid is None:
        return None

    org, _ = models.Organization.objects.get_or_create(uuid=uuid)

    if org.short_name is None:
        org.short_name = short_name
        org.save()

    return org


def mkDate(date: Optional[str]) -> Optional[datetime]:
    if date is None:
        return None

    time = datetime.fromisoformat(date)

    if time.tzinfo is None:
        return make_aware(time)

    return time


def mkMedia(data: Dict[str, str]) -> models.SupportingMedia:
    ctx: Dict[str, Any] = dict()
    ctx["_type"] = data["type"]
    ctx["base64"] = data["base64"]
    ctx["value"] = data["value"]

    return models.SupportingMedia.objects.create(**ctx)


def mkDescription(data: Dict[str, Any]) -> models.Description:
    ctx: Dict[str, Any] = dict()
    ctx["lang"] = data["lang"]
    ctx["value"] = data["value"]

    obj = models.Description.objects.create(**ctx)
    obj.media.set(map(mkMedia, data.get("supportingMedia", [])))

    return obj


def mkTag(name: str) -> models.Tag:
    obj, _ = models.Tag.objects.get_or_create(value=name)

    return obj


def mkReference(data: Dict[str, Any]) -> models.Reference:
    ctx: Dict[str, Any] = dict()
    ctx["url"] = data["url"]
    ctx["name"] = data.get("name", "")

    obj = models.Reference.objects.create(**ctx)
    obj.tags.set(map(mkTag, data.get("tags", [])))

    return obj


def mkProblemType(data: Dict[str, Any]) -> models.ProblemType:
    ctx: Dict[str, Any] = dict()
    ctx["cwe_id"] = data.get("cweId")
    ctx["_type"] = data.get("type")

    obj = models.ProblemType.objects.create(**ctx)
    obj.description.set(
        [mkDescription({"lang": data["lang"], "value": data["description"]})]
    )
    obj.references.set(map(mkReference, data.get("references", [])))

    return obj


def mkMetric(data: Dict[str, Any]) -> models.Metric:
    ctx: Dict[str, Any] = dict()
    ctx["format"] = "cvssV3_1"
    ctx["content"] = data.get("cvssV3_1", {})

    obj = models.Metric.objects.create(**ctx)
    obj.scenarios.set(map(mkDescription, data.get("scenarios", [])))

    return obj


def mkEvent(data: Dict[str, Any]) -> models.Event:
    ctx: Dict[str, Any] = dict()
    ctx["time"] = mkDate(data["time"])
    ctx["description"] = mkDescription(data)

    return models.Event.objects.create(**ctx)


def mkCredit(data: Dict[str, Any]) -> models.Credit:
    ctx: Dict[str, Any] = dict()
    ctx["_type"] = data.get("type", "finder")
    ctx["user"] = mkOrganization(uuid=data.get("user"))
    ctx["description"] = mkDescription(data)

    return models.Credit.objects.create(**ctx)


def mkPlatform(name: str) -> models.Platform:
    obj, _ = models.Platform.objects.get_or_create(name=name)

    return obj


def mkVersion(data: Dict[str, Any]) -> models.Version:
    ctx: Dict[str, Any] = dict()
    ctx["version"] = data.get("version")
    ctx["status"] = data.get("status", models.Version.Status.UNKNOWN)
    ctx["version_type"] = data.get("versionType")
    ctx["less_than"] = data.get("lessThan")
    ctx["less_equal"] = data.get("lessThanOrEqual")

    return models.Version.objects.create(**ctx)


def mkCpe(name: str) -> models.Cpe:
    obj, _ = models.Cpe.objects.get_or_create(name=name)

    return obj


def mkModule(name: str) -> models.Module:
    obj, _ = models.Module.objects.get_or_create(name=name)

    return obj


def mkProgramFile(name: str) -> models.ProgramFile:
    obj, _ = models.ProgramFile.objects.get_or_create(name=name)

    return obj


def mkProgramRoutine(name: str) -> models.ProgramRoutine:
    obj, _ = models.ProgramRoutine.objects.get_or_create(name=name)

    return obj


def mkAffectedProduct(data: Dict[str, Any]) -> models.AffectedProduct:
    ctx: Dict[str, Any] = dict()
    ctx["vendor"] = data.get("vendor")
    ctx["product"] = data.get("product")
    ctx["collection_url"] = data.get("collectionURL")
    ctx["package_name"] = data.get("packageName")
    ctx["repo"] = data.get("repo")
    ctx["default_status"] = data.get(
        "defaultStatus", models.AffectedProduct.Status.UNKNOWN
    )

    obj = models.AffectedProduct.objects.create(**ctx)
    obj.platforms.set(map(mkPlatform, data.get("platforms", [])))
    obj.versions.set(map(mkVersion, data.get("versions", [])))
    obj.cpes.set(map(mkCpe, data.get("cpes", [])))
    obj.modules.set(map(mkModule, data.get("modules", [])))
    obj.program_files.set(map(mkProgramFile, data.get("programFiles", [])))
    obj.program_routines.set(map(mkProgramRoutine, data.get("programRoutines", [])))

    return obj


def mkCveRecord(
    data: Dict[str, Any], cve: Optional[models.CveRecord] = None
) -> models.CveRecord:
    if cve is None:
        cve = models.CveRecord()

    cve.cve_id = data["cveId"]
    cve.state = data["state"]

    org = mkOrganization(
        uuid=data["assignerOrgId"], short_name=data.get("assignerShortName")
    )

    assert org is not None, "Organisation cannot be empty"

    cve.assigner = org
    cve.requester = mkOrganization(uuid=data.get("requesterUserId"))

    cve.date_reserved = mkDate(data.get("dateReserved"))
    cve.date_updated = mkDate(data.get("dateUpdated"))
    cve.date_published = mkDate(data.get("datePublished"))
    cve.serial = data.get("serial", 1)

    return cve


def mkContainer(
    data: Dict[str, Any], _type: str, cve: models.CveRecord
) -> models.Container:
    ctx: Dict[str, Any] = {"_type": _type, "cve": cve}
    ctx["provider"] = mkOrganization(
        uuid=data["providerMetadata"].get("orgId"),
        short_name=data["providerMetadata"].get("shortName"),
    )
    ctx["title"] = data.get("title", "")

    if _type == models.Container.Type.CNA:
        ctx["date_assigned"] = mkDate(data.get("dateAssigned"))

    ctx["date_public"] = mkDate(data.get("datePublic"))
    ctx["source"] = data.get("source", dict())

    obj = models.Container.objects.create(**ctx)
    obj.descriptions.set(map(mkDescription, data.get("descriptions", [])))

    obj.affected.set(map(mkAffectedProduct, data.get("affected", [])))
    # Map problem types from the terrible definition to our models
    problems = [
        desc
        for problem in data.get("problemTypes", [])
        for desc in problem.get("description", [])
    ]
    obj.problem_types.set(map(mkProblemType, problems))
    obj.references.set(map(mkReference, data.get("references", [])))
    obj.metrics.set(map(mkMetric, data.get("metrics", [])))
    obj.configurations.set(map(mkDescription, data.get("configurations", [])))
    obj.workarounds.set(map(mkDescription, data.get("workarounds", [])))
    obj.solutions.set(map(mkDescription, data.get("solutions", [])))
    obj.exploits.set(map(mkDescription, data.get("exploits", [])))
    obj.timeline.set(map(mkEvent, data.get("timeline", [])))
    obj.tags.set(map(mkTag, data.get("tags", [])))
    obj.credits.set(map(mkCredit, data.get("credits", [])))

    return obj


def mkCve(
    data: Dict[str, Any],
    record: Optional[models.CveRecord] = None,
    triaged: bool = False,
) -> models.CveRecord:
    cve = mkCveRecord(data["cveMetadata"], cve=record)
    cve.triaged = triaged
    cve.save()

    if record is not None:
        # TODO: Remove stale data to prevent overgrowth
        pass

    mkContainer(data["containers"]["cna"], _type=models.Container.Type.CNA, cve=cve)

    for adp in data["containers"].get("adp", []):
        mkContainer(adp, _type=models.Container.Type.ADP, cve=cve)

    return cve


def fetch_cve_gh(cve_id: str) -> Optional[models.CveRecord]:
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

    return mkCve(data)
