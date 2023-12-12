import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Generator

from asgiref.sync import sync_to_async
from dataclass_wizard import DumpMixin, JSONWizard, LoadMixin

from shared.models.nix_evaluation import (
    NixDerivation,
    NixDerivationMeta,
    NixDerivationOutput,
    NixEvaluation,
    NixLicense,
    NixMaintainer,
    NixOutput,
    NixPlatform,
    NixStorePathOutput,
)


@dataclass
class MaintainerAttribute(JSONWizard):
    name: str
    github: str | None = None
    githubId: int | None = None
    email: str | None = None
    matrix: str | None = None


@dataclass
class LicenseAttribute(JSONWizard):
    fullName: str | None = None
    deprecated: bool = False
    free: bool = False
    redistributable: bool = False
    shortName: str | None = None
    spdxId: str | None = None
    url: str | None = None


@dataclass
class MetadataAttribute(JSONWizard, LoadMixin, DumpMixin):
    outputsToInstall: list[str] = field(default_factory=list)
    available: bool = True
    broken: bool = False
    unfree: bool = False
    unsupported: bool = False
    insecure: bool = False
    mainProgram: str | None = None
    position: str | None = None
    homepage: str | None = None
    description: str | None = None
    name: str | None = None
    maintainers: list[MaintainerAttribute] = field(default_factory=list)
    license: list[LicenseAttribute] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    knownVulnerabilities: list[str] = field(default_factory=list)

    def __pre_as_dict__(self):
        linearized_maintainers = []
        for maintainer in self.maintainers:
            if maintainer.get("scope") is not None:  # pyright: ignore generalTypeIssue
                linearized_maintainers.extend(
                    maintainer.get("members", [])  # pyright: ignore generalTypeIssue
                )
            else:
                linearized_maintainers.append(maintainer)
        self.maintainers = linearized_maintainers


@dataclass
class EvaluatedAttribute(JSONWizard):
    """
    This is a totally evaluated attribute.
    """

    attr: str
    attrPath: list[str]
    name: str
    drvPath: str
    # drv -> list of outputs.
    inputDrvs: dict[str, list[str]]
    meta: MetadataAttribute | None
    outputs: dict[str, str]
    system: str


@dataclass
class PartialEvaluatedAttribute:
    """
    This represents a potentially invalid partially
    evaluated attribute for some reasons.
    Open the `evaluation` for more or read the `error`.
    """

    attr: str
    attrPath: list[str]
    error: str | None = None
    evaluation: EvaluatedAttribute | None = None


def parse_total_evaluation(raw: dict[str, Any]):
    # Various fixups to deal with... things.
    # my lord...
    if raw.get("meta", {}) is None:
        print(raw)

    if (
        raw.get("meta", {}) is not None
        and "license" in raw.get("meta", {})
        and not isinstance(raw.get("meta", {})["license"], list)
    ):
        if raw["meta"]["license"] == "unknown":
            raw["meta"]["license"] = []
        elif isinstance(raw["meta"]["license"], str):
            raw["meta"]["license"] = [{"fullName": raw["meta"]["license"]}]
        else:
            raw["meta"]["license"] = [raw["meta"]["license"]]

    new_maintainers = []
    if (
        raw.get("meta", {}) is not None
        and "maintainers" in raw.get("meta", {})
        and isinstance(raw.get("meta", {})["maintainers"], list)
    ):
        for maintainer in raw.get("meta", {})["maintainers"]:
            if maintainer.get("scope") is not None:
                new_maintainers.extend(maintainer["members"])
            else:
                new_maintainers.append(maintainer)
        raw["meta"]["maintainers"] = new_maintainers

    return EvaluatedAttribute.from_dict(raw)


def parse_evaluation_result(line) -> PartialEvaluatedAttribute:
    raw = json.loads(line)
    if raw.get("error") is not None:
        return PartialEvaluatedAttribute(**raw, evaluation=None)
    else:
        return PartialEvaluatedAttribute(
            attr=raw.get("attr"),
            attrPath=raw.get("attrPath"),
            error=None,
            evaluation=parse_total_evaluation(raw),
        )


def parse_evaluation_results(lines) -> Generator[PartialEvaluatedAttribute, None, None]:
    for line in lines:
        yield parse_evaluation_result(line)


class AsyncAttributeIngester:
    """
    This is a class to perform ingestion
    of a specific **evaluated** attribute.
    """

    def __init__(self, evaluation: EvaluatedAttribute):
        self.evaluation = evaluation

    async def initialize(self):
        self.maintainers = await sync_to_async(
            lambda: list(NixMaintainer.objects.all())
        )()
        self.licenses = await sync_to_async(lambda: list(NixLicense.objects.all()))()
        platforms = await sync_to_async(lambda: list(NixPlatform.objects.all()))()
        outputs = await sync_to_async(lambda: list(NixOutput.objects.all()))()
        store_path_outputs = await sync_to_async(
            lambda: list(NixStorePathOutput.objects.all())
        )()
        self.platforms = {model.system_double: model for model in platforms}
        self.outputs = {model.output_name: model for model in outputs}
        self.store_path_outputs = {
            (model.output_name, model.store_path): model for model in store_path_outputs
        }

    async def ingest_maintainers(
        self, maintainers: list[MaintainerAttribute]
    ) -> list[NixMaintainer]:
        ms = []
        seen = set()
        for m in maintainers:
            # Maintainers without a GitHub or a GitHub ID cannot be reconciled.
            # This unfortunately creates a partial view of all maintainers of a
            # given package. If you want to fix this, you can start from
            # looking around https://github.com/NixOS/nixpkgs/pull/273220.
            if m.github is None or m.githubId is None:
                continue

            # Duplicate...
            if m.githubId in seen:
                continue

            ms.append(
                NixMaintainer.objects.aupdate_or_create(
                    defaults={
                        "github": m.github,
                        "email": m.email,
                        "matrix": m.matrix,
                        "name": m.name,
                    },
                    github_id=m.githubId,
                )
            )
            seen.add(m.githubId)

        return [obj for obj, _ in (await asyncio.gather(*ms))]

    async def ingest_licenses(
        self, licenses: list[LicenseAttribute]
    ) -> list[NixLicense]:
        lics = []
        seen = set()

        for lic in licenses:
            # Duplicate...
            if lic.url in seen:
                continue
            lics.append(
                NixLicense.objects.aget_or_create(
                    defaults={
                        "deprecated": lic.deprecated,
                        "free": lic.free,
                        "redistributable": lic.redistributable,
                    },
                    full_name=lic.fullName,
                    short_name=lic.shortName,
                    spdx_id=lic.spdxId,
                    url=lic.url,
                )
            )
            seen.add(lic.url)

        return [obj for obj, _ in (await asyncio.gather(*lics))]

    async def ingest_platforms(self, platforms: list[str]) -> list[NixPlatform]:
        ps = []
        for p in platforms:
            if p not in self.platforms:
                self.platforms[p], _ = await NixPlatform.objects.aget_or_create(
                    system_double=p
                )

            ps.append(self.platforms[p])

        return ps

    async def ingest_meta(self) -> NixDerivationMeta:
        metadata = self.evaluation.meta
        assert (
            metadata is not None
        ), "invalid ingest_meta call to an invalid metadata attribute"
        maintainers = self.ingest_maintainers(metadata.maintainers)
        platforms = self.ingest_platforms(metadata.platforms)
        if isinstance(metadata.license, list):
            licenses = self.ingest_licenses(metadata.license)
        else:
            licenses = self.ingest_licenses([metadata.license])
        meta = await NixDerivationMeta.objects.acreate(
            name=metadata.name,
            insecure=metadata.insecure,
            available=metadata.available,
            broken=metadata.broken,
            unfree=metadata.unfree,
            unsupported=metadata.unsupported,
            homepage=metadata.homepage,
            description=metadata.description,
            main_program=metadata.mainProgram,
            position=metadata.position,
            known_vulnerabilities=metadata.knownVulnerabilities,
        )
        # Wait for those queries to land.
        maintainers, platforms, licenses = await asyncio.gather(
            maintainers, platforms, licenses
        )
        # Wait for adding those M2M.
        await asyncio.gather(
            meta.maintainers.aadd(*maintainers),
            meta.licenses.aadd(*licenses),
            meta.platforms.aadd(*platforms),
        )
        return meta

    async def ingest_outputs(self) -> list[NixStorePathOutput]:
        pending = {}
        for key, value in self.evaluation.outputs.items():
            if (key, value) not in self.store_path_outputs or (
                key,
                value,
            ) not in pending:
                pending[(key, value)] = NixStorePathOutput.objects.aget_or_create(
                    output_name=key, store_path=value
                )

        return [obj for obj, _ in (await asyncio.gather(*pending.values()))]

    async def ingest_dependencies(self) -> list[NixDerivationOutput]:
        drvs = []
        # TODO: improve concurrency of the loop here
        # with fine-grained async dependencies.
        for drvpath, outputs_raw in self.evaluation.inputDrvs.items():
            outputs = []
            for output in outputs_raw:
                if output in self.outputs:
                    outputs.append(self.outputs.get(output))
                else:
                    output_model, _ = await NixOutput.objects.aget_or_create(
                        output_name=output
                    )
                    outputs.append(output_model)
                    self.outputs[output] = output_model
            drv_out = await NixDerivationOutput.objects.acreate(derivation_path=drvpath)
            await drv_out.outputs.aadd(*outputs)

        return drvs

    async def ingest_derivation_shell(
        self,
        parent_evaluation: NixEvaluation,
        metadata: NixDerivationMeta | None = None,
    ) -> NixDerivation:
        return await NixDerivation.objects.acreate(
            attribute=self.evaluation.attr,
            derivation_path=self.evaluation.drvPath,
            name=self.evaluation.name,
            metadata=metadata,
            system=self.platforms[self.evaluation.system],
            parent_evaluation=parent_evaluation,
        )

    async def ingest(self, parent_evaluation: NixEvaluation) -> NixDerivation:
        sub_ingestions = [
            self.ingest_dependencies(),
            self.ingest_outputs(),
        ]

        results = await asyncio.gather(*sub_ingestions)
        metadata = None
        if self.evaluation.meta is not None:
            metadata = await self.ingest_meta()
        derivation = await self.ingest_derivation_shell(parent_evaluation, metadata)
        await derivation.dependencies.aadd(*results[0])
        await derivation.outputs.aadd(*results[1])

        return derivation
