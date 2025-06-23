import json
import logging
import time
from collections.abc import Callable, Generator, Iterable
from dataclasses import dataclass, field
from itertools import chain
from typing import Any, TypeVar

from dataclass_wizard import DumpMixin, JSONWizard, LoadMixin
from django.db.models import Model
from django.db.utils import IntegrityError

from shared.models.nix_evaluation import (
    NixDerivation,
    NixDerivationMeta,
    NixDerivationOutput,
    NixEvaluation,
    NixLicense,
    NixMaintainer,
    NixOutput,
    NixStorePathOutput,
)

T = TypeVar("T", bound=Model)
DeferredThrough = Callable[[int], list[T]]
logger = logging.getLogger(__name__)


@dataclass
class MaintainerAttribute(JSONWizard):
    name: str
    github: str | None = None
    github_id: int | None = None
    email: str | None = None
    matrix: str | None = None


@dataclass
class LicenseAttribute(JSONWizard):
    full_name: str | None = None
    deprecated: bool = False
    free: bool = False
    redistributable: bool = False
    short_name: str | None = None
    spdx_id: str | None = None
    url: str | None = None


@dataclass
class MetadataAttribute(JSONWizard, LoadMixin, DumpMixin):
    outputs_to_install: list[str] = field(default_factory=list)
    available: bool = True
    broken: bool = False
    unfree: bool = False
    unsupported: bool = False
    insecure: bool = False
    main_program: str | None = None
    position: str | None = None
    homepage: str | None = None
    description: str | None = None
    name: str | None = None
    maintainers: list[MaintainerAttribute] = field(default_factory=list)
    license: list[LicenseAttribute] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    known_vulnerabilities: list[str] = field(default_factory=list)

    def __pre_as_dict__(self) -> None:
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
    attr_path: list[str]
    name: str
    drv_path: str
    # drv -> list of outputs.
    input_drvs: dict[str, list[str]]
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
    attr_path: list[str]
    error: str | None = None
    evaluation: EvaluatedAttribute | None = None


def parse_total_evaluation(raw: dict[str, Any]) -> EvaluatedAttribute:
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


def parse_evaluation_result(line: str) -> PartialEvaluatedAttribute:
    raw = json.loads(line)
    return PartialEvaluatedAttribute(
        attr=raw.get("attr"),
        attr_path=raw.get("attr_path"),
        error=None,
        evaluation=parse_total_evaluation(raw) if raw.get("error") is None else None,
    )


def parse_evaluation_results(
    lines: Iterable[str],
) -> Generator[PartialEvaluatedAttribute]:
    for line in lines:
        yield parse_evaluation_result(line)


def bulkify[T](
    gen: Generator[tuple[EvaluatedAttribute, list[T]]],
) -> Generator[tuple[str, list[T]]]:
    for origin, elements in gen:
        yield (origin.drv_path, elements)


class SyncBatchAttributeIngester:
    """
    This is a class to perform ingestion
    of a bunch of **evaluated** attribute synchronously.
    """

    def __init__(self, evaluations: list[EvaluatedAttribute]) -> None:
        self.evaluations = evaluations

    def initialize(self) -> None:
        self.maintainers = list(NixMaintainer.objects.all())
        self.licenses = list(NixLicense.objects.all())
        outputs = list(NixOutput.objects.all())
        self.outputs = {model.output_name: model for model in outputs}

    def ingest_maintainers(
        self, maintainers: list[MaintainerAttribute]
    ) -> list[NixMaintainer]:
        ms = []
        seen = set()
        for m in maintainers:
            # Maintainers without a GitHub or a GitHub ID cannot be reconciled.
            # This unfortunately creates a partial view of all maintainers of a
            # given package. If you want to fix this, you can start from
            # looking around https://github.com/NixOS/nixpkgs/pull/273220.
            if m.github is None or m.github_id is None:
                continue

            # Duplicate...
            if m.github_id in seen:
                continue

            ms.append(
                NixMaintainer.objects.update_or_create(
                    defaults={
                        "github": m.github,
                        "email": m.email,
                        "matrix": m.matrix,
                        "name": m.name,
                    },
                    github_id=m.github_id,
                )
            )
            seen.add(m.github_id)

        return [obj for obj, _ in ms]

    def ingest_licenses(self, licenses: list[LicenseAttribute]) -> list[NixLicense]:
        lics = []
        seen = set()

        for lic in licenses:
            if lic.spdx_id is None or lic.spdx_id in seen:
                continue

            lics.append(
                NixLicense.objects.get_or_create(
                    defaults={
                        "deprecated": lic.deprecated,
                        "free": lic.free,
                        "redistributable": lic.redistributable,
                        "full_name": lic.full_name,
                        "short_name": lic.short_name,
                        "url": lic.url,
                    },
                    spdx_id=lic.spdx_id,
                )
            )
            seen.add(lic.spdx_id)

        return [obj for obj, _ in lics]

    def ingest_meta(
        self, evaluation: EvaluatedAttribute
    ) -> tuple[
        NixDerivationMeta,
        DeferredThrough[NixMaintainer],
        DeferredThrough[NixLicense],
    ]:
        metadata = evaluation.meta
        assert metadata is not None, (
            "invalid ingest_meta call to an invalid metadata attribute"
        )

        maintainers = self.ingest_maintainers(metadata.maintainers)
        if isinstance(metadata.license, list):
            licenses = self.ingest_licenses(metadata.license)
        else:
            licenses = self.ingest_licenses([metadata.license])
        meta = NixDerivationMeta(
            name=metadata.name,
            insecure=metadata.insecure,
            available=metadata.available,
            broken=metadata.broken,
            unfree=metadata.unfree,
            unsupported=metadata.unsupported,
            homepage=metadata.homepage,
            description=metadata.description,
            main_program=metadata.main_program,
            position=metadata.position,
            known_vulnerabilities=metadata.known_vulnerabilities,
        )

        # Those thunks are here to delay the evaluation of the M2M throughs.
        def thunk_maintainers_throughs(
            meta_pk: int,
        ) -> list[NixMaintainer]:
            return [
                NixDerivationMeta.maintainers.through(
                    nixderivationmeta_id=meta_pk, nixmaintainer_id=maintainer.pk
                )
                for maintainer in maintainers
            ]

        def thunk_licenses_throughs(
            meta_pk: int,
        ) -> list[NixLicense]:
            return [
                NixDerivationMeta.licenses.through(
                    nixderivationmeta_id=meta_pk, nixlicense_id=license.pk
                )
                for license in licenses
            ]

        return meta, thunk_maintainers_throughs, thunk_licenses_throughs

    def ingest_outputs(
        self, evaluation: EvaluatedAttribute
    ) -> list[NixStorePathOutput]:
        store_paths = [f"{value}!{key}" for (key, value) in evaluation.outputs.items()]
        existing = NixStorePathOutput.objects.in_bulk(
            store_paths, field_name="store_path"
        )
        return list(existing.values()) + [
            NixStorePathOutput(store_path=store_path)
            for store_path in store_paths
            if store_path not in existing
        ]

    def ingest_dependencies(
        self, evaluation: EvaluatedAttribute
    ) -> list[NixDerivationOutput]:
        # FIXME(raitobezarius): bulk upsert the outputs
        # then add them into the M2M.

        return [
            NixDerivationOutput(derivation_path=drvpath)
            for drvpath in evaluation.input_drvs.keys()
        ]

    def ingest_derivation_shell(
        self,
        evaluation: EvaluatedAttribute,
        parent_evaluation: NixEvaluation,
        metadata: NixDerivationMeta | None = None,
    ) -> NixDerivation:
        return NixDerivation(
            attribute=evaluation.attr.removesuffix(f".{evaluation.system}"),
            derivation_path=evaluation.drv_path,
            name=evaluation.name,
            metadata=metadata,
            system=evaluation.system,
            parent_evaluation=parent_evaluation,
        )

    def ingest(self, parent_evaluation: NixEvaluation) -> list[NixDerivation]:
        start = time.time()
        dependencies = dict(
            bulkify(
                (evaluation, self.ingest_dependencies(evaluation))
                for evaluation in self.evaluations
            )
        )
        NixDerivationOutput.objects.bulk_create(
            chain.from_iterable(dependencies.values())
        )
        logger.debug(
            "Ingestion of all dependencies (%d) took %f s",
            len(dependencies),
            time.time() - start,
        )

        outputs = dict(
            bulkify(
                (evaluation, self.ingest_outputs(evaluation))
                for evaluation in self.evaluations
            )
        )
        # When Django 5 will be available, we will be able to get PKs directly.
        start = time.time()
        inserted = False
        attempt = 0
        store_path_outputs = {
            item.store_path: item for item in chain.from_iterable(outputs.values())
        }
        new_store_path_outputs = [
            spo for spo in store_path_outputs.values() if spo.pk is None
        ]
        while not inserted:
            try:
                for spo in NixStorePathOutput.objects.bulk_create(
                    new_store_path_outputs
                ):
                    store_path_outputs[spo.store_path].pk = spo.pk
                inserted = True
                logger.debug(
                    "Ingestion of all Nix store path outputs (%d) took %f s",
                    len(store_path_outputs),
                    time.time() - start,
                )
            except IntegrityError:
                logger.debug(
                    "Failed to bulk-insert all Nix store path outputs, attempt %d...",
                    attempt,
                )
                attempt += 1
                existing_new = NixStorePathOutput.objects.in_bulk(
                    [spo.store_path for spo in new_store_path_outputs],
                    field_name="store_path",
                )
                # Filter out existing new ones.
                new_store_path_outputs = [
                    spo
                    for spo in new_store_path_outputs
                    if spo.store_path not in existing_new
                ]
                # Extend existing new ones with IDs.
                for spath, existing in existing_new.items():
                    store_path_outputs[spath].pk = existing.pk
                continue

        # FIXME(raitobezarius): bulk ingest the maintainers or licenses themselves.
        # This requires knowing in advance the maintainer PK or license PK
        # and thunking it further.
        derivations: dict[str, NixDerivation] = {}
        thunked_maintainers_throughs = []
        thunked_licenses_throughs = []
        maintainers_throughs = []
        licenses_throughs = []
        metadatas = []
        start = time.time()
        for index, evaluation in enumerate(self.evaluations):
            eval_dependencies = dependencies[evaluation.drv_path]
            eval_outputs = outputs[evaluation.drv_path]
            metadata = None
            if evaluation.meta is not None:
                (
                    metadata,
                    drv_maintainers_throughs,
                    drv_licenses_throughs,
                ) = self.ingest_meta(evaluation)
                metadata_index = len(metadatas)
                thunked_maintainers_throughs.append(
                    (metadata_index, drv_maintainers_throughs)
                )
                thunked_licenses_throughs.append(
                    (metadata_index, drv_licenses_throughs)
                )
                metadatas.append(metadata)

            derivations[evaluation.drv_path] = self.ingest_derivation_shell(
                evaluation, parent_evaluation, metadata
            )
        logger.debug(
            "Ingestion of derivation shells (%d) and their maintainers or licenses took %f s",
            len(derivations),
            time.time() - start,
        )

        start = time.time()
        metadatas = NixDerivationMeta.objects.bulk_create(metadatas)
        logger.debug(
            "Ingestion of all metadata (%d) took %f s",
            len(metadatas),
            time.time() - start,
        )

        derivations = {
            drv.derivation_path: drv
            for drv in NixDerivation.objects.bulk_create(derivations.values())
        }
        for index, thunk in thunked_maintainers_throughs:
            maintainers_throughs.extend(thunk(metadatas[index].pk))

        for index, thunk in thunked_licenses_throughs:
            licenses_throughs.extend(thunk(metadatas[index].pk))

        deps_throughs = []
        outputs_throughs = []
        for drvpath, eval_dependencies in dependencies.items():
            assert all(dep.pk is not None for dep in eval_dependencies), (
                "One dependency has no PK"
            )
            deps_throughs.extend(
                [
                    NixDerivation.dependencies.through(
                        nixderivationoutput_id=dep.pk,
                        nixderivation_id=derivations[drvpath].pk,
                    )
                    for dep in eval_dependencies
                ]
            )

        for drvpath, eval_outputs in outputs.items():
            assert all(
                store_path_outputs[output.store_path].pk is not None
                for output in eval_outputs
            ), "One output has no PK"
            outputs_throughs.extend(
                [
                    NixDerivation.outputs.through(
                        nixstorepathoutput_id=store_path_outputs[output.store_path].pk,
                        nixderivation_id=derivations[drvpath].pk,
                    )
                    for output in eval_outputs
                ]
            )

        start = time.time()
        NixDerivationMeta.maintainers.through.objects.bulk_create(maintainers_throughs)
        logger.debug(
            "Ingestion of all maintainers M2M (%d) took %f s",
            len(maintainers_throughs),
            time.time() - start,
        )

        start = time.time()
        NixDerivationMeta.licenses.through.objects.bulk_create(licenses_throughs)
        logger.debug(
            "Ingestion of all licenses M2M (%d) took %f s",
            len(licenses_throughs),
            time.time() - start,
        )

        start = time.time()
        NixDerivation.dependencies.through.objects.bulk_create(deps_throughs)
        logger.debug(
            "Ingestion of all dependencies M2M (%d) took %f s",
            len(deps_throughs),
            time.time() - start,
        )
        start = time.time()
        NixDerivation.outputs.through.objects.bulk_create(outputs_throughs)
        logger.debug(
            "Ingestion of all outputs M2M (%d)  took %f s",
            len(outputs_throughs),
            time.time() - start,
        )

        return list(derivations.values())
