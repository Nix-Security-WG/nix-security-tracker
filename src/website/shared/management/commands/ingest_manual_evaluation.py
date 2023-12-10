import contextlib
import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Generator

from dataclass_wizard import DumpMixin, JSONWizard, LoadMeta, LoadMixin
from django.core.management.base import BaseCommand
from django.db.models import DecimalField, ForeignKey
from shared.models import NixChannel, NixEvaluation, NixMaintainer
from shared.models.nix_evaluation import (
    NixDerivation,
    NixDerivationMeta,
    NixDerivationOutput,
    NixLicense,
    NixOutput,
    NixPlatform,
    NixStorePathOutput,
)
from tqdm import tqdm

log = logging.getLogger(__name__)


class BulkSave(object):

    """
    Batches inserts, deletions and updates together to perform the minimum number of
    SQL queries.

    This can efficiently set ManyToMany relationships on many objects.
    Batched inserts, batched updates, batched deletions.

    Large numbers of operations can be stored in this BulkSave and then performed when
    save() is called.

    Usage::
        with bulk_save() as bs:
            # add objects. Will use a single insert statement
            bs.add_insert(NewModel(value=1))
            bs.add_insert(NewModel(value=2))

            nm = NewModel(value=3)
            bs.add_insert(nm)

            # set m2m fields even though the field has not yet been saved
            bs.set_m2m(nm, 'owners', [user1, user2])
            # equivalent to:
            # nm.owners = [user1, user2]

            # update
            update_me = NewModel.objects.get(id=2)
            with bs.changing(update_me):
                update_me.value = 2

    """

    def __init__(self):
        self.snapshots = defaultdict(dict)
        self.updates = defaultdict(dict)
        self.inserts = defaultdict(list)
        self.deletes = defaultdict(list)
        self.m2m = defaultdict(dict)
        self.m2m_models = defaultdict(dict)
        self.saved = False

    def take_snapshot(self, model):
        """
        Take a snapshot of all field values on a model,
        prior to possibly setting some of those fields.

        Afterwards call add_changed_fields with the model
        to store any changes to be commited when the BulkSave completes.
        """
        klass = model.__class__
        opts = klass._meta
        self.snapshots[klass][model.pk] = {}
        for field in opts.fields:
            atn = field.get_attname()
            val = getattr(model, atn)
            self.snapshots[klass][model.pk][atn] = val

    def add_changed_fields(self, model):
        """
        Having taken a snapshot of model
        previously, add any changed fields
        to the scheduled updates

        For foreign_key compare with the id
        and set by setting the object
        """
        qwargs = {}
        klass = model.__class__
        opts = klass._meta
        for field in opts.fields:
            atn = field.get_attname()
            val = getattr(model, atn)
            try:
                prev = self.snapshots[klass][model.pk][atn]
            except KeyError:
                raise Exception(
                    "No snapshot found for %s pk=%s attribute=%s"
                    % (klass, model.pk, atn)
                )
            if val and (isinstance(field, DecimalField)):
                if not isinstance(val, Decimal):
                    if not isinstance(val, (int, float, str)):
                        raise Exception(
                            "%s %s is not a number, is: %s" % (model, val, type(val))
                        )
                    val = Decimal(str(round(float(val), field.decimal_places)))
            if prev != val:
                # print "CHANGED (%s).%s %s => %s" % (model, atn, prev, val)
                qwargs[field.name] = getattr(model, field.name)
        if qwargs:
            self.set(model, qwargs)
        del self.snapshots[klass][model.pk]

    def has_changed(self, model):
        """
        Having previously called take_snapshot(model),
        determine if any fields have been changed since then.
        """
        klass = model.__class__
        opts = klass._meta
        for field in opts.fields:
            atn = field.get_attname()
            val = getattr(model, atn)
            prev = self.snapshots[klass][model.pk][atn]
            if val and (isinstance(field, DecimalField)):
                if not isinstance(val, Decimal):
                    if isinstance(val, (int, float)):
                        raise Exception(
                            "%s %s is not a number, is: %s" % (model, val, type(val))
                        )
                    val = Decimal(str(round(val, field.decimal_places)))
            if prev != val:
                return True
        return False

    def add_insert(self, model):
        """
        Add an unsaved model (with no pk) to be inserted.
        """
        pos = len(self.inserts[model.__class__])
        self.inserts[model.__class__].append(model)
        # Save to set a temporary id.
        # Check `set_m2m` for the reason why this is needed.
        model.op_pos = f"insert-{pos}"

    def add_delete(self, model):
        """
        Add a model to be deleted.
        """
        self.deletes[model.__class__].append(model)

    def set(self, model, qwargs):
        """
        Set fields update for a model using a dict
        """
        klass = model.__class__
        if model.pk not in self.updates[klass]:
            self.updates[klass][model.pk] = {}

        self.updates[klass][model.pk].update(qwargs)

    def set_m2m(self, model, attname, objects):
        """
        Set many-to-many objects for a model.

        Equivalent to `model.{attname} = objects`

        But it will do this in bulk with
        one query to check for the current state (exists)
        one for all deletes
        and one for all inserts.
        """
        klass = model.__class__
        mid = model.pk
        # Set up a temporary id from the operation position;
        # otherwise all the m2m operations get collapsed into
        # a None key and relationships get lost when calling
        # save_m2m (that is, the m2m will only be set for the
        # last entry found).
        if model.pk is None:
            if "op_pos" not in model.__dict__.keys():
                raise RuntimeError(
                    "Temporary model id cannot be set. "
                    + "Check that all `save` operations set a temporary id "
                    + "inside `model.op_pos`."
                )
            mid = model.op_pos
        if mid not in self.m2m[klass]:
            self.m2m[klass][mid] = {}
        # Assert that all models are of the same type
        assert len(set([type(m) for m in objects])) <= 1, Exception(
            "Mixed models supplied to set_m2m: {} {}.{} = {}".format(
                model, type(model), attname, objects
            )
        )

        self.m2m[klass][mid][attname] = [
            obj if isinstance(obj, int) else obj.pk for obj in objects
        ]
        self.m2m_models[klass][mid] = model

    @contextlib.contextmanager
    def changing(self, obj):
        """
        Set fields on an object regardless of whether
        it is updating or inserting the object.

        usage::

            with bulk_save.changing(model):
                model.value = 1

        If a pk exists (updating the model)
        then it does snapshot then add_changed_fields.

        If no pk (creating) then it does add_insert/
        """
        creating = obj.pk is None
        if not creating:
            self.take_snapshot(obj)
        yield
        if not creating:
            self.add_changed_fields(obj)
        else:
            self.add_insert(obj)

    def save(self):
        """
        Perform all updates/inserts/deletes and m2m changes.
        """
        if self.saved:
            raise Exception("BulkSave has already saved")

        self.save_inserts()
        self.save_updates()
        self.save_deletes()

        self.save_m2m()
        self.saved = True

    def save_inserts(self):
        for klass, models in list(self.inserts.items()):
            self.save_inserts_for_model(klass, models)

    def save_inserts_for_model(self, klass, models):
        opts = klass._meta
        for model in models:
            for field in opts.fields:
                # if the foreign key field to an unsaved object
                # but now the object has been saved
                # then it still has no {fk}_id set
                # so set it now with that id
                if isinstance(field, ForeignKey):
                    atn = field.get_attname()
                    val = getattr(model, atn)
                    if val is None:
                        fk = getattr(model, field.get_cache_name(), None)
                        if fk:
                            val = fk.pk
                            setattr(model, field.get_attname(), val)
        try:
            klass.objects.bulk_create(models, 100)
        except Exception as e:
            # an IntegrityError or something
            # report what the model and db error message was
            raise Exception("%r while saving models: %s" % (e, klass))

    def save_updates(self):
        """
        Batch updates where possible.

        [0.030] UPDATE "nsproperties_apt" SET "available_on" = '2017-07-02'::date WHERE "nsproperties_apt"."id" = 704702
        [0.017] UPDATE "nsproperties_apt" SET "available_on" = '2017-07-05'::date WHERE "nsproperties_apt"."id" IN (704687, 704696)
        [0.023] UPDATE "nsproperties_apt" SET "available_on" = '2017-07-06'::date WHERE "nsproperties_apt"."id" IN (704683, 704691, 704692, 704693, 704694, 704697, 704698, 704704)

        """
        for klass, models in list(self.updates.items()):
            batched_qwargs = dict()
            batched_qwargs_pks = defaultdict(list)
            for pk, qwargs in list(models.items()):
                hh = dict_hash(qwargs)
                batched_qwargs[hh] = qwargs
                batched_qwargs_pks[hh].append(pk)
            for hh, qwargs in list(batched_qwargs.items()):
                pks = batched_qwargs_pks[hh]
                pkwargs = dict(pk__in=pks) if len(pks) > 1 else dict(pk=pks[0])
                klass.objects.filter(**pkwargs).update(**qwargs)

    def save_deletes(self):
        for klass, models in list(self.deletes.items()):
            klass.objects.filter(pk__in=[model.pk for model in models]).delete()

    def save_m2m(self):
        """
        self.m2m::

            {
                klass: {
                    model: {
                        m2m_attr: [id, id, ...]
                    }
                }
            }
        """
        for klass in list(self.m2m.keys()):
            self.save_m2m_for_model(klass)

    def save_m2m_for_model(self, klass):
        models_fields_ids = self.m2m[klass]

        # model to get
        fields_models_to_lookup = defaultdict(set)
        # related models to get
        for mid, fields_ids in list(models_fields_ids.items()):
            model = self.m2m_models[klass][mid]
            # model, {field: [id, id, ...], ...}
            if model.pk is None:
                raise Exception(
                    "No pk for model %s. cannot save m2m %s" % (model, fields_ids)
                )
            for field, _ in list(fields_ids.items()):
                fields_models_to_lookup[field].add(model)

        for field, models_to_lookup in list(fields_models_to_lookup.items()):
            self.save_m2m_for_field(klass, field, models_to_lookup, models_fields_ids)

    def save_m2m_for_field(self, klass, field, models_to_lookup, models_fields_ids):
        opts = klass._meta

        # joins that will need to be made
        # {join_model: join_attrs[]}
        joins_to_add = defaultdict(list)
        # {join.objects: join_id[]}
        joins_to_delete = defaultdict(list)

        ff = opts.get_field(field)
        # apt_contacts
        join_objects = ff.remote_field.through.objects
        # apt__in
        filter_in = "%s__in" % ff.m2m_field_name()
        qwargs = {filter_in: models_to_lookup}

        # field names on the join object
        # apt_id
        getr = ff.m2m_column_name()
        # contact_id
        othr = ff.m2m_reverse_name()
        existing = defaultdict(list)
        joins = dict()

        # find existing, joins
        for join in join_objects.filter(**qwargs):
            one_id = getattr(join, getr)
            two_id = getattr(join, othr)
            existing[one_id].append(two_id)
            joins[(one_id, two_id)] = join

        # Compare existing joins with what should exist
        for mid, fields_ids in list(models_fields_ids.items()):
            model = self.m2m_models[klass][mid]
            current = set(existing[model.id])
            for fg, shoulds in list(fields_ids.items()):
                if fg == field:
                    shoulds = set(shoulds)
                    to_remove = current.difference(shoulds)
                    if to_remove:
                        rmv_join_ids = [joins[(model.id, r)].id for r in to_remove]
                        joins_to_delete[join_objects].extend(rmv_join_ids)
                    to_add = shoulds.difference(current)
                    if to_add:
                        join_model = ff.remote_field.through
                        for a in to_add:
                            join_params = {
                                ff.m2m_column_name(): model.pk,
                                ff.m2m_reverse_name(): a,
                            }
                            assert a and model.pk, Exception(
                                "null id for join: %s %s" % (join_model, join_params)
                            )
                            joins_to_add[join_model].append(join_params)

        for join_model_objects, to_delete in list(joins_to_delete.items()):
            join_model_objects.filter(id__in=to_delete).delete()

        for join_model, to_adds in list(joins_to_add.items()):
            joins = [join_model(**params) for params in to_adds]
            join_model.objects.bulk_create(joins, 500)


@contextlib.contextmanager
def bulk_saver(maybe=None):
    """
    Context manager to perform a bulk save operation.

    If no parent is passed in then this creates a BulkSave, runs any code
    inside the context and saves when the context closes.

    """
    saver = maybe or BulkSave()
    try:
        yield saver
    except Exception as e:
        raise e
    else:
        if maybe is None:
            saver.save()


def dict_hash(qwargs):
    """
    Generate a unique hash for the dictionary

    Nested dictionaries are not hashable, so it falls back to hashing the unicode
    representation.

    Nested dictionaries can be passed in when saving to a PickleField or JSONField
    """
    try:
        items = sorted(qwargs.items())
        return hash(frozenset(items))
    except TypeError:
        return hashlib.sha1(qwargs).hexdigest()


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


# No choice...
LoadMeta(tag="list").bind_to(list[LicenseAttribute])


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


def parse_evaluation_results(lines) -> Generator[PartialEvaluatedAttribute, None, None]:
    for line in lines:
        raw = json.loads(line)
        if raw.get("error") is not None:
            yield PartialEvaluatedAttribute(**raw, evaluation=None)
        else:
            yield PartialEvaluatedAttribute(
                attr=raw.get("attr"),
                attrPath=raw.get("attrPath"),
                error=None,
                evaluation=parse_total_evaluation(raw),
            )


class BulkEvaluationIngestion:
    def __init__(self, bs: BulkSave):
        self.maintainers = NixMaintainer.objects.all()
        self.licenses = NixLicense.objects.all()
        self.platforms = {
            model.system_double: model for model in NixPlatform.objects.all()
        }
        self.outputs = {model.output_name: model for model in NixOutput.objects.all()}
        self.store_path_outputs = {
            (model.output_name, model.store_path): model
            for model in NixStorePathOutput.objects.all()
        }
        self.bs = bs
        self.created = 0
        self.updated = 0

    def ingest_maintainers(
        self, maintainers: list[MaintainerAttribute]
    ) -> list[NixMaintainer]:
        ms = []
        seen = set()
        for m in maintainers:
            # Duplicate...
            if m.name in seen:
                continue
            ms.append(
                NixMaintainer(
                    email=m.email,
                    github=m.github,
                    github_id=m.githubId,
                    matrix=m.matrix,
                    name=m.name,
                )
            )
            seen.add(m.name)

        NixMaintainer.objects.bulk_create(
            ms,
            update_conflicts=True,
            unique_fields=["name"],  # pyright: ignore generalTypeIssue
            update_fields=["email", "github", "github_id", "matrix"],
        )

        # HACK HACK HACK
        # https://github.com/django/django/commit/89c7454dbdae3e0df6d96aa6132205d05e4a9b3d is not merged yet in 4.2...
        added_ids = NixMaintainer.objects.filter(
            name__in=[m.name for m in ms]
        ).values_list("id", flat=True)
        return list(NixMaintainer.objects.in_bulk(added_ids).values())

    def ingest_licenses(self, licenses: list[LicenseAttribute]) -> list[NixLicense]:
        lics = []
        seen = set()

        for lic in licenses:
            # Duplicate...
            if lic.url in seen:
                continue
            lics.append(
                NixLicense.objects.get_or_create(
                    defaults={
                        "deprecated": lic.deprecated,
                        "free": lic.free,
                        "redistributable": lic.redistributable,
                    },
                    full_name=lic.fullName,
                    short_name=lic.shortName,
                    spdx_id=lic.spdxId,
                    url=lic.url,
                )[0]
            )
            seen.add(lic.url)

        return lics

    def ingest_platforms(self, platforms: list[str]) -> list[NixPlatform]:
        ps = []
        for p in platforms:
            if p not in self.platforms:
                self.created += 1
                self.platforms[p] = NixPlatform.objects.create(system_double=p)

            ps.append(self.platforms[p])

        return ps

    def ingest_meta(self, metadata: MetadataAttribute) -> NixDerivationMeta:
        maintainers = self.ingest_maintainers(metadata.maintainers)
        platforms = self.ingest_platforms(metadata.platforms)
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
            main_program=metadata.mainProgram,
            position=metadata.position,
            known_vulnerabilities=metadata.knownVulnerabilities,
        )
        self.bs.add_insert(meta)
        self.bs.set_m2m(meta, "maintainers", maintainers)
        self.bs.set_m2m(meta, "licenses", licenses)
        self.bs.set_m2m(meta, "platforms", platforms)

        return meta

    def ingest_dependencies(
        self, input_drvs: dict[str, list[str]]
    ) -> list[NixDerivationOutput]:
        drvs = []
        for drvpath, outputs_raw in input_drvs.items():
            outputs = []
            for output in outputs_raw:
                if output in self.outputs:
                    outputs.append(self.outputs.get(output))
                else:
                    output_model = NixOutput.objects.create(output_name=output)
                    outputs.append(output_model)
                    self.outputs[output] = output_model
            # New outputs created
            self.created += sum(
                (1 for output in outputs_raw if output not in self.outputs)
            )
            drv_out = NixDerivationOutput(derivation_path=drvpath)
            self.bs.add_insert(drv_out)
            self.bs.set_m2m(drv_out, "outputs", outputs)

        return drvs

    def ingest_outputs(self, outputs: dict[str, str]) -> list[NixStorePathOutput]:
        values = []
        for key, value in outputs.items():
            if (key, value) not in self.store_path_outputs:
                self.created += 1
                self.store_path_outputs[
                    (key, value)
                ] = NixStorePathOutput.objects.create(output_name=key, store_path=value)

            values.append(self.store_path_outputs[(key, value)])

        return values

    def ingest_derivation(self, drv: EvaluatedAttribute) -> NixDerivation:
        meta = None
        if drv.meta is not None:
            meta = self.ingest_meta(drv.meta)
        dependencies = self.ingest_dependencies(drv.inputDrvs)
        outputs = self.ingest_outputs(drv.outputs)

        derivation = NixDerivation(
            attribute=drv.attr,
            derivation_path=drv.drvPath,
            name=drv.name,
            metadata=meta,
            system=self.platforms[drv.system],
        )

        self.bs.add_insert(derivation)
        self.bs.set_m2m(derivation, "dependencies", dependencies)
        self.bs.set_m2m(derivation, "outputs", outputs)

        return derivation


class Command(BaseCommand):
    help = "Ingest a manual evaluation JSONL from nix-eval-jobs, assume from nixpkgs"

    def add_arguments(self, parser):
        parser.add_argument("commit_sha1", type=str)
        parser.add_argument("channel_branch", type=str)
        parser.add_argument("evaluation_result_file", type=str)
        parser.add_argument("-q", "--quiet", action="store_true")
        parser.add_argument(
            "-s",
            "--subset",
            nargs="?",
            type=int,
            help="Integer value representing the N subset of total entries. "
            + " Useful to generate a small dataset for development.",
            default=0,
        )

    def handle(self, *args, **kwargs):
        quiet = kwargs.get("quiet", True)
        channel = NixChannel.objects.get(channel_branch=kwargs["channel_branch"])
        filename = kwargs["evaluation_result_file"]
        print(
            "Ingesting evaluation contained in {} information from channel {}...".format(
                filename, str(channel)
            )
        )
        evaluation = NixEvaluation.objects.create(
            channel=channel, commit_sha1=kwargs["commit_sha1"]
        )

        with open(filename, "r") as f:
            with bulk_saver() as bs:
                ingester = BulkEvaluationIngestion(bs)
                lines = f.readlines()
                if kwargs["subset"] > 0:
                    lines = lines[: kwargs["subset"]]
                log.warn(f"{len(lines)} entries to ingest.")
                for result in tqdm(parse_evaluation_results(lines), total=len(lines)):
                    if result.error is not None:
                        if not quiet:
                            print("!", end="", flush=True)
                    elif result.evaluation is not None:
                        eval_ = result.evaluation
                        derivation = ingester.ingest_derivation(eval_)
                        derivation.parent_evaluation = evaluation
                        if not quiet:
                            print(".", end="", flush=True)
                    else:
                        raise RuntimeError("Impossible situation; bug")
