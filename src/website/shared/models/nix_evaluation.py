from django.contrib.postgres import fields
from django.contrib.postgres.indexes import BTreeIndex, GinIndex
from django.contrib.postgres.search import SearchVectorField
from django.db import models
from django.utils.translation import gettext_lazy as _
from pgtrigger import UpdateSearchVector


def text_length(choices: type[models.TextChoices]) -> int:
    return max(map(len, choices.values))


class TimeStampMixin(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:  # type: ignore[override]
        abstract = True


class NixMaintainer(models.Model):
    """
    This represents a maintainer in the `maintainers` field of a package.
    """

    github_id = models.IntegerField(unique=True, primary_key=True)
    github = models.CharField(max_length=200, unique=True)
    email = models.CharField(max_length=200, null=True)
    matrix = models.CharField(max_length=200, null=True)
    name = models.CharField(max_length=200, null=True)

    def __str__(self) -> str:
        return f"@{self.github}"


class NixLicense(models.Model):
    """
    This represents a Nix license data, we don't keep only the SPDX ID
    for maximal faithfulness to what nixpkgs tells us.

    We refuse any license without an SPDX ID, it is not realistic
    to handle them without as this would make reconcilation hard.
    """

    spdx_id = models.CharField(max_length=255, unique=True)
    deprecated = models.BooleanField()
    free = models.BooleanField()
    full_name = models.CharField(max_length=255, null=True)
    short_name = models.CharField(max_length=255, null=True)
    redistributable = models.BooleanField()
    url = models.URLField(null=True)

    def __str__(self) -> str:
        return f"{self.spdx_id}"


class NixSourceProvenance(models.Model):
    """
    Source provenance informs you about whether
    something is a binary native code or comes from a real source build.
    """

    qualifier = models.CharField(max_length=255)
    source = models.BooleanField()

    # TODO: define binary as !source


class NixPlatform(models.Model):
    """
    e.g. x86_64-linux.
    """

    system_double = models.CharField(max_length=255, unique=True)

    def __str__(self) -> str:
        return self.system_double


class NixDerivationMeta(models.Model):
    """
    All the meta attribute of a derivation
    is synthesized here.
    """

    name = models.CharField(max_length=255, null=True)
    maintainers = models.ManyToManyField(NixMaintainer)
    licenses = models.ManyToManyField(NixLicense)
    source_provenances = models.ManyToManyField(NixSourceProvenance)

    known_vulnerabilities = fields.ArrayField(
        models.CharField(max_length=255), default=list
    )

    insecure = models.BooleanField()
    available = models.BooleanField()
    broken = models.BooleanField()
    unfree = models.BooleanField()
    unsupported = models.BooleanField()

    homepage = models.URLField(null=True)

    description = models.TextField(null=True)
    main_program = models.CharField(max_length=255, null=True)

    # FIXME(raitobezarius):
    # Ridiculously big, we should encode all reasonable known platforms
    # into a static BitField (~120 of them, so 7 bits?).
    # Ideally, we should find a way to deal with "inspect patterns"
    # which are really dynamic things, maybe just project over our set of statically
    # known platforms.
    # platforms = models.ManyToManyField(NixPlatform)

    position = models.URLField(null=True)

    search_vector = SearchVectorField(null=True)

    def __str__(self) -> str:
        return self.description or ""

    class Meta:  # type: ignore[override]
        indexes = [
            # Add a GIN index to speed up vector search queries
            GinIndex(fields=["search_vector"]),
        ]
        triggers = [
            # Add a trigger to maintain the search vector updated with row changes
            UpdateSearchVector(
                name="description_search_vector_idx",
                vector_field="search_vector",
                document_fields=[
                    "description",
                ],
            )
        ]


class NixOutput(models.Model):
    """
    This is all the known outputs names.
    """

    output_name = models.CharField(max_length=255, unique=True)

    def __str__(self) -> str:
        return self.output_name


class NixStorePathOutput(models.Model):
    """
    This is all the outputs of a given derivation, e.g. out, doc, etc.
    associated to their store paths.

    This represents in database as '{store_path}!{out}'.
    """

    store_path = models.CharField(max_length=255, unique=True)

    def __hash__(self) -> int:
        return hash(self.store_path)


class NixDerivationOutput(models.Model):
    """
    A derivation may depend on another derivation,
    but it must specify two things:

    - derivation path
    - output depended upon
    e.g. depending on /nix/store/eeeeeeeeeeeeeee-something.drv and its 'out' output.
    """

    outputs = models.ManyToManyField(NixOutput)
    derivation_path = models.CharField(max_length=255)


class NixChannel(TimeStampMixin):
    """
    This represents a "Nixpkgs" (*) channel, e.g.
    - a Git object representing a branch that moves regularly.
    - a state, e.g. EOL, deprecated, stable, unstable.
    - if it's not unstable, release number.

    (*): Anything that looks like Nixpkgs is also good.
    """

    class ChannelState(models.TextChoices):
        END_OF_LIFE = "END_OF_LIFE", _("End of life")
        DEPRECATED = "DEPRECATED", _("Deprecated")
        BETA = "BETA", _("Beta")
        STABLE = "STABLE", _("Stable")
        UNSTABLE = "UNSTABLE", _("Unstable")
        # "Special" channel, for which the staging-branch == staging.
        # The channel_branch is staging-next in this instance.
        # But it's complicated because there's no channel move per se.
        STAGING = "STAGING", _("Staging")

    # A staging branch is the `release-$number` branch or `master` for unstable.
    # Not to confuse with the staging branch itself.
    staging_branch = models.CharField(max_length=255)
    # A channel branch is the `nixos-$number` branch of
    # `nixos-unstable(-small)` for unstable(-small). Not to confuse with the
    # channel tarballs and scripts from releases.nixos.org.
    channel_branch = models.CharField(max_length=255, primary_key=True)
    # The currently known HEAD SHA1 commit of that channel.
    head_sha1_commit = models.CharField(max_length=255)
    state = models.CharField(
        max_length=text_length(ChannelState), choices=ChannelState.choices
    )
    release_version = models.CharField(max_length=255, null=True)
    # Repository can be stored as URLs for now...
    # We can always reparse them as proper GitHub URIs if necessary
    # It's a bit annoying though
    # TODO(raitobezarius): make a proper ForeignKey?
    repository = models.CharField(max_length=255)

    def __str__(self) -> str:
        return f"{self.staging_branch} -> {self.channel_branch} (Release: {self.release_version})"


class NixEvaluation(TimeStampMixin):
    """
    This is a Nix evaluation of a repository,
    potentially ongoing.

    It contains its derivations via `derivations` attribute
    set by the `NixDerivation` model.
    """

    class EvaluationState(models.TextChoices):
        COMPLETED = "COMPLETED", _("Completed")
        WAITING = (
            "WAITING",
            _("Waiting to be started"),
        )
        IN_PROGRESS = (
            "IN_PROGRESS",
            _("In progress"),
        )
        # Crash means resource exhaustion or unexpected crash of the worker
        CRASHED = (
            "CRASHED",
            _("Crashed"),
        )
        # Failed means critical evaluation errors
        FAILED = "FAILED", _("Failed")

    # Parent channel of that evaluation.
    channel = models.ForeignKey(
        NixChannel, related_name="evaluations", on_delete=models.CASCADE
    )
    # Commit SHA1 on which the evaluation was done precisely.
    commit_sha1 = models.CharField(max_length=255)
    # State in which the evaluation is in.
    state = models.CharField(
        max_length=text_length(EvaluationState), choices=EvaluationState.choices
    )
    # How many times have been we trying to evaluate
    # this? We use it for the crash backoff loop.
    attempt = models.IntegerField(default=0)
    # Last failure reason
    failure_reason = models.TextField(null=True)
    # Time elapsed in seconds for this evaluation.
    elapsed = models.FloatField(null=True)

    def __str__(self) -> str:
        return f"{self.channel} {self.commit_sha1[:8]}"

    class Meta:  # type: ignore[override]
        unique_together = ("channel", "commit_sha1")


class NixDerivation(models.Model):
    """
    This represents a Nix derivation "evaluated",
    we fill this model using two things:

    - evaluation result
    - parsing the .drv
    """

    attribute = models.CharField(max_length=255)
    derivation_path = models.CharField(max_length=255)
    dependencies = models.ManyToManyField(NixDerivationOutput)
    name = models.CharField(max_length=255)
    metadata = models.OneToOneField(
        NixDerivationMeta,
        related_name="derivation",
        on_delete=models.CASCADE,
        null=True,
    )
    outputs = models.ManyToManyField(NixStorePathOutput)
    system = models.CharField(max_length=255)
    parent_evaluation = models.ForeignKey(
        NixEvaluation, related_name="derivations", on_delete=models.CASCADE
    )

    search_vector = SearchVectorField(null=True)

    def __str__(self) -> str:
        hash = self.derivation_path.split("-")[0].split("/")[-1]
        return f"{self.name} {hash[:8]}"

    class Meta:  # type: ignore[override]
        indexes = [
            BTreeIndex(fields=["name"]),
            GinIndex(fields=["search_vector"]),
        ]

        triggers = [
            # Add a trigger to maintain the search vector updated with row changes
            UpdateSearchVector(
                name="attribute_name_search_vector_idx",
                vector_field="search_vector",
                document_fields=[
                    "attribute",
                    "name",
                ],
            )
        ]


# Major channels are the important channels that a user wants to keep an eye on.
# FIXME figure this out dynamically
MAJOR_CHANNELS = ["23.11", "24.05", "24.11", "unstable"]


# The major channel that a branch name (e.g. nixpkgs-24.05-darwin) belongs to
def get_major_channel(branch_name: str) -> str | None:
    for mc in MAJOR_CHANNELS:
        if mc in branch_name:
            return f"nixos-{mc}"
    return None
