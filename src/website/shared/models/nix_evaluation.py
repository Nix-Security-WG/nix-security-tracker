from django.contrib.postgres import fields
from django.db import models
from django.utils.translation import gettext_lazy as _


def text_length(choices: type[models.TextChoices]) -> int:
    return max(map(len, choices.values))


class NixMaintainer(models.Model):
    """
    This represents a maintainer in the `maintainers` field of a package.
    """

    github_id = models.IntegerField(unique=True)
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
    """

    deprecated = models.BooleanField()
    free = models.BooleanField()
    full_name = models.CharField(max_length=255, null=True)
    short_name = models.CharField(max_length=255, null=True)
    spdx_id = models.CharField(max_length=255, null=True)
    redistributable = models.BooleanField()
    url = models.URLField(null=True)

    class Meta:
        unique_together = ("full_name", "short_name", "spdx_id", "url")

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

    platforms = models.ManyToManyField(NixPlatform)

    position = models.URLField(null=True)

    def __str__(self) -> str | None:
        return self.description


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
    """

    # TODO(raitobezarius): do we foreign key or not?
    # seems like premature optimization to me.
    output_name = models.CharField(max_length=255)
    store_path = models.CharField(max_length=255)

    class Meta:
        unique_together = ("output_name", "store_path")


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


class NixChannel(models.Model):
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


class NixEvaluation(models.Model):
    """
    This is a complete Nix evaluation of a repository.

    It contains its derivations via `derivations` attribute
    set by the `NixDerivation` model.
    """

    # Parent channel of that evaluation.
    channel = models.ForeignKey(
        NixChannel, related_name="evaluations", on_delete=models.CASCADE
    )
    # Commit SHA1 on which the evaluation was done precisely.
    commit_sha1 = models.CharField(max_length=255)

    def __str__(self) -> str:
        return f"{self.channel} {self.commit_sha1[:8]}"


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
    system = models.ForeignKey(
        NixPlatform, related_name="derivations", on_delete=models.CASCADE
    )
    parent_evaluation = models.ForeignKey(
        NixEvaluation, related_name="derivations", on_delete=models.CASCADE
    )

    def __str__(self) -> str:
        hash = self.derivation_path.split("-")[0].split("/")[-1]
        return f"{self.name} {hash[:8]}"
