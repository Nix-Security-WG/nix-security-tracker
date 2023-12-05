# Generated by Django 4.2.7 on 2023-12-05 01:14

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("shared", "0002_remove_cpe__product_remove_module__product_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="NixChannel",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("staging_branch", models.CharField(max_length=255)),
                ("channel_branch", models.CharField(max_length=255)),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("END_OF_LIFE", "End of life"),
                            ("DEPRECATED", "Deprecated"),
                            ("BETA", "Beta"),
                            ("STABLE", "Stable"),
                            ("UNSTABLE", "Unstable"),
                            ("STAGING", "Staging"),
                        ],
                        max_length=11,
                    ),
                ),
                ("release_version", models.CharField(max_length=255, null=True)),
                ("repository", models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name="NixLicense",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("deprecated", models.BooleanField()),
                ("free", models.BooleanField()),
                ("full_name", models.CharField(max_length=255)),
                ("short_name", models.CharField(max_length=255)),
                ("spdx_id", models.CharField(max_length=255)),
                ("redistributable", models.BooleanField()),
                ("url", models.URLField()),
            ],
        ),
        migrations.CreateModel(
            name="NixMaintainer",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("email", models.CharField(max_length=200, null=True)),
                ("github", models.CharField(max_length=200, null=True)),
                ("github_id", models.IntegerField(null=True)),
                ("matrix", models.CharField(max_length=200, null=True)),
                ("name", models.CharField(max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name="NixOutput",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("output_name", models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name="NixPlatform",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("system_double", models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name="NixSourceProvenance",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("qualifier", models.CharField(max_length=255)),
                ("source", models.BooleanField()),
            ],
        ),
        migrations.CreateModel(
            name="NixStorePathOutput",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("output_name", models.CharField(max_length=255)),
                ("store_path", models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name="NixEvaluation",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("commit_sha1", models.CharField(max_length=255)),
                (
                    "channel",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="evaluations",
                        to="shared.nixchannel",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="NixDerivationOutput",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("derivation_path", models.CharField(max_length=255)),
                ("outputs", models.ManyToManyField(to="shared.nixoutput")),
            ],
        ),
        migrations.CreateModel(
            name="NixDerivationMeta",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=255)),
                ("insecure", models.BooleanField()),
                ("available", models.BooleanField()),
                ("broken", models.BooleanField()),
                ("unfree", models.BooleanField()),
                ("unsupported", models.BooleanField()),
                ("homepage", models.URLField()),
                ("description", models.TextField()),
                ("main_program", models.CharField(max_length=255)),
                ("position", models.URLField()),
                ("licenses", models.ManyToManyField(to="shared.nixlicense")),
                ("maintainers", models.ManyToManyField(to="shared.nixmaintainer")),
                ("platforms", models.ManyToManyField(to="shared.nixplatform")),
                (
                    "source_provenances",
                    models.ManyToManyField(to="shared.nixsourceprovenance"),
                ),
            ],
        ),
        migrations.CreateModel(
            name="NixDerivation",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("attribute", models.CharField(max_length=255)),
                ("derivation_path", models.CharField(max_length=255)),
                ("name", models.CharField(max_length=255)),
                (
                    "dependencies",
                    models.ManyToManyField(to="shared.nixderivationoutput"),
                ),
                (
                    "metadata",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="derivation",
                        to="shared.nixderivationmeta",
                    ),
                ),
                ("outputs", models.ManyToManyField(to="shared.nixstorepathoutput")),
                (
                    "parent_evaluation",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="derivations",
                        to="shared.nixevaluation",
                    ),
                ),
                (
                    "system",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="derivations",
                        to="shared.nixplatform",
                    ),
                ),
            ],
        ),
    ]
