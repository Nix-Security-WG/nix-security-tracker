# Generated by Django 4.2.16 on 2024-10-08 10:33

from django.db.models.fields.json import KT
from django.db.models import F
from django.db.models.functions import Cast, Trim
from django.db import migrations, models
from django.db.models.fields import FloatField

def parse_cvss_json(apps, schema_editor):
    Metric = apps.get_model("shared", "Metric")

    updated = Metric.objects \
        .annotate(
            base_score_as_float=Cast("raw_cvss_json__baseScore", output_field=FloatField()),
            vector_string_as_text=KT("raw_cvss_json__vectorString"),
            scope_as_text=KT("raw_cvss_json__scope"),
        ) \
        .filter(raw_cvss_json__scope__isnull=False) \
        .update(scope=F("scope_as_text"), vector_string=Trim("vector_string_as_text"), base_score=F("base_score_as_float"))
    print(f' {updated} metrics updated.')

def unparse_cvss_json(apps, schema_editor):
    Metric = apps.get_model("shared", "Metric")
    Metric.objects.update(scope=None, base_score=None, vector_string=None)

class Migration(migrations.Migration):

    dependencies = [
        ('shared', '0033_rename_cvederivationclusterproposals_cvederivationclusterproposal'),
    ]

    operations = [
        migrations.RenameField(
            model_name='metric',
            old_name='content',
            new_name='raw_cvss_json',
        ),
        migrations.AddField(
            model_name='metric',
            name='base_score',
            field=models.FloatField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='metric',
            name='scope',
            field=models.CharField(choices=[('UNCHANGED', 'UNCHANGED'), ('CHANGED', 'CHANGED')], default=None, max_length=9, null=True),
        ),
        migrations.AddField(
            model_name='metric',
            name='vector_string',
            field=models.CharField(default=None, max_length=128, null=True),
        ),
        migrations.RunPython(parse_cvss_json, unparse_cvss_json)
    ]
