from django.db.models.fields.json import KT
from django.db.models import F
from django.db.models.functions import Cast, Trim
from django.db import migrations, models
from django.db.models.fields import FloatField

def parse_cvss_json(apps, schema_editor):
    Metric = apps.get_model("shared", "Metric")

    updated = Metric.objects \
        .annotate(
            base_severity_as_text=KT("raw_cvss_json__baseSeverity"),
        ) \
        .filter(raw_cvss_json__vectorString__isnull=False) \
        .update(base_severity=Trim("base_severity_as_text"))
    print(f' {updated} metrics updated.')

def unparse_cvss_json(apps, schema_editor):
    Metric = apps.get_model("shared", "Metric")
    Metric.objects.update(base_severity=None)

class Migration(migrations.Migration):
    dependencies = [
        ('shared', '0040_alter_container_cve_and_more'),
    ]

    operations = [
        migrations.RunPython(parse_cvss_json, unparse_cvss_json)
    ]
