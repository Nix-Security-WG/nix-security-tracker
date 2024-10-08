# Generated by Django 4.2.16 on 2024-10-08 11:05

from django.db.models.fields.json import KT
from django.db.models import F
from django.db import migrations, models

TARGET_FIELDS = (
    'attack_complexity',
    'attack_vector',
    'availability_impact',
    'confidentiality_impact',
    'integrity_impact',
    'privileges_required',
    'user_interaction'
)

def to_camel_case(name):
    """
    >>> to_camel_case("abc_def")
    abcDef
    """
    from re import sub
    s = sub(r"(_|-)+", " ", name).title().replace(" ", "")
    return ''.join([s[0].lower(), s[1:]])

def parse_cvss_fields(apps, schema_editor):
    Metric = apps.get_model("shared", "Metric")

    annotations = {}
    update_dict = {}
    for field in TARGET_FIELDS:
        camel_case_field = to_camel_case(field)
        annotations[f'{field}_as_text'] = KT(f'raw_cvss_json__{camel_case_field}')
        update_dict[field] = F(f'{field}_as_text')

    updated = Metric.objects \
        .annotate(**annotations) \
        .filter(raw_cvss_json__scope__isnull=False) \
        .update(**update_dict)

    print(f' {updated} metrics updated.')

def unparse_cvss_fields(apps, schema_editor):
    Metric = apps.get_model("shared", "Metric")

    update_dict = {}
    for field in TARGET_FIELDS:
        update_dict[field] = None

    Metric.objects.update(**update_dict)


class Migration(migrations.Migration):

    dependencies = [
        ('shared', '0034_rename_content_metric_raw_cvss_json_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='metric',
            name='attack_complexity',
            field=models.CharField(choices=[('NONE', 'NONE'), ('LOW', 'LOW'), ('MEDIUM', 'MEDIUM'), ('HIGH', 'HIGH'), ('CRITICAL', 'CRITICAL')], default=None, max_length=8, null=True),
        ),
        migrations.AddField(
            model_name='metric',
            name='attack_vector',
            field=models.CharField(choices=[('PHYSICAL', 'PHYSICAL'), ('LOCAL', 'LOCAL'), ('ADJACENT_NETWORK', 'ADJACENT_NETWORK'), ('NETWORK', 'NETWORK')], default=None, max_length=16, null=True),
        ),
        migrations.AddField(
            model_name='metric',
            name='availability_impact',
            field=models.CharField(choices=[('NONE', 'NONE'), ('LOW', 'LOW'), ('MEDIUM', 'MEDIUM'), ('HIGH', 'HIGH'), ('CRITICAL', 'CRITICAL')], default=None, max_length=8, null=True),
        ),
        migrations.AddField(
            model_name='metric',
            name='base_severity',
            field=models.CharField(choices=[('NONE', 'NONE'), ('LOW', 'LOW'), ('MEDIUM', 'MEDIUM'), ('HIGH', 'HIGH'), ('CRITICAL', 'CRITICAL')], default=None, max_length=8, null=True),
        ),
        migrations.AddField(
            model_name='metric',
            name='confidentiality_impact',
            field=models.CharField(choices=[('NONE', 'NONE'), ('LOW', 'LOW'), ('MEDIUM', 'MEDIUM'), ('HIGH', 'HIGH'), ('CRITICAL', 'CRITICAL')], default=None, max_length=8, null=True),
        ),
        migrations.AddField(
            model_name='metric',
            name='integrity_impact',
            field=models.CharField(choices=[('NONE', 'NONE'), ('LOW', 'LOW'), ('MEDIUM', 'MEDIUM'), ('HIGH', 'HIGH'), ('CRITICAL', 'CRITICAL')], default=None, max_length=8, null=True),
        ),
        migrations.AddField(
            model_name='metric',
            name='privileges_required',
            field=models.CharField(choices=[('NONE', 'NONE'), ('LOW', 'LOW'), ('MEDIUM', 'MEDIUM'), ('HIGH', 'HIGH'), ('CRITICAL', 'CRITICAL')], default=None, max_length=8, null=True),
        ),
        migrations.AddField(
            model_name='metric',
            name='user_interaction',
            field=models.CharField(choices=[('NONE', 'NONE'), ('LOW', 'LOW'), ('MEDIUM', 'MEDIUM'), ('HIGH', 'HIGH'), ('CRITICAL', 'CRITICAL')], default=None, max_length=8, null=True),
        ),
        migrations.RunPython(parse_cvss_fields, unparse_cvss_fields)
    ]
