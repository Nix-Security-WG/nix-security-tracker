# Generated by Django 4.2.16 on 2024-11-20 15:28

import django.core.serializers.json
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('shared', '0041_migrate_cvss_json_without_scope'),
    ]

    operations = [
        migrations.CreateModel(
            name='CachedSuggestions',
            fields=[
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('proposal', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to='shared.cvederivationclusterproposal')),
                ('payload', models.JSONField(encoder=django.core.serializers.json.DjangoJSONEncoder)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]