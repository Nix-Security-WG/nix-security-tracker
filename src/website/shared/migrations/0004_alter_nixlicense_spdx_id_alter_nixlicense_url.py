# Generated by Django 4.2.7 on 2023-12-05 03:37

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("shared", "0003_nixchannel_nixlicense_nixmaintainer_nixoutput_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="nixlicense",
            name="spdx_id",
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name="nixlicense",
            name="url",
            field=models.URLField(null=True),
        ),
    ]