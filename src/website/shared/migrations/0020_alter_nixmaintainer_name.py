# Generated by Django 4.2.7 on 2023-12-11 11:19

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("shared", "0019_merge_20231211_0203"),
    ]

    operations = [
        migrations.AlterField(
            model_name="nixmaintainer",
            name="name",
            field=models.CharField(max_length=200, null=True),
        ),
    ]
