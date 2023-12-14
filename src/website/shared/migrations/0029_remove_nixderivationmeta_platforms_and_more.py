# Generated by Django 4.2.7 on 2023-12-18 12:18

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("shared", "0028_remove_nixmaintainer_id_remove_nixplatform_id_and_more"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="nixderivationmeta",
            name="platforms",
        ),
        migrations.AlterField(
            model_name="nixderivation",
            name="system",
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name="nixstorepathoutput",
            name="output_name",
            field=models.CharField(max_length=50),
        ),
    ]