from django.db import migrations, models, transaction
import django.db.models.deletion

def populate_package_field(apps, schema_editor):
    NixPackage = apps.get_model('shared', 'NixPackage')
    NixDerivation = apps.get_model('shared', 'NixDerivation')

    with transaction.atomic():
        for derivation in NixDerivation.objects.all():
            package, _ = NixPackage.objects.get_or_create(name=derivation.attribute)
            derivation.package = package
            derivation.save()

def reverse_populate_package_field(apps, schema_editor):
    NixDerivation = apps.get_model('shared', 'NixDerivation')
    NixDerivation.objects.update(package=None)


class Migration(migrations.Migration):

    dependencies = [
        ('shared', '0048_remove_attribute_suffix'),
    ]

    operations = [
        migrations.CreateModel(
            name='NixPackage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, unique=True)),
            ],
        ),
        migrations.AddField(
            model_name='nixderivation',
            name='package',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='shared.nixpackage'),
        ),
        migrations.RunPython(populate_package_field, reverse_populate_package_field),
        migrations.AlterField(
            model_name='nixderivation',
            name='package',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='shared.nixpackage'),
        ),
    ]
