# Generated by Django 4.2.7 on 2023-12-19 11:10

from django.db import migrations, models
import django.utils.timezone
import pgtrigger.compiler
import pgtrigger.migrations


class Migration(migrations.Migration):

    dependencies = [
        ('shared', '0022_nixchannel_head_sha1_commit_and_more'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='nixstorepathoutput',
            unique_together=set(),
        ),
        migrations.RemoveField(
            model_name='nixderivationmeta',
            name='platforms',
        ),
        migrations.AddField(
            model_name='nixchannel',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='nixchannel',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AddField(
            model_name='nixevaluation',
            name='attempt',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='nixevaluation',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='nixevaluation',
            name='elapsed',
            field=models.FloatField(null=True),
        ),
        migrations.AddField(
            model_name='nixevaluation',
            name='failure_reason',
            field=models.TextField(null=True),
        ),
        migrations.AddField(
            model_name='nixevaluation',
            name='state',
            field=models.CharField(choices=[('COMPLETED', 'Completed'), ('WAITING', 'Waiting to be started'), ('IN_PROGRESS', 'In progress'), ('CRASHED', 'Crashed'), ('FAILED', 'Failed')], default='WAITING', max_length=11),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='nixevaluation',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AlterField(
            model_name='nixderivation',
            name='system',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='nixstorepathoutput',
            name='store_path',
            field=models.CharField(max_length=255, unique=True),
        ),
        migrations.AlterUniqueTogether(
            name='nixevaluation',
            unique_together={('channel', 'commit_sha1')},
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='nixchannel',
            trigger=pgtrigger.compiler.Trigger(name='pgpubsub_ae5b1', sql=pgtrigger.compiler.UpsertTriggerSql(declare='DECLARE payload TEXT;', func="\n            \n            payload := json_build_object(\n                'app', 'shared',\n                'model', 'NixChannel',\n                'old', row_to_json(OLD),\n                'new', row_to_json(NEW)\n              );\n        \n            \n            perform pg_notify('pgpubsub_ae5b1', payload);\n            RETURN NEW;\n        ", hash='e4f38cbd82ee07621ae9d61e3a672c6d36a49aa4', operation='INSERT', pgid='pgtrigger_pgpubsub_ae5b1_eb186', table='shared_nixchannel', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='nixevaluation',
            trigger=pgtrigger.compiler.Trigger(name='pgpubsub_aa9f7', sql=pgtrigger.compiler.UpsertTriggerSql(declare='DECLARE payload TEXT;', func="\n            \n            payload := json_build_object(\n                'app', 'shared',\n                'model', 'NixEvaluation',\n                'old', row_to_json(OLD),\n                'new', row_to_json(NEW)\n              );\n        \n            \n            INSERT INTO pgpubsub_notification (channel, payload)\n            VALUES ('pgpubsub_aa9f7', to_json(payload::text));\n        \n            perform pg_notify('pgpubsub_aa9f7', payload);\n            RETURN NEW;\n        ", hash='25db610c183b644bb790893fdd3c4df4cbe1ccf3', operation='INSERT', pgid='pgtrigger_pgpubsub_aa9f7_77b01', table='shared_nixevaluation', when='AFTER')),
        ),
        migrations.RemoveField(
            model_name='nixstorepathoutput',
            name='output_name',
        ),
    ]
