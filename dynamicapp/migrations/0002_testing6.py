# Generated by Django 3.2.8 on 2022-02-02 14:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dynamicapp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Testing6',
            fields=[
                ('user_id', models.AutoField(primary_key=True, serialize=False)),
                ('username', models.CharField(max_length=50, unique=True)),
                ('password', models.CharField(max_length=50)),
            ],
            options={
                'db_table': 'testing6',
                'managed': False,
            },
        ),
    ]