# Generated by Django 3.2.8 on 2021-12-27 10:51

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('UserAdministration', '0004_alllogin_alllogout'),
    ]

    operations = [
        migrations.AlterField(
            model_name='alllogin',
            name='login_time',
            field=models.TimeField(auto_now_add=True, default=datetime.datetime(2021, 12, 27, 10, 51, 37, 169844, tzinfo=utc)),
            preserve_default=False,
        ),
    ]