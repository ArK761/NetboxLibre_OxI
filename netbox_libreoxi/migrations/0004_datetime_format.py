from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_libreoxi", "0003_storage_root_default"),
    ]

    operations = [
        migrations.AddField(
            model_name="libreoxisettings",
            name="datetime_format",
            field=models.CharField(
                default="%d.%m.%Y %H:%M:%S",
                max_length=64,
            ),
        ),
    ]
