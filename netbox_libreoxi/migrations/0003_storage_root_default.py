from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_libreoxi", "0002_settings_scope"),
    ]

    operations = [
        migrations.AlterField(
            model_name="libreoxisettings",
            name="storage_root",
            field=models.CharField(
                default="/opt/libreoxi",
                max_length=500,
            ),
        ),
    ]
