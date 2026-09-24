from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_libreoxi", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="libreoxisettings",
            name="storage_root",
            field=models.CharField(
                default="/var/lib/netbox/libreoxi",
                max_length=500,
            ),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="device_role_ids",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="device_ids",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AlterField(
            model_name="libreoxisettings",
            name="check_interval_minutes",
            field=models.PositiveIntegerField(default=5),
        ),
    ]
