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
            name="device_roles",
            field=models.ManyToManyField(
                blank=True,
                related_name="libreoxi_settings",
                to="dcim.devicerole",
            ),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="devices",
            field=models.ManyToManyField(
                blank=True,
                related_name="libreoxi_settings",
                to="dcim.device",
            ),
        ),
    ]
