from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_libreoxi", "0008_audit_email_smtp"),
    ]

    operations = [
        migrations.AddField(
            model_name="libreoxisettings",
            name="smtp_from_name",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="smtp_timeout",
            field=models.PositiveIntegerField(default=10),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="smtp_auto_tls",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="smtp_auth",
            field=models.BooleanField(default=False),
        ),
    ]
