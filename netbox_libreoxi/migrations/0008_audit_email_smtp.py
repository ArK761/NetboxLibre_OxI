from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_libreoxi", "0007_reset_audit_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="libreoxisettings",
            name="audit_email_frequency",
            field=models.CharField(default="daily", max_length=16),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="audit_email_weekday",
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="audit_email_attach_pdf",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="audit_email_attach_csv",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="smtp_host",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="smtp_port",
            field=models.PositiveIntegerField(default=587),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="smtp_security",
            field=models.CharField(default="starttls", max_length=16),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="smtp_username",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="smtp_password",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="smtp_from",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
    ]
