from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_libreoxi", "0005_schedule_cron"),
    ]

    operations = [
        migrations.AddField(
            model_name="libreoxisettings",
            name="audit_email_enabled",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="audit_email_recipients",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="audit_email_time",
            field=models.CharField(default="07:00", max_length=5),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="audit_min_severity",
            field=models.CharField(default="medium", max_length=16),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="audit_severity_map",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="audit_fields",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="audit_send_empty",
            field=models.BooleanField(default=False),
        ),
    ]
