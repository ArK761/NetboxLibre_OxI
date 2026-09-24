from django.db import migrations, models


def migrate_interval_to_cron(apps, schema_editor):
    settings_model = apps.get_model("netbox_libreoxi", "LibreOXISettings")
    mapping = {
        5: "*/5 * * * *",
        10: "*/10 * * * *",
        15: "*/15 * * * *",
        20: "*/20 * * * *",
        30: "*/30 * * * *",
        60: "0 * * * *",
    }
    for settings in settings_model.objects.all():
        settings.schedule_cron = mapping.get(settings.check_interval_minutes, "*/5 * * * *")
        settings.save(update_fields=["schedule_cron"])


class Migration(migrations.Migration):
    dependencies = [("netbox_libreoxi", "0001_initial")]

    operations = [
        migrations.AddField(
            model_name="libreoxisettings",
            name="schedule_cron",
            field=models.TextField(default="*/5 * * * *"),
        ),
        migrations.RunPython(migrate_interval_to_cron, migrations.RunPython.noop),
    ]
