from django.db import migrations


def reset_audit_fields(apps, schema_editor):
    # Versions before this fix saved only ["change"] because the report field
    # checkboxes were rendered unticked; restore the defaults for them.
    settings_model = apps.get_model("netbox_libreoxi", "LibreOXISettings")
    for settings in settings_model.objects.all():
        if settings.audit_fields == ["change"]:
            settings.audit_fields = []
            settings.save(update_fields=["audit_fields"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_libreoxi", "0006_audit_email"),
    ]

    operations = [
        migrations.RunPython(reset_audit_fields, migrations.RunPython.noop),
    ]
