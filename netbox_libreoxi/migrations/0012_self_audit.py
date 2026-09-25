from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_libreoxi", "0011_audit_pdf_password"),
    ]

    operations = [
        migrations.AddField(
            model_name="libreoxisettings",
            name="self_audit_email",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="self_audit_min_severity",
            field=models.CharField(default="low", max_length=16),
        ),
        migrations.AddField(
            model_name="libreoxisettings",
            name="self_audit_snapshot",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.CreateModel(
            name="SelfAuditRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("object_type", models.CharField(max_length=100)),
                ("field", models.CharField(max_length=150)),
                ("severity", models.CharField(default="medium", max_length=16)),
                ("message", models.TextField(blank=True, default="")),
                ("enabled", models.BooleanField(default=True)),
            ],
            options={"ordering": ("object_type", "field")},
        ),
        migrations.AddConstraint(
            model_name="selfauditrule",
            constraint=models.UniqueConstraint(fields=("object_type", "field"), name="netbox_libreoxi_selfauditrule_unique"),
        ),
        migrations.CreateModel(
            name="SelfAuditSystemEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("time", models.DateTimeField()),
                ("kind", models.CharField(max_length=16)),
                ("name", models.CharField(blank=True, default="", max_length=150)),
                ("old", models.CharField(blank=True, default="", max_length=100)),
                ("new", models.CharField(blank=True, default="", max_length=100)),
            ],
            options={"ordering": ("-time",)},
        ),
    ]
