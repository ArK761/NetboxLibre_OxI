from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_libreoxi", "0010_language"),
    ]

    operations = [
        migrations.AddField(
            model_name="libreoxisettings",
            name="audit_pdf_password",
            field=models.TextField(blank=True, default=""),
        ),
    ]
