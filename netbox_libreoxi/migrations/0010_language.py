from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_libreoxi", "0009_email_options"),
    ]

    operations = [
        migrations.AddField(
            model_name="libreoxisettings",
            name="language",
            field=models.CharField(default="en", max_length=8),
        ),
    ]
