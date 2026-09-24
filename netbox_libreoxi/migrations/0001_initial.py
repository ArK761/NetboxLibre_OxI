from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="LibreOXISettings",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "singleton",
                    models.BooleanField(default=True, unique=True),
                ),
                (
                    "librenms_url",
                    models.URLField(),
                ),
                (
                    "oxidized_path",
                    models.CharField(
                        default="/api/v0/oxidized/config",
                        max_length=255,
                    ),
                ),
                (
                    "api_token_encrypted",
                    models.TextField(blank=True, default=""),
                ),
                (
                    "request_timeout",
                    models.PositiveIntegerField(default=10),
                ),
                (
                    "check_interval_minutes",
                    models.PositiveIntegerField(default=60),
                ),
                (
                    "retention_days",
                    models.PositiveIntegerField(default=365),
                ),
                (
                    "retention_revisions",
                    models.PositiveIntegerField(default=100),
                ),
                (
                    "verify_tls",
                    models.BooleanField(default=True),
                ),
                (
                    "enabled",
                    models.BooleanField(default=True),
                ),
                (
                    "updated_at",
                    models.DateTimeField(auto_now=True),
                ),
            ],
        ),
    ]
