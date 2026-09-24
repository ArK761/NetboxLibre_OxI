from django.db import models


class LibreOXISettings(models.Model):
    singleton = models.BooleanField(default=True, unique=True)
    librenms_url = models.URLField()
    oxidized_path = models.CharField(
        max_length=255,
        default="/api/v0/oxidized/config",
    )
    api_token_encrypted = models.TextField(blank=True, default="")
    request_timeout = models.PositiveIntegerField(default=10)
    check_interval_minutes = models.PositiveIntegerField(default=60)
    retention_days = models.PositiveIntegerField(default=365)
    retention_revisions = models.PositiveIntegerField(default=100)
    verify_tls = models.BooleanField(default=True)
    enabled = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "LibreOXI settings"
