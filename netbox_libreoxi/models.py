from django.db import models


class LibreOXISettings(models.Model):
    singleton = models.BooleanField(default=True, unique=True)
    librenms_url = models.URLField()
    oxidized_path = models.CharField(
        max_length=255,
        default="/api/v0/oxidized/config",
    )
    api_token_encrypted = models.TextField(blank=True, default="")
    storage_root = models.CharField(
        max_length=500,
        default="/var/lib/netbox/libreoxi",
    )
    request_timeout = models.PositiveIntegerField(default=10)
    check_interval_minutes = models.PositiveIntegerField(default=5)
    schedule_cron = models.TextField(default="*/5 * * * *")
    retention_days = models.PositiveIntegerField(default=365)
    retention_revisions = models.PositiveIntegerField(default=100)
    verify_tls = models.BooleanField(default=True)
    enabled = models.BooleanField(default=True)
    device_role_ids = models.JSONField(default=list, blank=True)
    device_ids = models.JSONField(default=list, blank=True)
    datetime_format = models.CharField(
        max_length=64,
        default="%d.%m.%Y %H:%M:%S",
    )
    audit_email_enabled = models.BooleanField(default=False)
    audit_email_recipients = models.TextField(blank=True, default="")
    audit_email_time = models.CharField(max_length=5, default="07:00")
    audit_min_severity = models.CharField(max_length=16, default="medium")
    audit_severity_map = models.JSONField(default=dict, blank=True)
    audit_fields = models.JSONField(default=list, blank=True)
    audit_send_empty = models.BooleanField(default=False)
    audit_email_frequency = models.CharField(max_length=16, default="daily")
    audit_email_weekday = models.PositiveSmallIntegerField(default=0)
    audit_email_attach_pdf = models.BooleanField(default=True)
    audit_email_attach_csv = models.BooleanField(default=False)
    smtp_host = models.CharField(max_length=255, blank=True, default="")
    smtp_port = models.PositiveIntegerField(default=587)
    smtp_security = models.CharField(max_length=16, default="starttls")
    smtp_username = models.CharField(max_length=255, blank=True, default="")
    smtp_password = models.TextField(blank=True, default="")
    smtp_from = models.CharField(max_length=255, blank=True, default="")
    smtp_from_name = models.CharField(max_length=255, blank=True, default="")
    smtp_timeout = models.PositiveIntegerField(default=10)
    smtp_auto_tls = models.BooleanField(default=False)
    smtp_auth = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "LibreOXI settings"
