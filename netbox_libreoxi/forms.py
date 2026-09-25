import os
import tempfile
from pathlib import Path

from django import forms

from dcim.models import Device, DeviceRole
from utilities.forms.fields import DynamicModelMultipleChoiceField

from .audit import AUDIT_CATEGORIES, AUDIT_FIELDS, DEFAULT_AUDIT_FIELDS, SEVERITIES, severity_map
from .models import LibreOXISettings
from .scheduler import validate_cron_schedule


DATETIME_FORMAT_CHOICES = (
    ("%d.%m.%Y %H:%M:%S", "24.09.2026 18:06:06 (EU)"),
    ("%d/%m/%Y %H:%M:%S", "24/09/2026 18:06:06 (EU slash)"),
    ("%Y-%m-%d %H:%M:%S", "2026-09-24 18:06:06 (ISO-like)"),
    ("%d.%m.%Y %H:%M", "24.09.2026 18:06 (EU, no seconds)"),
    ("%Y-%m-%dT%H:%M:%S", "2026-09-24T18:06:06 (ISO 8601)"),
)

SCHEDULE_PRESETS = (
    ("*/5 * * * *", "Every 5 minutes — :00, :05, :10, ..."),
    ("*/10 * * * *", "Every 10 minutes — :00, :10, :20, ..."),
    ("*/15 * * * *", "Every 15 minutes — :00, :15, :30, :45"),
    ("*/20 * * * *", "Every 20 minutes — :00, :20, :40"),
    ("*/30 * * * *", "Every 30 minutes — :00, :30"),
    ("0 * * * *", "Every full hour — :00"),
    ("0 1 * * *", "Every day at 01:00"),
    ("0 0 * * *", "Every day at 00:00"),
)


class LibreOXISettingsForm(forms.ModelForm):
    api_token = forms.CharField(
        label="LibreNMS API token",
        required=False,
        widget=forms.PasswordInput(render_value=True),
    )
    device_roles = DynamicModelMultipleChoiceField(
        label="Device roles to monitor",
        queryset=DeviceRole.objects.all(),
        required=False,
        help_text="All devices assigned to these roles will be checked automatically.",
    )
    devices = DynamicModelMultipleChoiceField(
        label="Additional devices",
        queryset=Device.objects.all(),
        required=False,
        help_text="These devices are checked even when their role is not selected.",
    )
    datetime_format = forms.ChoiceField(
        label="Date/time display format",
        choices=DATETIME_FORMAT_CHOICES,
        help_text="Only the displayed date/time format changes. Stored timestamps remain UTC/ISO internally.",
    )
    schedule_cron = forms.CharField(
        label="Schedule (cron)",
        widget=forms.Textarea(attrs={"rows": 3, "spellcheck": "false", "placeholder": "*/30 * * * *"}),
        help_text=(
            "True cron schedule. Examples: */30 * * * * = every full 30 minutes; "
            "0 * * * * = every full hour; 0 1 * * * = every day at 01:00. "
            "You may enter multiple cron lines for complex schedules."
        ),
    )
    schedule_preset = forms.ChoiceField(
        label="Cron preset",
        choices=(("", "— select a preset —"),) + SCHEDULE_PRESETS,
        required=False,
        help_text="Selecting a preset fills the cron field; the cron field is the value that is saved.",
    )

    audit_min_severity = forms.ChoiceField(
        label="Audit: minimum severity to report",
        choices=SEVERITIES,
        help_text="Only changes with this severity or higher are included in the audit for the security manager.",
    )
    audit_fields = forms.MultipleChoiceField(
        label="Audit: fields in the report",
        choices=AUDIT_FIELDS,
        required=False,
        widget=forms.CheckboxSelectMultiple,
        help_text="The device name and the change are always included.",
    )

    class Meta:
        model = LibreOXISettings
        fields = (
            "librenms_url",
            "oxidized_path",
            "api_token",
            "storage_root",
            "request_timeout",
            "schedule_preset",
            "schedule_cron",
            "retention_days",
            "retention_revisions",
            "verify_tls",
            "enabled",
            "device_roles",
            "devices",
            "datetime_format",
            "audit_min_severity",
            "audit_fields",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        severities = severity_map(self.instance)
        for key, label, _default in AUDIT_CATEGORIES:
            self.fields[f"audit_severity_{key}"] = forms.ChoiceField(
                label=f"Audit severity: {label}",
                choices=SEVERITIES,
                initial=severities[key],
            )
        # ModelForm takes initial values from the instance (an empty list for new
        # settings), which would leave all checkboxes unticked; use the defaults.
        self.initial["audit_fields"] = self.instance.audit_fields or DEFAULT_AUDIT_FIELDS
        self.fields["api_token"].initial = self.instance.api_token_encrypted
        self.fields["schedule_preset"].initial = ""
        if self.instance.pk:
            self.fields["device_roles"].initial = DeviceRole.objects.filter(
                pk__in=self.instance.device_role_ids or []
            )
            self.fields["devices"].initial = Device.objects.filter(
                pk__in=self.instance.device_ids or []
            )

    def clean_storage_root(self):
        value = self.cleaned_data["storage_root"].strip()
        if not value:
            raise forms.ValidationError("Storage path is required.")
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise forms.ValidationError("Storage path must be an absolute path.")
        if not path.exists():
            raise forms.ValidationError(
                f"Storage directory does not exist: {path}. Create it and grant write permission to the netbox user."
            )
        if not path.is_dir():
            raise forms.ValidationError(f"Storage path is not a directory: {path}.")
        if not os.access(path, os.W_OK | os.X_OK):
            raise forms.ValidationError(
                f"Storage directory is not writable by the NetBox process: {path}."
            )
        fd = None
        probe = None
        try:
            fd, probe = tempfile.mkstemp(prefix=".libreoxi-write-test-", dir=path)
            os.write(fd, b"libreoxi")
        except OSError as exc:
            raise forms.ValidationError(
                f"NetBox does not have write permission for storage directory: {path} ({exc})."
            ) from exc
        finally:
            if fd is not None:
                os.close(fd)
            if probe is not None:
                try:
                    os.unlink(probe)
                except OSError:
                    pass
        return str(path.resolve())

    def clean_schedule_cron(self):
        value = self.cleaned_data["schedule_cron"].strip()
        preset = self.cleaned_data.get("schedule_preset")
        if preset:
            value = preset
        try:
            return validate_cron_schedule(value)
        except ValueError as exc:
            raise forms.ValidationError(str(exc)) from exc

    def save(self, commit=True):
        instance = super().save(commit=False)
        token = self.cleaned_data.get("api_token")
        if token:
            instance.api_token_encrypted = token
        instance.device_role_ids = [obj.pk for obj in self.cleaned_data.get("device_roles", [])]
        instance.device_ids = [obj.pk for obj in self.cleaned_data.get("devices", [])]
        instance.audit_severity_map = {
            key: self.cleaned_data[f"audit_severity_{key}"] for key, _label, _default in AUDIT_CATEGORIES
        }
        fields = list(self.cleaned_data.get("audit_fields") or [])
        if "change" not in fields:
            fields.append("change")
        instance.audit_fields = [key for key, _label in AUDIT_FIELDS if key in fields]
        if commit:
            instance.save()
        return instance
