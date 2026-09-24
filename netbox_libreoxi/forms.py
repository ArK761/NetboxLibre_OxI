import os
import tempfile
from pathlib import Path

from django import forms

from dcim.models import Device, DeviceRole
from utilities.forms.fields import DynamicModelMultipleChoiceField

from .models import LibreOXISettings


DATETIME_FORMAT_CHOICES = (
    ("%d.%m.%Y %H:%M:%S", "24.09.2026 18:06:06 (EU)"),
    ("%d/%m/%Y %H:%M:%S", "24/09/2026 18:06:06 (EU slash)"),
    ("%Y-%m-%d %H:%M:%S", "2026-09-24 18:06:06 (ISO-like)"),
    ("%d.%m.%Y %H:%M", "24.09.2026 18:06 (EU, no seconds)"),
    ("%Y-%m-%dT%H:%M:%S", "2026-09-24T18:06:06 (ISO 8601)"),
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

    class Meta:
        model = LibreOXISettings
        fields = (
            "librenms_url",
            "oxidized_path",
            "api_token",
            "storage_root",
            "request_timeout",
            "check_interval_minutes",
            "retention_days",
            "retention_revisions",
            "verify_tls",
            "enabled",
            "device_roles",
            "devices",
            "datetime_format",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["api_token"].initial = self.instance.api_token_encrypted
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
            fd, probe = tempfile.mkstemp(
                prefix=".libreoxi-write-test-",
                dir=path,
            )
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

    def save(self, commit=True):
        instance = super().save(commit=False)
        token = self.cleaned_data.get("api_token")
        if token:
            instance.api_token_encrypted = token
        instance.device_role_ids = [obj.pk for obj in self.cleaned_data.get("device_roles", [])]
        instance.device_ids = [obj.pk for obj in self.cleaned_data.get("devices", [])]
        if commit:
            instance.save()
        return instance
