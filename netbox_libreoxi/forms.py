import os
import tempfile
from pathlib import Path

from django import forms

from dcim.models import Device, DeviceRole
from utilities.forms.fields import DynamicModelMultipleChoiceField

import re

from django.core.validators import validate_email

from .audit import (
    AUDIT_CATEGORIES,
    AUDIT_FIELD_KEYS,
    DEFAULT_AUDIT_FIELDS,
    audit_fields,
    frequencies,
    severities,
    severity_map,
    smtp_securities,
    weekdays,
)
from .i18n import LANGUAGES, language_of, tr
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

    language = forms.ChoiceField(label="Language", choices=LANGUAGES)
    audit_min_severity = forms.ChoiceField(label="Audit: minimum severity to report", choices=severities())
    audit_fields = forms.MultipleChoiceField(
        label="Audit: columns in the report",
        choices=audit_fields(),
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={"class": "form-check-input"}),
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
            "language",
            "audit_min_severity",
            "audit_fields",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        lang = language_of(self.instance)
        self.fields["language"].label = tr("form.language", lang) + (" / Language" if lang != "en" else "")
        self.fields["language"].help_text = tr("form.language_help", lang)
        self.fields["audit_min_severity"].label = tr("form.min_severity", lang)
        self.fields["audit_min_severity"].help_text = tr("form.min_severity_help", lang)
        self.fields["audit_min_severity"].choices = severities(lang)
        self.fields["audit_fields"].label = tr("form.fields", lang)
        self.fields["audit_fields"].help_text = tr("form.fields_help", lang)
        self.fields["audit_fields"].choices = audit_fields(lang)
        configured = severity_map(self.instance)
        for key, _default in AUDIT_CATEGORIES:
            self.fields[f"audit_severity_{key}"] = forms.ChoiceField(
                label=tr("form.severity_for", lang, category=tr(f"category.{key}", lang)),
                choices=severities(lang),
                initial=configured[key],
            )
        # ModelForm takes initial values from the instance (an empty list for new
        # settings), which would leave all checkboxes unticked; use the defaults.
        self.initial["audit_fields"] = self.instance.audit_fields or DEFAULT_AUDIT_FIELDS
        order = list(self.fields)
        severity_fields = [name for name in order if name.startswith("audit_severity_")]
        rest = [name for name in order if name not in severity_fields]
        position = rest.index("audit_min_severity")
        self.order_fields(rest[:position] + severity_fields + rest[position:])
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
            key: self.cleaned_data[f"audit_severity_{key}"] for key, _default in AUDIT_CATEGORIES
        }
        fields = list(self.cleaned_data.get("audit_fields") or [])
        if "change" not in fields:
            fields.append("change")
        instance.audit_fields = [key for key in AUDIT_FIELD_KEYS if key in fields]
        if commit:
            instance.save()
        return instance


class LibreOXIEmailForm(forms.ModelForm):
    """E-mail delivery of the audit (separate page, similar to LibreNMS Email Options)."""

    # Labels and help texts are set in __init__ in the configured language.
    audit_email_enabled = forms.BooleanField(required=False)
    smtp_from_name = forms.CharField(required=False)
    smtp_from = forms.CharField(required=False)
    smtp_host = forms.CharField(required=False)
    smtp_port = forms.IntegerField(min_value=1, max_value=65535)
    smtp_timeout = forms.IntegerField(min_value=1, max_value=300)
    smtp_security = forms.ChoiceField(choices=smtp_securities())
    smtp_auto_tls = forms.BooleanField(required=False)
    smtp_auth = forms.BooleanField(required=False)
    smtp_username = forms.CharField(required=False)
    smtp_password_input = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}),
    )
    audit_email_recipients = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 2, "placeholder": "security@example.com, soc@example.com"}),
    )
    audit_email_frequency = forms.ChoiceField(choices=frequencies())
    audit_email_weekday = forms.TypedChoiceField(choices=weekdays(), coerce=int)
    audit_email_time = forms.CharField(widget=forms.TimeInput(attrs={"type": "time"}))
    audit_send_empty = forms.BooleanField(required=False)
    audit_email_attach_pdf = forms.BooleanField(required=False)
    audit_email_attach_csv = forms.BooleanField(required=False)

    class Meta:
        model = LibreOXISettings
        fields = (
            "smtp_from_name",
            "smtp_from",
            "smtp_host",
            "smtp_port",
            "smtp_timeout",
            "smtp_security",
            "smtp_auto_tls",
            "smtp_auth",
            "smtp_username",
            "audit_email_enabled",
            "audit_email_recipients",
            "audit_email_frequency",
            "audit_email_weekday",
            "audit_email_time",
            "audit_send_empty",
            "audit_email_attach_pdf",
            "audit_email_attach_csv",
        )

    LABELS = {
        "audit_email_enabled": ("form.enabled", None),
        "smtp_from_name": ("form.from_name", "form.from_name_help"),
        "smtp_from": ("form.from_email", "form.from_email_help"),
        "smtp_host": ("form.smtp_host", "form.smtp_host_help"),
        "smtp_port": ("form.smtp_port", None),
        "smtp_timeout": ("form.smtp_timeout", None),
        "smtp_security": ("form.security", None),
        "smtp_auto_tls": ("form.auto_tls", "form.auto_tls_help"),
        "smtp_auth": ("form.auth", None),
        "smtp_username": ("form.username", None),
        "smtp_password_input": ("form.password", "form.password_help"),
        "audit_email_recipients": ("form.recipients", "form.recipients_help"),
        "audit_email_frequency": ("form.frequency", None),
        "audit_email_weekday": ("form.weekday", None),
        "audit_email_time": ("form.time", "form.time_help"),
        "audit_send_empty": ("form.send_empty", "form.send_empty_help"),
        "audit_email_attach_pdf": ("form.attach_pdf", None),
        "audit_email_attach_csv": ("form.attach_csv", None),
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lang = lang = language_of(self.instance)
        for name, (label, help_text) in self.LABELS.items():
            self.fields[name].label = tr(label, lang)
            self.fields[name].help_text = tr(help_text, lang) if help_text else ""
        self.fields["smtp_security"].choices = smtp_securities(lang)
        self.fields["audit_email_frequency"].choices = frequencies(lang)
        self.fields["audit_email_weekday"].choices = weekdays(lang)
        for field in self.fields.values():
            widget = field.widget
            if getattr(widget, "input_type", "") == "checkbox":
                widget.attrs.setdefault("class", "form-check-input")
                widget.attrs.setdefault("role", "switch")
            elif isinstance(widget, forms.Select):
                widget.attrs.setdefault("class", "form-select")
            else:
                widget.attrs.setdefault("class", "form-control")
        self.order_fields(
            [
                "smtp_from_name",
                "smtp_from",
                "smtp_host",
                "smtp_port",
                "smtp_timeout",
                "smtp_security",
                "smtp_auto_tls",
                "smtp_auth",
                "smtp_username",
                "smtp_password_input",
                "audit_email_enabled",
                "audit_email_recipients",
                "audit_email_frequency",
                "audit_email_weekday",
                "audit_email_time",
                "audit_send_empty",
                "audit_email_attach_pdf",
                "audit_email_attach_csv",
            ]
        )

    def clean_audit_email_recipients(self):
        value = self.cleaned_data.get("audit_email_recipients", "") or ""
        addresses = [address.strip() for address in re.split(r"[,;\s]+", value) if address.strip()]
        for address in addresses:
            try:
                validate_email(address)
            except forms.ValidationError as exc:
                raise forms.ValidationError(tr("form.err_email", self.lang, address=address)) from exc
        if self.cleaned_data.get("audit_email_enabled") and not addresses:
            raise forms.ValidationError(tr("form.err_need_recipient", self.lang))
        return ", ".join(addresses)

    def clean_audit_email_time(self):
        value = (self.cleaned_data.get("audit_email_time") or "").strip()[:5]
        if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", value):
            raise forms.ValidationError(tr("form.err_time", self.lang))
        return value

    def clean_smtp_from(self):
        value = (self.cleaned_data.get("smtp_from") or "").strip()
        if value:
            try:
                validate_email(value)
            except forms.ValidationError as exc:
                raise forms.ValidationError(tr("form.err_from", self.lang)) from exc
        return value

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("smtp_auth") and not (cleaned.get("smtp_username") or "").strip():
            self.add_error("smtp_username", tr("form.err_username", self.lang))
        return cleaned

    def save(self, commit=True):
        instance = super().save(commit=False)
        password = self.cleaned_data.get("smtp_password_input")
        if password:
            instance.smtp_password = password
        if not instance.smtp_auth:
            instance.smtp_username = ""
            instance.smtp_password = ""
        if commit:
            instance.save()
        return instance

