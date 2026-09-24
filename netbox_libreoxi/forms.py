from django import forms

from dcim.models import Device, DeviceRole
from utilities.forms.fields import DynamicModelMultipleChoiceField

from .models import LibreOXISettings


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
