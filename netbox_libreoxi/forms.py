from django import forms

from .models import LibreOXISettings


class LibreOXISettingsForm(forms.ModelForm):
    api_token = forms.CharField(
        label="LibreNMS API token",
        required=False,
        widget=forms.PasswordInput(render_value=True),
    )

    class Meta:
        model = LibreOXISettings
        fields = (
            "librenms_url",
            "oxidized_path",
            "api_token",
            "request_timeout",
            "check_interval_minutes",
            "retention_days",
            "retention_revisions",
            "verify_tls",
            "enabled",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["api_token"].initial = self.instance.api_token_encrypted

    def save(self, commit=True):
        instance = super().save(commit=False)
        token = self.cleaned_data.get("api_token")
        if token:
            instance.api_token_encrypted = token
        if commit:
            instance.save()
        return instance
