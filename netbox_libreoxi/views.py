from django.contrib import messages
from django.shortcuts import redirect, render

from .forms import LibreOXISettingsForm
from .models import LibreOXISettings


def settings_view(request):
    instance = LibreOXISettings.objects.first()
    if instance is None:
        instance = LibreOXISettings(
            librenms_url="",
            oxidized_path="/api/v0/oxidized/config",
        )

    if request.method == "POST":
        form = LibreOXISettingsForm(request.POST, instance=instance)
        if form.is_valid():
            form.save()
            messages.success(request, "LibreOXI settings saved.")
            return redirect("plugins:netbox_libreoxi:settings")
    else:
        form = LibreOXISettingsForm(instance=instance)

    return render(request, "netbox_libreoxi/settings.html", {"form": form})
