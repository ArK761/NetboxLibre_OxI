from pathlib import Path

from django.contrib import messages
from django.shortcuts import redirect, render, get_object_or_404
from django.urls import reverse

from dcim.models import Device
from netbox.views import generic
from utilities.views import ViewTab, register_model_view

from .forms import LibreOXISettingsForm
from .models import LibreOXISettings
from .oxi import fetch_device, monitored_devices
from .storage import device_dir, list_history, read_current


@register_model_view(Device, name="libreoxi", path="libreoxi")
class DeviceLibreOXIView(generic.ObjectView):
    queryset = Device.objects.all()
    tab = ViewTab(label="LibreOXI", weight=500)

    def get(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        settings = LibreOXISettings.objects.first()
        current, current_hash = (None, None)
        history = []
        monitored = False
        error = None
        last_check = None

        if settings:
            monitored = monitored_devices(settings).filter(pk=device.pk).exists()
            current, current_hash = read_current(settings.storage_root, device.pk)
            directory = device_dir(settings.storage_root, device.pk)
            marker = directory / "last_check"
            if marker.exists():
                last_check = marker.read_text(encoding="utf-8").strip()
            history = [p.name for p in list_history(settings.storage_root, device.pk) if p.name != "current.cfg"]

        if request.method == "POST":
            if not settings:
                messages.error(request, "LibreOXI settings have not been configured.")
            elif not monitored:
                messages.warning(request, "This device is not selected for LibreOXI monitoring.")
            else:
                result = fetch_device(settings, device)
                if result["ok"]:
                    if result["changed"]:
                        messages.warning(request, "Configuration changed and a new revision was stored.")
                    else:
                        messages.success(request, "No configuration change detected.")
                else:
                    messages.error(request, f"Configuration was not changed: {result['error']}")
            return redirect(reverse("dcim:device_libreoxi", kwargs={"pk": device.pk}))

        return render(
            request,
            "netbox_libreoxi/device_tab.html",
            {
                "object": device,
                "device": device,
                "tab": self.tab,
                "settings": settings,
                "monitored": monitored,
                "current": current,
                "current_hash": current_hash,
                "history": history,
                "last_check": last_check,
            },
        )


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
