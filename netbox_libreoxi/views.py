from django.contrib import messages
from django.shortcuts import redirect, render, get_object_or_404

from dcim.models import Device
from netbox.views import generic
from utilities.views import ViewTab, register_model_view

from .forms import LibreOXISettingsForm
from .models import LibreOXISettings


@register_model_view(Device, name="libreoxi", path="libreoxi")
class DeviceLibreOXIView(generic.ObjectView):
    queryset = Device.objects.all()
    tab = ViewTab(label="LibreOXI", weight=500)

    def get(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        return render(
            request,
            "netbox_libreoxi/device_tab.html",
            {
                "object": device,
                "device": device,
                "tab": self.tab,
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
