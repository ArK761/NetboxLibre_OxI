from pathlib import Path

from django.contrib import messages
from django.http import HttpResponse
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
        selected_config = None
        selected_name = "current.cfg"
        history = []
        monitored = False
        last_check = None
        storage_error = None

        if settings:
            monitored = monitored_devices(settings).filter(pk=device.pk).exists()
            try:
                current, current_hash = read_current(settings.storage_root, device.pk)
                directory = device_dir(settings.storage_root, device.pk, create=False)
                marker = directory / "last_check"
                if marker.exists():
                    last_check = marker.read_text(encoding="utf-8").strip()

                history_paths = [
                    p for p in list_history(settings.storage_root, device.pk)
                    if p.name != "current.cfg"
                ]
                history = [p.name for p in history_paths]

                revision = request.GET.get("revision", "").strip()
                if revision and revision in history:
                    selected_path = directory / revision
                    selected_config = selected_path.read_text(encoding="utf-8", errors="replace")
                    selected_name = revision
                else:
                    selected_config = current
            except OSError as exc:
                storage_error = f"LibreOXI storage is not accessible: {exc}"

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
                "selected_config": selected_config,
                "selected_name": selected_name,
                "history": history,
                "last_check": last_check,
                "storage_error": storage_error,
            },
        )

    def post(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        settings = LibreOXISettings.objects.first()

        if not settings:
            messages.error(request, "LibreOXI settings have not been configured.")
        elif not monitored_devices(settings).filter(pk=device.pk).exists():
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


def download_config(request, pk):
    device = get_object_or_404(Device, pk=pk)
    settings = LibreOXISettings.objects.first()

    if not settings or not monitored_devices(settings).filter(pk=device.pk).exists():
        return HttpResponse("Device is not selected for LibreOXI monitoring.", status=404, content_type="text/plain")

    try:
        directory = device_dir(settings.storage_root, device.pk, create=False)
        revision = request.GET.get("revision", "").strip()

        if revision:
            history = {p.name for p in list_history(settings.storage_root, device.pk)}
            if revision not in history or Path(revision).name != revision:
                return HttpResponse("Configuration revision not found.", status=404, content_type="text/plain")
            selected_path = directory / revision
            current = selected_path.read_text(encoding="utf-8", errors="replace")
        else:
            current, _ = read_current(settings.storage_root, device.pk)
    except OSError as exc:
        return HttpResponse(f"LibreOXI storage is not accessible: {exc}", status=500, content_type="text/plain")

    if not current:
        return HttpResponse("No configuration is stored for this device.", status=404, content_type="text/plain")

    ip = device.primary_ip4.address.ip if device.primary_ip4 else None
    filename = f"{ip}.txt" if ip else f"device-{device.pk}.txt"
    response = HttpResponse(current, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def settings_view(request):
    instance = LibreOXISettings.objects.first()
    if instance is None:
        instance = LibreOXISettings(
            librenms_url="",
            oxidized_path="/api/v0/oxidized/config",
            storage_root="/opt/libreoxi",
        )

    if request.method == "POST":
        form = LibreOXISettingsForm(request.POST, instance=instance)
        if form.is_valid():
            form.save()
            messages.success(request, "LibreOXI settings saved. New storage path is used immediately by device views and refresh jobs.")
            return redirect("plugins:netbox_libreoxi:settings")
    else:
        form = LibreOXISettingsForm(instance=instance)

    return render(request, "netbox_libreoxi/settings.html", {"form": form})
