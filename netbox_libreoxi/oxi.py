from __future__ import annotations

from urllib.parse import quote

import requests

from .models import LibreOXISettings
from .storage import append_log, cleanup, store_if_changed


def monitored_devices(settings):
    from dcim.models import Device

    role_ids = settings.device_roles.values_list("id", flat=True)
    devices = Device.objects.filter(role_id__in=role_ids)
    return (devices | settings.devices.all()).distinct().order_by("pk")


def device_ip(device):
    if not device.primary_ip4:
        return None
    return str(device.primary_ip4.address.ip)


def fetch_device(settings: LibreOXISettings, device):
    ip = device_ip(device)
    if not ip:
        return {"ok": False, "error": "Device has no primary IPv4 address."}

    base = settings.librenms_url.rstrip("/")
    path = settings.oxidized_path.strip("/")
    url = f"{base}/{path}/{quote(ip, safe='') }"
    headers = {"X-Auth-Token": settings.api_token_encrypted}

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=settings.request_timeout,
            verify=settings.verify_tls,
        )
        response.raise_for_status()
        content = response.text
    except requests.RequestException as exc:
        append_log(settings.storage_root, f"ERROR {device} LibreNMS request failed: {exc}")
        return {"ok": False, "error": str(exc)}

    if not content.strip():
        error = "LibreNMS returned an empty configuration. Existing configuration was kept."
        append_log(settings.storage_root, f"ERROR {device} empty configuration")
        return {"ok": False, "error": error}

    result = store_if_changed(settings.storage_root, device.pk, content)
    cleanup(
        settings.storage_root,
        device.pk,
        settings.retention_days,
        settings.retention_revisions,
    )
    if result["changed"]:
        append_log(settings.storage_root, f"CHANGE {device} configuration stored hash={result['hash']}")
    else:
        append_log(settings.storage_root, f"NOCHANGE {device} hash={result['hash']}")
    return {"ok": True, "device": device, **result}
