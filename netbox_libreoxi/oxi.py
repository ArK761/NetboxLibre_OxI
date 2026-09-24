from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import quote

import requests

from .models import LibreOXISettings
from .storage import append_log, cleanup, device_dir, store_if_changed


def monitored_devices(settings):
    from dcim.models import Device

    role_ids = [int(value) for value in (settings.device_role_ids or [])]
    device_ids = [int(value) for value in (settings.device_ids or [])]
    devices = Device.objects.filter(role_id__in=role_ids)
    return (devices | Device.objects.filter(pk__in=device_ids)).distinct().order_by("pk")


def device_ip(device):
    if not device.primary_ip4:
        return None
    return str(device.primary_ip4.address.ip)


def _extract_config(response: requests.Response):
    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError("LibreNMS returned an invalid JSON response.") from exc

    if not isinstance(data, dict):
        raise RuntimeError("LibreNMS returned an unexpected response format.")

    if data.get("status") != "ok":
        status = data.get("status") or "unknown"
        raise RuntimeError(f"LibreNMS returned status: {status}")

    config = data.get("config")
    if isinstance(config, list):
        if not all(isinstance(line, str) for line in config):
            raise RuntimeError("LibreNMS returned an invalid config array.")
        return "".join(config)

    if isinstance(config, str):
        return config

    raise RuntimeError("LibreNMS response does not contain a valid config.")


def fetch_device(settings: LibreOXISettings, device):
    ip = device_ip(device)
    if not ip:
        return {"ok": False, "error": "Device has no primary IPv4 address."}

    base = settings.librenms_url.rstrip("/")
    path = settings.oxidized_path.strip("/")
    url = f"{base}/{path}/{quote(ip, safe='')}"
    headers = {"X-Auth-Token": settings.api_token_encrypted}

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=settings.request_timeout,
            verify=settings.verify_tls,
        )
        response.raise_for_status()
        content = _extract_config(response)
    except requests.RequestException as exc:
        append_log(settings.storage_root, f"ERROR {device} LibreNMS request failed: {exc}")
        _record_last_check(settings.storage_root, device.pk)
        return {"ok": False, "error": str(exc)}
    except RuntimeError as exc:
        append_log(settings.storage_root, f"ERROR {device} LibreNMS response invalid: {exc}")
        _record_last_check(settings.storage_root, device.pk)
        return {"ok": False, "error": str(exc)}

    _record_last_check(settings.storage_root, device.pk)

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


def _record_last_check(root: str, device_id: int) -> None:
    marker = device_dir(root, device_id) / "last_check"
    marker.write_text(datetime.now(timezone.utc).isoformat(timespec="seconds"), encoding="utf-8")
