from __future__ import annotations

from datetime import datetime, timezone

from netbox_libreoxi.storage.file_store import LibreOXIFileStore


def compare_and_store(
    *,
    store: LibreOXIFileStore,
    device_key: str,
    content: bytes,
) -> dict[str, object]:
    new_hash = store.sha256(content)
    old_hash = store.read_current_hash(device_key)

    if old_hash == new_hash:
        return {
            "changed": False,
            "hash": new_hash,
        }

    revision_name = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S_%f")
    store.install_new_revision(
        device_key=device_key,
        content=content,
        revision_name=revision_name,
    )
    return {
        "changed": True,
        "hash": new_hash,
        "revision": revision_name,
    }
