from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path


def device_dir(root: str, device_id: int, create: bool = True) -> Path:
    path = Path(root).expanduser().resolve() / "devices" / str(device_id)
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def read_current(root: str, device_id: int) -> tuple[str | None, str | None]:
    directory = device_dir(root, device_id, create=False)
    cfg = directory / "current.cfg"
    digest = directory / "current.sha256"
    if not cfg.exists():
        return None, None

    content = cfg.read_text(encoding="utf-8", errors="replace")
    stored_hash = (
        digest.read_text(encoding="ascii").strip()
        if digest.exists()
        else sha256(content)
    )
    return content, stored_hash


def store_if_changed(root: str, device_id: int, content: str) -> dict:
    directory = device_dir(root, device_id)
    new_hash = sha256(content)
    _old_content, old_hash = read_current(root, device_id)

    if old_hash == new_hash:
        return {"changed": False, "hash": new_hash, "old_hash": old_hash}

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    history = directory / f"{timestamp}.cfg"
    temp_cfg = directory / "current.cfg.tmp"
    temp_hash = directory / "current.sha256.tmp"

    history.write_text(content, encoding="utf-8")
    temp_cfg.write_text(content, encoding="utf-8")
    temp_hash.write_text(new_hash + "\n", encoding="ascii")
    temp_cfg.replace(directory / "current.cfg")
    temp_hash.replace(directory / "current.sha256")

    return {
        "changed": True,
        "hash": new_hash,
        "old_hash": old_hash,
        "history": str(history),
    }


def list_history(root: str, device_id: int) -> list[Path]:
    directory = device_dir(root, device_id, create=False)
    if not directory.exists():
        return []
    return sorted(directory.glob("*.cfg"), reverse=True)


def cleanup(root: str, device_id: int, retention_days: int, retention_revisions: int) -> None:
    history = list_history(root, device_id)
    cutoff = datetime.now(timezone.utc).timestamp() - (retention_days * 86400)
    kept = 0

    for path in history:
        if path.name == "current.cfg":
            continue

        if path.stat().st_mtime >= cutoff and kept < retention_revisions:
            kept += 1
        else:
            path.unlink(missing_ok=True)


def append_log(root: str, message: str) -> None:
    path = Path(root).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    with (path / "libreoxi.log").open("a", encoding="utf-8") as log:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        log.write(f"{timestamp} {message}\n")
