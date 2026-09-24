from __future__ import annotations

import hashlib
from pathlib import Path


class LibreOXIFileStore:
    """Filesystem storage for current configuration and revisions."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def device_dir(self, device_key: str) -> Path:
        safe_key = "".join(
            ch if ch.isalnum() or ch in "._-" else "_"
            for ch in device_key
        )
        return self.root / "devices" / safe_key

    @staticmethod
    def sha256(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def read_current(self, device_key: str) -> bytes | None:
        path = self.device_dir(device_key) / "current.cfg"
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    def read_current_hash(self, device_key: str) -> str | None:
        path = self.device_dir(device_key) / "current.sha256"
        try:
            return path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            return None

    def install_new_revision(
        self,
        device_key: str,
        content: bytes,
        revision_name: str,
    ) -> str:
        directory = self.device_dir(device_key)
        history = directory / "history"
        history.mkdir(parents=True, exist_ok=True)

        content_hash = self.sha256(content)
        temp_cfg = directory / "current.cfg.tmp"
        temp_hash = directory / "current.sha256.tmp"
        directory.mkdir(parents=True, exist_ok=True)

        revision_path = history / f"{revision_name}.cfg"
        revision_path.write_bytes(content)

        temp_cfg.write_bytes(content)
        temp_hash.write_text(content_hash + "\n", encoding="ascii")
        temp_cfg.replace(directory / "current.cfg")
        temp_hash.replace(directory / "current.sha256")

        return content_hash
