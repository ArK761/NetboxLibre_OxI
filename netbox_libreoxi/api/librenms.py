from __future__ import annotations

from dataclasses import dataclass

import requests


class LibreNMSAPIError(RuntimeError):
    pass


@dataclass(frozen=True)
class LibreNMSClient:
    base_url: str
    oxidized_path: str
    api_token: str
    timeout: int = 10
    verify_tls: bool = True

    def fetch_config(self, address: str) -> bytes:
        url = self.base_url.rstrip("/") + "/" + self.oxidized_path.lstrip("/")
        url = url.rstrip("/") + "/" + address

        response = requests.get(
            url,
            headers={"X-Auth-Token": self.api_token},
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        if response.status_code != 200:
            raise LibreNMSAPIError(
                f"LibreNMS returned HTTP {response.status_code}"
            )

        content = response.content
        if not content.strip():
            raise LibreNMSAPIError("LibreNMS returned an empty configuration")

        return content
