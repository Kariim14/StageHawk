from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class VirusTotalClient:
    api_key: str | None = None
    base_url: str = "https://www.virustotal.com/api/v3"
    timeout: int = 30

    def __post_init__(self) -> None:
        self.api_key = self.api_key or os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
        self.base_url = self.base_url.rstrip("/")

    def available(self) -> bool:
        return bool(self.api_key)

    def get_file_report(self, file_hash: str) -> dict[str, Any]:
        if not self.api_key:
            return {
                "provider": "virustotal",
                "status": "unavailable",
                "reason": "VirusTotal API key not configured.",
            }

        try:
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers={"accept": "application/json", "x-apikey": self.api_key},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return {
                "provider": "virustotal",
                "status": "error",
                "reason": str(exc),
            }

        if response.status_code == 404:
            return {
                "provider": "virustotal",
                "status": "not_found",
                "reason": "Hash not found in VirusTotal.",
                "http_status": 404,
            }

        if response.status_code in {401, 403}:
            return {
                "provider": "virustotal",
                "status": "unauthorized",
                "reason": "VirusTotal API key rejected or not permitted.",
                "http_status": response.status_code,
            }

        if response.status_code == 429:
            return {
                "provider": "virustotal",
                "status": "rate_limited",
                "reason": "VirusTotal rate limit reached.",
                "http_status": 429,
            }

        if not response.ok:
            return {
                "provider": "virustotal",
                "status": "error",
                "reason": response.text[:500],
                "http_status": response.status_code,
            }

        try:
            data = response.json()
        except ValueError:
            return {
                "provider": "virustotal",
                "status": "error",
                "reason": "Non-JSON response from VirusTotal.",
                "http_status": response.status_code,
            }

        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}

        return {
            "provider": "virustotal",
            "status": "found",
            "http_status": response.status_code,
            "id": (data.get("data") or {}).get("id"),
            "type": (data.get("data") or {}).get("type"),
            "meaningful_name": attrs.get("meaningful_name"),
            "reputation": attrs.get("reputation"),
            "last_analysis_stats": {
                "malicious": int(stats.get("malicious") or 0),
                "suspicious": int(stats.get("suspicious") or 0),
                "undetected": int(stats.get("undetected") or 0),
                "harmless": int(stats.get("harmless") or 0),
                "timeout": int(stats.get("timeout") or 0),
            },
            "last_analysis_date": attrs.get("last_analysis_date"),
            "popular_threat_classification": attrs.get("popular_threat_classification"),
            "tags": attrs.get("tags", []),
            "raw_included": False,
        }
