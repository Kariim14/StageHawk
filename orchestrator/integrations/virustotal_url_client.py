from __future__ import annotations

import base64
import os
from typing import Any

import requests


def vt_url_id(url: str) -> str:
    """VirusTotal v3 URL identifier: URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


class VirusTotalURLClient:
    def __init__(
        self,
        api_key: str | None = None,
        api_base: str = "https://www.virustotal.com/api/v3",
        timeout: int = 30,
    ) -> None:
        self.api_key = api_key or os.environ.get("VT_API_KEY", "")
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout

    def lookup_url(self, url: str) -> dict[str, Any]:
        if not self.api_key:
            return {
                "provider": "virustotal_url",
                "status": "not_configured",
                "reason": "VT_API_KEY is missing.",
            }

        url_id = vt_url_id(url)

        try:
            response = requests.get(
                f"{self.api_base}/urls/{url_id}",
                headers={
                    "x-apikey": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": "StageHawk-Malware-Orchestrator/1.0",
                },
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return {
                "provider": "virustotal_url",
                "status": "error",
                "reason": str(exc),
            }

        if response.status_code == 404:
            return {
                "provider": "virustotal_url",
                "status": "not_found",
                "url_id": url_id,
                "reason": "URL was not found in VirusTotal URL reports.",
            }

        try:
            data = response.json()
        except ValueError:
            return {
                "provider": "virustotal_url",
                "status": "error",
                "http_status": response.status_code,
                "reason": "Non-JSON response from VirusTotal.",
                "response_preview": response.text[:300],
            }

        if response.status_code != 200:
            error = data.get("error") or {}
            return {
                "provider": "virustotal_url",
                "status": "error",
                "http_status": response.status_code,
                "reason": error.get("message") or "VirusTotal URL request failed.",
                "code": error.get("code"),
            }

        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}

        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)

        return {
            "provider": "virustotal_url",
            "status": "found",
            "url_id": url_id,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "reputation": attrs.get("reputation"),
            "last_final_url": attrs.get("last_final_url"),
            "title": attrs.get("title"),
            "categories": attrs.get("categories") or {},
            "threat_names": attrs.get("threat_names") or [],
            "last_analysis_date": attrs.get("last_analysis_date"),
            "raw_included": False,
        }
