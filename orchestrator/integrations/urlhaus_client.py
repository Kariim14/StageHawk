from __future__ import annotations

import os
from typing import Any

import requests


class URLhausClient:
    def __init__(
        self,
        api_key: str | None = None,
        api_url: str = "https://urlhaus-api.abuse.ch/v1/url/",
        timeout: int = 30,
    ) -> None:
        self.api_key = api_key or os.environ.get("URLHAUS_AUTH_KEY", "")
        self.api_url = api_url
        self.timeout = timeout

    def lookup_url(self, url: str) -> dict[str, Any]:
        if not self.api_key:
            return {
                "provider": "urlhaus",
                "status": "not_configured",
                "reason": "URLHAUS_AUTH_KEY is missing.",
            }

        try:
            response = requests.post(
                self.api_url,
                headers={
                    "Auth-Key": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": "StageHawk-Malware-Orchestrator/1.0",
                },
                data={"url": url},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return {
                "provider": "urlhaus",
                "status": "error",
                "reason": str(exc),
            }

        content_type = response.headers.get("content-type", "")

        try:
            data = response.json()
        except ValueError:
            return {
                "provider": "urlhaus",
                "status": "error",
                "http_status": response.status_code,
                "content_type": content_type,
                "reason": "Non-JSON response from URLhaus.",
                "response_preview": response.text[:300],
            }

        query_status = data.get("query_status")

        if response.status_code != 200:
            return {
                "provider": "urlhaus",
                "status": "error",
                "http_status": response.status_code,
                "query_status": query_status,
                "reason": data.get("error") or "URLhaus request failed.",
            }

        if query_status == "ok":
            return {
                "provider": "urlhaus",
                "status": "found",
                "query_status": query_status,
                "url": data.get("url"),
                "url_status": data.get("url_status"),
                "host": data.get("host"),
                "date_added": data.get("date_added"),
                "threat": data.get("threat"),
                "blacklists": data.get("blacklists"),
                "tags": data.get("tags") or [],
                "payloads": data.get("payloads") or [],
                "raw_included": False,
            }

        if query_status in {"no_results", "not_found"}:
            return {
                "provider": "urlhaus",
                "status": "not_found",
                "query_status": query_status,
                "reason": "URL was not found in URLhaus.",
            }

        return {
            "provider": "urlhaus",
            "status": "unknown",
            "query_status": query_status,
            "reason": data.get("error") or "URLhaus returned an unrecognized query_status.",
        }
