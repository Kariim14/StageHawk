from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from orchestrator.integrations.urlhaus_client import URLhausClient
from orchestrator.integrations.virustotal_url_client import VirusTotalURLClient


def normalize_url(raw_url: str) -> str:
    value = (raw_url or "").strip()

    if not value:
        raise ValueError("URL is required.")

    parsed = urlparse(value)

    if not parsed.scheme:
        value = "http://" + value
        parsed = urlparse(value)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")

    if not parsed.netloc:
        raise ValueError("URL must include a valid host.")

    return value


def lookup_url_reputation(raw_url: str) -> dict[str, Any]:
    url = normalize_url(raw_url)

    vt = VirusTotalURLClient().lookup_url(url)
    uh = URLhausClient().lookup_url(url)

    vt_malicious = int(vt.get("malicious") or 0) if vt.get("status") == "found" else 0
    vt_suspicious = int(vt.get("suspicious") or 0) if vt.get("status") == "found" else 0
    urlhaus_found = uh.get("status") == "found"

    if urlhaus_found and vt_malicious >= 5:
        verdict = "known_malicious_url_confirmed_by_multiple_sources"
        confidence = "high"
    elif urlhaus_found:
        verdict = "known_malicious_url_in_urlhaus"
        confidence = "high"
    elif vt_malicious >= 10:
        verdict = "malicious_url_reputation_in_virustotal"
        confidence = "medium-high"
    elif vt_malicious >= 3:
        verdict = "suspicious_url_reputation_in_virustotal"
        confidence = "medium"
    elif vt_malicious > 0 or vt_suspicious > 0:
        verdict = "weak_url_reputation_signal"
        confidence = "low"
    elif vt.get("status") == "found" or uh.get("status") == "not_found":
        verdict = "no_malicious_url_reputation_found"
        confidence = "low-medium"
    else:
        verdict = "inconclusive_url_reputation"
        confidence = "unknown"

    if verdict.startswith("known_malicious"):
        label = "Known malicious URL"
    elif verdict.startswith("malicious"):
        label = "Malicious URL reputation"
    elif verdict.startswith("suspicious"):
        label = "Suspicious URL reputation"
    elif verdict == "weak_url_reputation_signal":
        label = "Weak URL reputation signal"
    elif verdict == "no_malicious_url_reputation_found":
        label = "No malicious URL reputation found"
    else:
        label = "Inconclusive URL reputation"

    return {
        "input_url": raw_url,
        "normalized_url": url,
        "verdict": verdict,
        "label": label,
        "confidence": confidence,
        "summary": {
            "virustotal_malicious": vt_malicious,
            "virustotal_suspicious": vt_suspicious,
            "urlhaus_found": urlhaus_found,
            "urlhaus_status": uh.get("status"),
            "virustotal_status": vt.get("status"),
        },
        "providers": {
            "virustotal_url": vt,
            "urlhaus": uh,
        },
        "note": "This lookup queries threat-intelligence providers only. It does not browse, execute, or download the URL.",
    }
