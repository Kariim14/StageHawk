from __future__ import annotations

import re
from typing import Any

from orchestrator.integrations.malwarebazaar_client import MalwareBazaarClient
from orchestrator.integrations.virustotal_client import VirusTotalClient


HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")


def classify_hash(value: str) -> str | None:
    cleaned = value.strip().lower()
    if not HASH_RE.match(cleaned):
        return None
    if len(cleaned) == 32:
        return "md5"
    if len(cleaned) == 40:
        return "sha1"
    if len(cleaned) == 64:
        return "sha256"
    return None


def _vt_verdict(vt: dict[str, Any]) -> tuple[str, int, int]:
    stats = vt.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)

    if vt.get("status") != "found":
        return vt.get("status", "unknown"), malicious, suspicious

    if malicious > 0:
        return "malicious", malicious, suspicious
    if suspicious > 0:
        return "suspicious", malicious, suspicious
    return "no_malicious_detection", malicious, suspicious


def lookup_hash_reputation(value: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    config = config or {}
    cleaned = value.strip().lower()
    hash_type = classify_hash(cleaned)

    if not hash_type:
        return {
            "query": value,
            "status": "invalid",
            "hash_type": None,
            "verdict": "invalid_input",
            "reason": "Input is not a valid MD5, SHA1, or SHA256 hash.",
            "providers": {},
        }

    vt_config = config.get("virustotal", {}) if isinstance(config, dict) else {}
    mb_config = config.get("malwarebazaar", {}) if isinstance(config, dict) else {}

    vt = VirusTotalClient(
        api_key=vt_config.get("api_key"),
        base_url=vt_config.get("base_url", "https://www.virustotal.com/api/v3"),
        timeout=int(vt_config.get("timeout_seconds", 30)),
    ).get_file_report(cleaned)

    mb = MalwareBazaarClient(
        api_key=mb_config.get("api_key"),
        api_url=mb_config.get("api_url", "https://mb-api.abuse.ch/api/v1/"),
        timeout=int(mb_config.get("timeout_seconds", 30)),
    ).get_hash_info(cleaned)

    vt_status, vt_malicious, vt_suspicious = _vt_verdict(vt)
    mb_found = mb.get("status") == "found"

    provider_statuses = {
        "virustotal": vt.get("status"),
        "malwarebazaar": mb.get("status"),
    }

    # Reputation thresholding:
    # - MalwareBazaar "found" is strong known-malware evidence.
    # - A small number of VT detections (1-2) is treated as a weak signal, not a malicious verdict.
    # - VT malicious >= 10 is strong enough to call malicious reputation.
    # - VT malicious 3-9 is suspicious reputation and should be reviewed.
    if mb_found and vt_malicious >= 10:
        verdict = "known_malware_confirmed_by_multiple_sources"
        confidence = "high"
    elif mb_found:
        verdict = "known_malware_in_malwarebazaar"
        confidence = "high"
    elif vt_malicious >= 10:
        verdict = "malicious_reputation_in_virustotal"
        confidence = "medium-high"
    elif vt_malicious >= 3:
        verdict = "suspicious_reputation_in_virustotal"
        confidence = "medium"
    elif vt_malicious > 0 or vt_suspicious > 0:
        verdict = "weak_reputation_signal"
        confidence = "low"
    elif vt.get("status") == "found":
        verdict = "no_malicious_reputation_seen"
        confidence = "low-medium"
    elif all(v in {"unavailable", "error", "unauthorized", "rate_limited"} for v in provider_statuses.values()):
        verdict = "reputation_providers_unavailable"
        confidence = "none"
    elif all(v == "not_found" for v in provider_statuses.values()):
        verdict = "not_found_in_configured_reputation_sources"
        confidence = "low"
    else:
        verdict = "inconclusive_reputation"
        confidence = "low"

    return {
        "query": cleaned,
        "hash_type": hash_type,
        "status": "completed",
        "verdict": verdict,
        "confidence": confidence,
        "summary": {
            "provider_statuses": provider_statuses,
            "virustotal_malicious": vt_malicious,
            "virustotal_suspicious": vt_suspicious,
            "malwarebazaar_found": mb_found,
            "malwarebazaar_signature": mb.get("signature"),
            "malwarebazaar_tags": mb.get("tags") or [],
        },
        "providers": {
            "virustotal": vt,
            "malwarebazaar": mb,
        },
    }
