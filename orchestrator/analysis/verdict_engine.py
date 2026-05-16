from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from orchestrator.analysis.reputation_lookup import lookup_hash_reputation


INSTALLER_HINTS = [
    "setup",
    "install",
    "installer",
    "guest",
    "tools",
    "driver",
    "spice",
    "vmware",
    "virtualbox",
]


HIGH_RISK_CAPE_NAMES = {
    "ransomware_attribute_stripping",
    "mass_file_modification_access",
    "credential_access",
    "credential_dumping",
    "browser_passwords",
    "keylogger",
    "screenshot",
    "injection_rwx",
    "process_injection",
    "dropper",
    "persistence_autorun",
    "persistence_autorun_tasks",
    "persistence_service",
    "procmem_yara",
}


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return default


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def _load_or_lookup_reputation(report: dict[str, Any], root: Path | None) -> dict[str, Any]:
    sample = report.get("input_sample", {}) or {}
    sha256 = sample.get("sha256")
    if not sha256:
        return {"status": "skipped", "verdict": "no_hash_available", "providers": {}, "summary": {}}

    cache_path = None
    if root:
        cache_path = root / "reports" / "reputation_lookup.json"
        if cache_path.exists():
            cached = _load_json(cache_path)
            if cached:
                return cached

    result = lookup_hash_reputation(str(sha256))

    if cache_path:
        try:
            cache_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        except OSError:
            pass

    return result


def _load_cape_signatures(root: Path | None) -> list[dict[str, Any]]:
    if not root:
        return []
    cape_report = root / "cape" / "cape_report.json"
    data = _load_json(cape_report)
    sigs = data.get("signatures") or []
    return sigs if isinstance(sigs, list) else []


def build_report_verdict_context(report: dict[str, Any], root: Path | None = None) -> dict[str, Any]:
    summary = report.get("summary", {}) or {}
    cape = report.get("cape_analysis_summary", {}) or {}
    signature = report.get("signature_scan", {}) or {}
    sig_summary = signature.get("summary", {}) if isinstance(signature, dict) else {}
    sample = report.get("input_sample", {}) or {}
    case = report.get("case", {}) or {}

    reputation = _load_or_lookup_reputation(report, root)
    rep_summary = reputation.get("summary", {}) or {}
    rep_providers = reputation.get("providers", {}) or {}
    vt = rep_providers.get("virustotal", {}) or {}
    mb = rep_providers.get("malwarebazaar", {}) or {}

    vt_malicious = _safe_int(rep_summary.get("virustotal_malicious"))
    vt_suspicious = _safe_int(rep_summary.get("virustotal_suspicious"))
    mb_found = mb.get("status") == "found"

    cape_signatures = _safe_int(cape.get("signature_count"))
    cape_score = _safe_float(cape.get("score"))
    artifact_count = _safe_int(summary.get("artifact_count"))
    stage_artifacts = _safe_int(summary.get("stage_artifact_count"))
    ioc_count = _safe_int(summary.get("ioc_count"))
    mitre_count = _safe_int(summary.get("mitre_mapping_count"))
    signature_matches = _safe_int(sig_summary.get("total_match_count"))
    signature_engines = signature.get("engines", {}) if isinstance(signature, dict) else {}
    yara_matches = (signature_engines.get("yara", {}) or {}).get("matches", []) if isinstance(signature_engines, dict) else []
    clamav_matches = (signature_engines.get("clamav", {}) or {}).get("matches", []) if isinstance(signature_engines, dict) else []
    known_family_signature_matches = len([
        match for match in yara_matches
        if match.get("collection") == "known_families" or match.get("quality") == "known_family"
    ])
    generic_signature_matches = len([
        match for match in yara_matches
        if match.get("collection") == "generic" or match.get("quality") == "generic"
    ])
    experimental_signature_matches = len([
        match for match in yara_matches
        if match.get("collection") == "experimental" or match.get("quality") == "experimental"
    ])
    unknown_yara_signature_matches = max(
        0,
        len(yara_matches)
        - known_family_signature_matches
        - generic_signature_matches
        - experimental_signature_matches,
    )
    strong_signature_matches = (
        known_family_signature_matches
        + len(clamav_matches)
        + unknown_yara_signature_matches
    )

    cape_sig_items = _load_cape_signatures(root)
    high_risk_hits = []
    max_cape_severity = 0

    for sig in cape_sig_items:
        name = str(sig.get("name") or "")
        severity = _safe_int(sig.get("severity"))
        max_cape_severity = max(max_cape_severity, severity)
        if name in HIGH_RISK_CAPE_NAMES or severity >= 4:
            high_risk_hits.append({
                "name": name,
                "severity": severity,
                "description": sig.get("description"),
            })

    sample_name = str(sample.get("name") or case.get("case_name") or "").lower()
    installer_like = any(hint in sample_name for hint in INSTALLER_HINTS) or (
        artifact_count >= 80 and stage_artifacts >= 40 and strong_signature_matches == 0 and not mb_found and vt_malicious <= 2
    )

    # Evidence collection score: how much usable evidence exists, not maliciousness.
    evidence_score = 0
    evidence_breakdown: list[str] = []

    if cape.get("status") == "completed":
        evidence_score += 15
        evidence_breakdown.append("CAPE completed")

    if cape_score > 0:
        added = min(25, int(cape_score * 2.5))
        evidence_score += added
        evidence_breakdown.append(f"CAPE score contributed {added}")

    if cape_signatures:
        added = min(10, max(1, cape_signatures // 4))
        evidence_score += added
        evidence_breakdown.append(f"CAPE signatures contributed {added}")

    if artifact_count:
        added = min(10, max(1, artifact_count // 25))
        evidence_score += added
        evidence_breakdown.append(f"Artifacts contributed {added}")

    if ioc_count:
        added = min(10, max(1, ioc_count // 50))
        evidence_score += added
        evidence_breakdown.append(f"IOCs contributed {added}")

    if mitre_count:
        added = min(10, max(1, mitre_count // 2))
        evidence_score += added
        evidence_breakdown.append(f"Behavior mappings contributed {added}")

    if reputation.get("status") == "completed":
        evidence_score += 15
        evidence_breakdown.append("External reputation lookup completed")

    evidence_score = min(100, evidence_score)

    if evidence_score >= 75:
        evidence_label = "High evidence"
    elif evidence_score >= 45:
        evidence_label = "Medium evidence"
    elif evidence_score > 0:
        evidence_label = "Low evidence"
    else:
        evidence_label = "No scored evidence"

    # Maliciousness likelihood: suspiciousness of evidence.
    malicious_score = 0
    drivers: list[str] = []
    caution: list[str] = []

    if mb_found:
        malicious_score += 45
        drivers.append("MalwareBazaar identifies the hash as known malware")

    if vt_malicious >= 10:
        added = min(35, vt_malicious)
        malicious_score += added
        drivers.append(f"VirusTotal has {vt_malicious} malicious detections")
    elif vt_malicious >= 3:
        malicious_score += 15
        drivers.append(f"VirusTotal has {vt_malicious} malicious detections")
    elif vt_malicious > 0:
        malicious_score += 4
        caution.append(f"Only {vt_malicious} VirusTotal detections; treat as weak signal")

    if strong_signature_matches:
        malicious_score += 35
        drivers.append("Verified local signature matched")

    if generic_signature_matches:
        added = min(10, generic_signature_matches * 3)
        malicious_score += added
        drivers.append("Generic local YARA heuristic matched; analyst review required")
        caution.append("Generic local YARA matches are heuristic triage signals, not confirmed malware")

    if experimental_signature_matches:
        caution.append("Experimental local YARA matches are research/testing signals only")

    if high_risk_hits:
        added = min(25, len(high_risk_hits) * 5)
        malicious_score += added
        drivers.append(f"{len(high_risk_hits)} high-risk CAPE signatures matched")

    # CAPE score/signature count alone is weak because benign installers are noisy.
    if cape_score >= 8 and not installer_like:
        malicious_score += 10
        drivers.append("High CAPE score")
    elif cape_score >= 8 and installer_like:
        caution.append("High CAPE score may be caused by installer/admin-tool behavior")

    if cape_signatures >= 20 and not installer_like:
        malicious_score += 8
        drivers.append("Many CAPE signatures")
    elif cape_signatures >= 20 and installer_like:
        caution.append("Many CAPE signatures may be installer noise")

    if stage_artifacts and not installer_like:
        added = min(8, stage_artifacts)
        malicious_score += added
        drivers.append("Dropped/stage-like artifacts observed")
    elif stage_artifacts and installer_like:
        caution.append("Many dropped files are expected from installers and guest-tools packages")

    if installer_like and not mb_found and vt_malicious <= 2 and strong_signature_matches == 0:
        malicious_score = min(malicious_score, 45)
        behavior_label = "Installer-like / admin-tool behavior"
        assessment_text = "Installer-like behavior observed; maliciousness not confirmed"
        confidence = "medium"
        explanation = "The sample produced noisy sandbox behavior, but external reputation is weak and no local known-malware signature matched. Manual review is recommended."
    elif mb_found or vt_malicious >= 10 or strong_signature_matches:
        behavior_label = "Malicious reputation or signature evidence"
        assessment_text = "Known malicious or strongly malicious evidence observed"
        confidence = "high" if mb_found or strong_signature_matches else "medium-high"
        explanation = "At least one strong reputation/signature source supports malicious classification."
    elif high_risk_hits and malicious_score >= 55:
        behavior_label = "Suspicious sandbox behavior"
        assessment_text = "Suspicious behavior observed in sandbox"
        confidence = "medium-high"
        explanation = "High-risk sandbox signatures were observed, but analyst confirmation is still recommended."
    elif malicious_score >= 35:
        behavior_label = "Suspicious behavior"
        assessment_text = "Suspicious behavior observed; manual review recommended"
        confidence = "medium"
        explanation = "Some suspicious behavior was observed, but strong malware reputation was not confirmed."
    elif case.get("analysis_mode") == "static":
        behavior_label = "Static-only evidence"
        assessment_text = "Inconclusive static-only result"
        confidence = "low-medium"
        explanation = "Only static analysis was performed. A low score does not prove the file is safe."
    else:
        behavior_label = "No strong malicious evidence observed"
        assessment_text = "No strong malicious evidence observed"
        confidence = "low-medium"
        explanation = "Configured evidence sources did not confirm maliciousness. This does not guarantee the file is safe."

    malicious_score = min(100, malicious_score)

    maliciousness = {
        "score": malicious_score,
        "label": behavior_label,
        "drivers": drivers,
        "caution": caution,
        "explanation": explanation,
        "note": "This is a heuristic likelihood indicator, not a calibrated mathematical probability.",
    }

    stagehawk_score = {
        "score": evidence_score,
        "label": evidence_label,
        "breakdown": evidence_breakdown,
        "note": "This is an internal weighted evidence score, not a probability of maliciousness.",
    }

    assessment = {
        "assessment": assessment_text,
        "confidence": confidence,
        "note": "Assessment is evidence-based and does not assign malware family attribution unless a signature or reputation source supports it.",
    }

    behavior_classification = {
        "label": behavior_label,
        "installer_like": installer_like,
        "high_risk_signature_count": len(high_risk_hits),
        "max_cape_severity": max_cape_severity,
        "high_risk_signatures": high_risk_hits[:20],
        "caution": caution,
    }

    return {
        "stagehawk_score": stagehawk_score,
        "maliciousness": maliciousness,
        "assessment": assessment,
        "behavior_classification": behavior_classification,
        "reputation": reputation,
    }
