"""Final JSON and Markdown report generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from orchestrator.analysis.verdict_engine import build_report_verdict_context


LIMITATIONS = [
    "Real memory dumping is not implemented yet.",
    "CAPE sandbox submission/import is implemented, but depends on the local CAPE VM and machinery configuration.",
    "Debugger-assisted debugger-assisted reverse-engineering is planned as a future enhancement, not part of the current automated pipeline.",
    "Real unpacked shellcode reconstruction is not implemented.",
    "Production-grade malware triage is future work.",
    "Real malware execution is disabled by default and must remain quarantine/sandbox-only.",
]


def _build_signature_quality_summary(signature: dict[str, Any]) -> dict[str, Any]:
    engines = signature.get("engines", {}) if isinstance(signature, dict) else {}
    yara = engines.get("yara", {}) if isinstance(engines, dict) else {}
    clamav = engines.get("clamav", {}) if isinstance(engines, dict) else {}
    catalog = signature.get("signature_catalog", {}) if isinstance(signature, dict) else {}
    collections = catalog.get("collections", {}) if isinstance(catalog, dict) else {}
    yara_matches = yara.get("matches", []) or []

    match_quality_counts: dict[str, int] = {}
    match_collections: dict[str, int] = {}
    for match in yara_matches:
        quality = match.get("quality", "unknown")
        collection = match.get("collection", "unknown")
        match_quality_counts[quality] = match_quality_counts.get(quality, 0) + 1
        match_collections[collection] = match_collections.get(collection, 0) + 1

    notes = [
        "Generic local YARA rules are heuristic triage signals; they do not confirm malware by themselves.",
        "Known-family attribution is only valid for verified rules in the known_families collection.",
    ]
    if signature.get("verdict") == "no_signature_sources_configured":
        notes.append("No local signature sources were configured for this run.")
    if clamav.get("status") == "unavailable":
        notes.append("The ClamAV engine was unavailable; this is not evidence that the sample is clean.")

    return {
        "catalog_loaded": bool(catalog.get("metadata_loaded")) if isinstance(catalog, dict) else False,
        "catalog_path": catalog.get("metadata_path") if isinstance(catalog, dict) else None,
        "collections": collections,
        "yara_rule_count": len(yara.get("rules_loaded", []) or []),
        "yara_match_count": yara.get("match_count", len(yara_matches)),
        "match_quality_counts": match_quality_counts,
        "match_collections": match_collections,
        "notes": notes,
    }


def build_final_report(
    manifest: dict[str, Any],
    input_metadata: dict[str, Any],
    static_summary: dict[str, Any],
    stage_candidates: list[dict[str, Any]],
    runtime_events: dict[str, Any],
    artifacts: list[dict[str, Any]],
    graph: dict[str, Any],
    iocs: dict[str, list[str]],
    mitre_mappings: list[dict[str, str]],
    backend_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    backend_status = backend_status or {}
    cape_result = backend_status.get("cape_result") or {}

    signature_scan: dict[str, Any] = {}
    signature_path = (manifest.get("output_paths") or {}).get("signature_scan")
    if signature_path:
        try:
            signature_scan = json.loads(Path(str(signature_path)).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            signature_scan = {
                "verdict": "unavailable",
                "summary": {
                    "matched_engine_count": 0,
                    "clean_engine_count": 0,
                    "unavailable_engine_count": 0,
                    "not_configured_engine_count": 0,
                    "error_engine_count": 1,
                    "total_match_count": 0,
                },
                "engines": {},
                "error": "failed to read signature_scan.json",
            }

    signature_summary = signature_scan.get("summary", {}) if isinstance(signature_scan, dict) else {}
    signature_quality = _build_signature_quality_summary(signature_scan)

    summary = {
        "analysis_mode": manifest.get("analysis_mode"),
        "selected_backends": manifest.get("selected_backends", {}),
        "artifact_count": len(artifacts),
        "stage_artifact_count": len([a for a in artifacts if a.get("is_stage_artifact")]),
        "high_value_artifact_count": len([a for a in artifacts if a.get("high_value_artifact")]),
        "graph_artifact_count": len([a for a in artifacts if a.get("graph_include", a.get("is_stage_artifact"))]),
        "ioc_count": sum(len(v) for v in iocs.values()),
        "ioc_type_count": len(iocs),
        "mitre_mapping_count": len(mitre_mappings),
        "graph_node_count": len(graph.get("nodes", [])),
        "graph_edge_count": len(graph.get("edges", [])),
        "signature_verdict": signature_scan.get("verdict"),
        "signature_match_count": signature_summary.get("total_match_count", 0),
    }

    selected = manifest.get("selected_backends", {}) or {}
    backend_summary = {
        "static": "Ghidra" if selected.get("ghidra") else ("Basic static analysis" if selected.get("static") else "Not selected"),
        "dynamic": "CAPE Sandbox" if selected.get("cape") else "Not selected",
        "debugger_assisted_tracing": "Future enhancement: debugger-assisted reverse-engineering module",
    }
    future_enhancements = [
        {
            "name": "Debugger-assisted reverse engineering",
            "tool": "debugger",
            "purpose": "Validate transition points, inspect API arguments, and dump memory buffers at unpacking/decryption moments.",
            "status": "planned_future_work",
        }
    ]
    summary["backend_summary"] = backend_summary
    summary["future_enhancements"] = future_enhancements

    return {
        "schema_version": "1.1",
        "backend_summary": backend_summary,
        "future_enhancements": future_enhancements,
        "case": {
            "case_id": manifest.get("case_id"),
            "case_name": manifest.get("case_name"),
            "analysis_mode": manifest.get("analysis_mode"),
            "selected_backends": manifest.get("selected_backends", {}),
            "current_status": manifest.get("current_status"),
            "created_at": manifest.get("timestamps", {}).get("created_at"),
        },
        "summary": summary,
        # Backward/simple aliases for web/chatbot consumers.
        "analysis_mode": manifest.get("analysis_mode"),
        "selected_backends": manifest.get("selected_backends", {}),
        "artifacts": artifacts,
        "mitre_mappings": mitre_mappings,
        "safety_note": (
            "Defensive academic workflow. Dynamic execution is intended only for "
            "the isolated Windows VM. Real malware mode is disabled by default."
        ),
        "input_sample": input_metadata,
        "backend_status": backend_status,
        "static_analysis_summary": static_summary,
        "signature_scan": signature_scan,
        "signature_quality": signature_quality,
        "stage_candidate_summary": {
            "candidate_count": len(stage_candidates),
            "top_candidates": stage_candidates[:10],
        },
        "dynamic_analysis_summary": {
            "event_count": runtime_events.get("event_count", 0),
            "api_counts": runtime_events.get("api_counts", {}),
            "stage_counts": runtime_events.get("stage_counts", {}),
            "source": runtime_events.get("input_log") or runtime_events.get("input_evidence_dir"),
        },
        "cape_analysis_summary": {
            "status": cape_result.get("status", "skipped"),
            "mode": cape_result.get("mode"),
            "task_id": (cape_result.get("summary") or {}).get("task_id") or cape_result.get("task_id"),
            "score": (cape_result.get("summary") or {}).get("score"),
            "signature_count": (cape_result.get("summary") or {}).get("signature_count", 0),
            "dropped_artifact_count": len((cape_result.get("summary") or {}).get("copied_artifacts", [])),
            "reason": cape_result.get("reason"),
        },
        "runtime_evidence_summary": {
            "marker_count": len([a for a in artifacts if a.get("artifact_kind") == "api_hit_marker"]),
            "dropped_stage_artifact_count": len([a for a in artifacts if a.get("is_stage_artifact")]),
        },
        "extracted_artifacts": artifacts,
        "recursive_analysis_results": [
            {
                "artifact": a.get("destination_path") or a.get("path"),
                "status": a.get("analysis_status", "static_skipped"),
                "reason": a.get("analysis_skip_reason", "not a supported PE or recursion disabled"),
            }
            for a in artifacts
            if a.get("is_stage_artifact")
        ],
        "stage_graph": graph,
        "iocs": iocs,
        "mitre_style_mapping": mitre_mappings,
        "limitations": LIMITATIONS,
        "next_steps": [
            "Optional future enhancement: add debugger-assisted memory-buffer validation using a debugger.",
            "Add optional real Windows VM dynamic run mode once the lab is configured.",
            "Keep CAPE VM tags, snapshots, and result-server networking validated as the sandbox changes.",
            "Build GUI/web/chatbot adapters on top of run_full_pipeline().",
        ],
    }


def write_final_report(report: dict[str, Any], output_dir: str | Path) -> dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "final_report.json"
    md_path = out / "final_report.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    case = report["case"]
    sample = report["input_sample"]
    summary = report.get("summary", {})
    static = report.get("static_analysis_summary", {})
    signature = report.get("signature_scan", {}) or {}
    signature_engines = signature.get("engines", {}) if isinstance(signature, dict) else {}
    yara = signature_engines.get("yara", {}) if isinstance(signature_engines, dict) else {}
    clamav = signature_engines.get("clamav", {}) if isinstance(signature_engines, dict) else {}
    cape = report.get("cape_analysis_summary", {})
    runtime = report.get("runtime_evidence_summary", {})
    timing = report.get("timing", {}) if isinstance(report.get("timing", {}), dict) else {}
    timing_steps = timing.get("steps", {}) if isinstance(timing.get("steps", {}), dict) else {}
    graph = report.get("stage_graph", {})
    iocs = report.get("iocs", {})
    mappings = report.get("mitre_style_mapping", [])
    recursive = report.get("recursive_analysis_results", [])
    artifacts = report.get("extracted_artifacts", [])
    signature_quality = _build_signature_quality_summary(signature)
    report["signature_quality"] = signature_quality

    signature_verdict = signature.get("verdict", "not available")
    cape_status = cape.get("status", "not selected")
    cape_score = cape.get("score")
    sig_matches = (signature.get("summary") or {}).get("total_match_count", 0)
    yara_matches = yara.get("matches", []) or []
    clamav_matches = clamav.get("matches", []) or []
    cape_sigs = cape.get("signature_count", 0)
    artifact_count = summary.get("artifact_count", 0)
    ioc_count = summary.get("ioc_count", 0)
    mapping_count = summary.get("mitre_mapping_count", 0)

    generic_only_signature = (
        signature_verdict == "matched_known_signature"
        and signature_quality.get("match_collections", {}).get("generic", 0) > 0
        and signature_quality.get("match_collections", {}).get("known_families", 0) == 0
    )

    if signature_verdict == "matched_known_signature" and generic_only_signature:
        assessment = "Generic local signature heuristic matched"
        confidence = "medium"
    elif signature_verdict == "matched_known_signature":
        assessment = "Verified local signature match detected"
        confidence = "high"
    elif cape_status == "completed" and ((cape_score or 0) >= 7 or cape_sigs >= 10):
        assessment = "Suspicious behavior observed in sandbox"
        confidence = "medium-high"
    elif cape_status == "completed" and (artifact_count or 0) > 0:
        assessment = "Runtime activity observed; manual review recommended"
        confidence = "medium"
    elif case.get("analysis_mode") == "static":
        assessment = "Static-only evidence collected"
        confidence = "medium"
    else:
        assessment = "No confirmed malicious verdict from configured engines"
        confidence = "low-medium"

    report["analysis_assessment"] = {
        "assessment": assessment,
        "confidence": confidence,
        "basis": {
            "signature_verdict": signature_verdict,
            "signature_matches": sig_matches,
            "cape_status": cape_status,
            "cape_score": cape_score,
            "cape_signature_count": cape_sigs,
            "artifact_count": artifact_count,
            "ioc_count": ioc_count,
            "mitre_mapping_count": mapping_count,
        },
        "note": "Assessment is evidence-based and does not assign malware family attribution unless a signature or reputation source supports it.",
    }

    # Verdict Engine v2: persist the same calibrated verdict used by the HTML report.
    try:
        verdict_context = build_report_verdict_context(report, root=out.parent)
        report["analysis_assessment"] = verdict_context["assessment"]
        report["stagehawk_score"] = verdict_context["stagehawk_score"]
        report["maliciousness"] = verdict_context["maliciousness"]
        report["behavior_classification"] = verdict_context["behavior_classification"]
        report["external_reputation"] = verdict_context["reputation"]

        assessment = verdict_context["assessment"].get("assessment", assessment)
        confidence = verdict_context["assessment"].get("confidence", confidence)
    except Exception as exc:
        report["verdict_engine_error"] = str(exc)

    # Re-write JSON after adding assessment.
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines: list[str] = [
        "# Malware Analysis Report",
        "",
        "## 1. Executive Summary",
        "",
        f"- **Assessment:** {assessment}",
        f"- **Confidence:** `{confidence}`",
        f"- **Maliciousness likelihood:** `{(report.get('maliciousness') or {}).get('score', 'N/A')}/100` — {(report.get('maliciousness') or {}).get('label', 'not calculated')}",
        f"- **Behavior classification:** `{(report.get('behavior_classification') or {}).get('label', 'not calculated')}`",
        f"- **External reputation:** `{(report.get('external_reputation') or {}).get('verdict', 'not checked')}`",
        f"- **Case ID:** `{case.get('case_id')}`",
        f"- **Case name:** `{case.get('case_name')}`",
        f"- **Status:** `{case.get('current_status')}`",
        f"- **Analysis mode:** `{case.get('analysis_mode')}`",
        f"- **Static backend:** `{report.get('backend_summary', {}).get('static')}`",
        f"- **Dynamic backend:** `{report.get('backend_summary', {}).get('dynamic')}`",
        "",
        "This report is generated from collected evidence only. It does not claim malware-family attribution unless a configured signature, sandbox result, or external reputation source supports that claim.",
        "",
        "### Key Counts",
        "",
        f"- Artifacts collected: `{summary.get('artifact_count', 0)}`",
        f"- Stage-like artifacts: `{summary.get('stage_artifact_count', 0)}`",
        f"- High-value artifacts: `{summary.get('high_value_artifact_count', 0)}`",
        f"- Graph-selected artifacts: `{summary.get('graph_artifact_count', 0)}`",
        f"- IOCs extracted: `{summary.get('ioc_count', 0)}`",
        f"- MITRE-style mappings: `{summary.get('mitre_mapping_count', 0)}`",
        f"- Stage graph nodes/edges: `{summary.get('graph_node_count', 0)}` / `{summary.get('graph_edge_count', 0)}`",
        f"- Local signature matches: `{sig_matches}`",
        f"- CAPE score: `{cape_score}`",
        f"- CAPE signatures: `{cape_sigs}`",
        "",
        "## 2. Scope and Methodology",
        "",
        "- The sample was processed by the local orchestrator pipeline.",
        "- Static analysis uses local metadata extraction and Ghidra when configured.",
        "- Local signature scanning uses configured YARA rules and ClamAV when available.",
        "- Dynamic analysis is performed only through the configured CAPE sandbox and isolated Windows VM.",
        "- Extracted artifacts are tracked and checked for recursive static-analysis eligibility.",
        "- ATT&CK-style mappings are produced from observed/static evidence and should be treated as analyst-supporting mappings, not automatic attribution.",
        "",
        "## 3. Sample Identification",
        "",
        f"- File name: `{sample.get('name')}`",
        f"- Size: `{sample.get('size')}` bytes",
        f"- SHA-256: `{sample.get('sha256')}`",
        f"- SHA-1: `{sample.get('sha1')}`",
        f"- MD5: `{sample.get('md5')}`",
        "",
        "## 4. Overall Evidence-Based Assessment",
        "",
        f"- Assessment: **{assessment}**",
        f"- Confidence: `{confidence}`",
        f"- Basis:",
        f"  - Signature verdict: `{signature_verdict}`",
        f"  - Signature matches: `{sig_matches}`",
        f"  - CAPE status: `{cape_status}`",
        f"  - CAPE score: `{cape_score}`",
        f"  - CAPE signatures: `{cape_sigs}`",
        f"  - Artifacts collected: `{artifact_count}`",
        f"  - IOCs extracted: `{ioc_count}`",
        "",
        "## 5. Local Signature Scan",
        "",
        f"- Verdict: `{signature_verdict}`",
        f"- Total local signature matches: `{sig_matches}`",
        f"- YARA status: `{yara.get('status', 'not available')}`",
        f"- YARA available: `{yara.get('available')}`",
        f"- YARA rules loaded: `{len(yara.get('rules_loaded', []))}`",
        f"- YARA match count: `{yara.get('match_count', len(yara_matches))}`",
        f"- ClamAV status: `{clamav.get('status', 'not available')}`",
        f"- ClamAV available: `{clamav.get('available')}`",
    ]

    if yara.get("error"):
        lines.append(f"- YARA note: `{yara.get('error')}`")
    if clamav.get("error"):
        lines.append(f"- ClamAV note: `{clamav.get('error')}`")

    lines.extend([
        "",
        "### Signature Quality and Source",
        "",
        f"- Catalog metadata loaded: `{signature_quality.get('catalog_loaded')}`",
        f"- Catalog metadata path: `{signature_quality.get('catalog_path') or 'not available'}`",
        "- Generic local YARA rules are heuristic triage signals; they do not confirm malware by themselves.",
        "- Known-family attribution is only valid for verified rules in the `known_families` collection.",
    ])
    if signature_verdict == "no_signature_sources_configured":
        lines.append("- No local signature sources were configured for this run.")
    if clamav.get("status") == "unavailable":
        lines.append("- The ClamAV engine was unavailable; this is not evidence that the sample is clean.")

    collections = signature_quality.get("collections", {}) or {}
    if collections:
        lines.extend(["", "#### Local Signature Collections", ""])
        for name in ("generic", "known_families", "experimental"):
            collection = collections.get(name, {}) or {}
            lines.append(
                f"- `{name}`: quality `{collection.get('quality', 'unknown')}`, "
                f"rule files `{len(collection.get('rule_files', []) or [])}`, "
                f"{collection.get('confidence_meaning', 'source quality not available')}"
            )

    if yara_matches or clamav_matches:
        lines.extend(["", "### Signature Matches", ""])
        for match in yara_matches[:30]:
            lines.append(
                f"- YARA `{match.get('rule')}` from `{match.get('source_rule_file')}` "
                f"(collection `{match.get('collection', 'unknown')}`, "
                f"quality `{match.get('quality', 'unknown')}`: "
                f"{match.get('confidence_meaning', 'source quality not available')})"
            )
        for match in clamav_matches[:30]:
            lines.append(f"- ClamAV `{match.get('signature')}`")
    else:
        lines.extend([
            "",
            "No local known-malware signature match was recorded. This does not mean the sample is benign if signature sources are unavailable or not configured.",
        ])

    lines.extend([
        "",
        "## 6. Static Analysis Findings",
        "",
    ])

    for key, value in static.items():
        lines.append(f"- {key}: `{value}`")

    lines.extend([
        "",
        "### Stage/Behavior Candidates",
        "",
        f"- Candidate count: `{report.get('stage_candidate_summary', {}).get('candidate_count', 0)}`",
    ])

    candidates = report.get("stage_candidate_summary", {}).get("top_candidates", []) or []
    if candidates:
        for item in candidates[:15]:
            lines.append(
                f"- `{item.get('candidate_id')}` — {item.get('reason')} "
                f"(confidence `{item.get('confidence')}`)"
            )
    else:
        lines.append("- No stage candidates were produced.")

    lines.extend([
        "",
        "## 7. CAPE Sandbox Dynamic Behavior",
        "",
        f"- Status: `{cape.get('status')}`",
        f"- Mode: `{cape.get('mode')}`",
        f"- Task ID: `{cape.get('task_id')}`",
        f"- Score: `{cape.get('score')}`",
        f"- Signature count: `{cape.get('signature_count')}`",
        f"- Dropped artifacts copied: `{cape.get('dropped_artifact_count')}`",
        f"- Reason: `{cape.get('reason')}`",
        "",
        "### Runtime Evidence Summary",
        "",
        f"- API hit markers: `{runtime.get('marker_count')}`",
        f"- Dropped stage artifacts: `{runtime.get('dropped_stage_artifact_count')}`",
        "",
    ])

    cape_timing_keys = [
        "cape_submission",
        "cape_sandbox_wait",
        "cape_import",
        "cape_artifact_copy",
        "cape_total",
    ]
    cape_timing = {key: timing_steps.get(key) for key in cape_timing_keys if timing_steps.get(key)}
    if cape_timing:
        lines.extend([
            "### CAPE Phase Timing",
            "",
            "CAPE phase timing is recorded at existing safe orchestration boundaries. Report import and artifact copy are timed separately at the nearest boundary inside the CAPE import workflow.",
        ])
        for key in cape_timing_keys:
            item = cape_timing.get(key)
            if item:
                lines.append(
                    f"- `{key}`: `{item.get('duration_seconds', '-')}` seconds "
                    f"({item.get('status', '-')})"
                )
        lines.append("")

    lines.extend([
        "## 8. Extracted Artifacts and Stage Graph",
        "",
        f"- Graph nodes: `{len(graph.get('nodes', []))}`",
        f"- Graph edges: `{len(graph.get('edges', []))}`",
        "",
    ])

    stage_artifacts = [a for a in artifacts if a.get("graph_include", a.get("is_stage_artifact"))]
    if stage_artifacts:
        lines.append("### Graph-Selected High-Value Artifacts")
        lines.append("")
        for artifact in stage_artifacts[:50]:
            lines.append(
                f"- `{artifact.get('stage_id')}` — `{artifact.get('destination_path') or artifact.get('path')}` "
                f"sha256 `{artifact.get('sha256')}`"
            )
    else:
        lines.append("- No real dropped stage-like artifacts were collected in this run.")

    lines.extend([
        "",
        "## 9. Recursive Analysis",
        "",
    ])

    if recursive:
        for item in recursive:
            lines.append(
                f"- `{item.get('artifact')}`: `{item.get('status')}` — {item.get('reason')}"
            )
    else:
        lines.append("- No child artifacts were eligible for recursive static analysis.")

    lines.extend([
        "",
        "## 10. Indicators of Compromise",
        "",
    ])

    if iocs:
        for key, values in iocs.items():
            lines.append(f"### {key} ({len(values)})")
            if values:
                for value in values[:100]:
                    lines.append(f"- `{value}`")
            else:
                lines.append("- None")
            lines.append("")
    else:
        lines.append("- No IOCs were extracted.")

    lines.extend([
        "## 11. MITRE ATT&CK-Style Mapping",
        "",
        "Mappings below are generated from observed/static evidence and should be reviewed by an analyst before operational use.",
        "",
    ])

    if mappings:
        for item in mappings[:100]:
            lines.append(
                f"- `{item.get('source_api')}` → {item.get('label')} "
                f"(`{item.get('technique_id')}`, `{item.get('mapping_type')}`)"
            )
    else:
        lines.append("- No behavior mappings were produced.")

    lines.extend([
        "",
        "## 12. Limitations",
        "",
    ])
    for limitation in report.get("limitations", []):
        lines.append(f"- {limitation}")

    lines.extend([
        "",
        "## 13. Recommended Next Actions",
        "",
    ])

    recommendations = [
        "Review CAPE signatures and dropped artifacts manually before operational classification.",
        "Configure local YARA rules and ClamAV signatures for stronger known-malware detection.",
        "Add VirusTotal or another reputation provider to compare local findings with external intelligence.",
        "Perform recursive static analysis on supported extracted PE/MZ payloads and review skipped artifacts.",
        "Use the stage graph to prioritize child artifacts with hashes, dropped-file evidence, or suspicious behavior.",
    ]
    for item in recommendations:
        lines.append(f"- {item}")

    lines.extend([
        "",
        "## 14. Evidence Appendix",
        "",
        f"- Final JSON report: `final_report.json`",
        f"- Markdown report: `final_report.md`",
        f"- Stage graph JSON/DOT/Markdown: `graph/`",
        f"- Static analysis output: `static/`",
        f"- CAPE output: `cape/`",
        f"- Extracted artifacts: `extracted/`",
    ])

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"final_report_json": str(json_path), "final_report_md": str(md_path)}

# === StageHawk report timing injection v1 ===
from pathlib import Path as _TimingPath
import json as _timing_json

_write_final_report_raw_timing = write_final_report


def write_final_report(report: dict[str, Any], out: _TimingPath) -> dict[str, str]:
    out = _TimingPath(out)
    timing_path = out.parent / "case_timing.json"
    if timing_path.exists():
        try:
            report["timing"] = _timing_json.loads(timing_path.read_text(encoding="utf-8"))
        except Exception as exc:
            report["timing"] = {"status": "error", "error": str(exc)}

    paths = _write_final_report_raw_timing(report, out)

    # Re-write JSON once more after timing is available, because the raw writer may
    # have generated the JSON before this wrapper injected timing in older flows.
    json_path = out / "final_report.json"
    if timing_path.exists() and json_path.exists():
        try:
            data = _timing_json.loads(json_path.read_text(encoding="utf-8"))
            data["timing"] = report.get("timing", {})
            json_path.write_text(_timing_json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    return paths
