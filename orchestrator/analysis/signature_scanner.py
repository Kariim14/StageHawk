from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


COLLECTION_MEANINGS: dict[str, dict[str, str]] = {
    "generic": {
        "quality": "generic",
        "confidence_meaning": "heuristic triage signal, not confirmed malware",
    },
    "known_families": {
        "quality": "known_family",
        "confidence_meaning": "verified attributed family rule when populated",
    },
    "experimental": {
        "quality": "experimental",
        "confidence_meaning": "research/testing signal only",
    },
    "unknown": {
        "quality": "unknown",
        "confidence_meaning": "source quality could not be inferred",
    },
}


def _safe_run(cmd: list[str], timeout: int) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "executed": True,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "error": None,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "executed": False,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "error": f"timeout after {timeout} seconds",
        }
    except OSError as exc:
        return {
            "executed": False,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": str(exc),
        }


def _collect_yara_rules(config: dict[str, Any]) -> list[Path]:
    rule_files: list[Path] = []

    for item in config.get("signature_rule_files", []) or []:
        path = Path(str(item)).expanduser()
        if path.exists() and path.is_file():
            rule_files.append(path.resolve())

    for item in config.get("signature_rules_dirs", []) or []:
        root = Path(str(item)).expanduser()
        if root.exists() and root.is_dir():
            for pattern in ("*.yar", "*.yara"):
                rule_files.extend(p.resolve() for p in root.rglob(pattern) if p.is_file())

    # stable, unique order
    return sorted(set(rule_files))


def _find_signature_metadata_path(config: dict[str, Any]) -> Path | None:
    candidates: list[Path] = []
    for item in config.get("signature_rules_dirs", []) or []:
        root = Path(str(item)).expanduser()
        candidates.append(root / "METADATA.json")
        if root.name in COLLECTION_MEANINGS:
            candidates.append(root.parent / "METADATA.json")

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _infer_collection_from_path(path: str | Path) -> str:
    parts = set(Path(str(path)).parts)
    for collection in ("generic", "known_families", "experimental"):
        if collection in parts:
            return collection
    return "unknown"


def _looks_like_yara_rule_name(value: str) -> bool:
    if not value:
        return False
    first = value.split(":", 1)[-1]
    if not (first[0].isalpha() or first[0] == "_"):
        return False
    return all(ch.isalnum() or ch == "_" for ch in first)


def _catalog_rule_files_for_collection(collection: str, rule_files: list[Path]) -> list[str]:
    return [
        str(path)
        for path in rule_files
        if _infer_collection_from_path(path) == collection
    ]


def build_signature_catalog(config: dict[str, Any], rule_files: list[Path] | None = None) -> dict[str, Any]:
    rule_files = rule_files if rule_files is not None else _collect_yara_rules(config)
    metadata_path = _find_signature_metadata_path(config)
    metadata: dict[str, Any] = {}

    if metadata_path:
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            metadata = {}

    collections: dict[str, Any] = {}
    metadata_collections = metadata.get("rule_collections", {}) if isinstance(metadata, dict) else {}

    for collection in ("generic", "known_families", "experimental"):
        source = metadata_collections.get(collection, {}) if isinstance(metadata_collections, dict) else {}
        metadata_rule_files = source.get("rule_files") if isinstance(source, dict) else None
        collections[collection] = {
            "quality": COLLECTION_MEANINGS[collection]["quality"],
            "confidence_meaning": COLLECTION_MEANINGS[collection]["confidence_meaning"],
            "rule_files": metadata_rule_files
            if isinstance(metadata_rule_files, list)
            else _catalog_rule_files_for_collection(collection, rule_files),
        }

    return {
        "metadata_loaded": bool(metadata),
        "metadata_path": str(metadata_path) if metadata_path else None,
        "collections": collections,
    }


def _enrich_yara_match(match: dict[str, Any]) -> dict[str, Any]:
    source_rule_file = match.get("source_rule_file") or ""
    collection = match.get("collection") or _infer_collection_from_path(source_rule_file)
    meaning = COLLECTION_MEANINGS.get(collection, COLLECTION_MEANINGS["unknown"])
    enriched = dict(match)
    enriched.setdefault("collection", collection)
    enriched.setdefault("quality", meaning["quality"])
    enriched.setdefault("confidence_meaning", meaning["confidence_meaning"])
    return enriched


def scan_with_yara(sample_path: str | Path, config: dict[str, Any]) -> dict[str, Any]:
    sample = Path(sample_path).resolve()
    yara_bin = shutil.which(str(config.get("yara_binary", "yara")))
    timeout = int(config.get("signature_scan_timeout_seconds", 120))
    rule_files = _collect_yara_rules(config)

    result: dict[str, Any] = {
        "engine": "yara",
        "available": bool(yara_bin),
        "rules_loaded": [str(p) for p in rule_files],
        "status": "unavailable",
        "matches": [],
        "match_count": 0,
        "error": None,
    }

    if not yara_bin:
        result["error"] = "yara binary not found"
        return result

    if not rule_files:
        result["status"] = "not_configured"
        result["error"] = "no YARA rule files configured"
        return result

    matches: list[dict[str, Any]] = []
    errors: list[str] = []

    for rule in rule_files:
        run = _safe_run([yara_bin, "-r", str(rule), str(sample)], timeout=timeout)

        if run["error"]:
            errors.append(f"{rule}: {run['error']}")
            continue

        # YARA returns 0 when it ran successfully. Matches are printed to stdout.
        if run["returncode"] not in (0,):
            errors.append((run["stderr"] or run["stdout"] or f"{rule}: return code {run['returncode']}").strip())
            continue

        for line in run["stdout"].splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            rule_name = parts[0]
            if not _looks_like_yara_rule_name(rule_name):
                continue
            matches.append(
                _enrich_yara_match(
                    {
                        "rule": rule_name,
                        "source_rule_file": str(rule),
                        "raw": line,
                    }
                )
            )

    result["matches"] = matches
    result["match_count"] = len(matches)
    result["status"] = "matched" if matches else "clean"
    result["error"] = "; ".join(errors) if errors else None
    return result


def scan_with_clamav(sample_path: str | Path, config: dict[str, Any]) -> dict[str, Any]:
    sample = Path(sample_path).resolve()
    clamscan_bin = shutil.which(str(config.get("clamscan_binary", "clamscan")))
    timeout = int(config.get("signature_scan_timeout_seconds", 120))

    result: dict[str, Any] = {
        "engine": "clamav",
        "available": bool(clamscan_bin),
        "status": "unavailable",
        "matches": [],
        "match_count": 0,
        "error": None,
        "raw_stdout": "",
        "raw_stderr": "",
    }

    if not clamscan_bin:
        result["error"] = "clamscan binary not found"
        return result

    run = _safe_run([clamscan_bin, "--no-summary", str(sample)], timeout=timeout)
    result["raw_stdout"] = run["stdout"]
    result["raw_stderr"] = run["stderr"]

    if run["error"]:
        result["status"] = "error"
        result["error"] = run["error"]
        return result

    # clamscan return codes:
    # 0 = no virus found
    # 1 = virus found
    # 2+ = error
    if run["returncode"] == 0:
        result["status"] = "clean"
        return result

    if run["returncode"] == 1:
        result["status"] = "matched"
        for line in run["stdout"].splitlines():
            line = line.strip()
            if not line:
                continue
            # Typical: /path/file: Win.Test.EICAR_HDB-1 FOUND
            if line.endswith("FOUND"):
                left, _, detected = line.partition(":")
                result["matches"].append(
                    {
                        "signature": detected.replace("FOUND", "").strip(),
                        "raw": line,
                        "file": left.strip(),
                    }
                )
        result["match_count"] = len(result["matches"])
        return result

    result["status"] = "error"
    result["error"] = (run["stderr"] or run["stdout"] or f"clamscan return code {run['returncode']}").strip()
    return result


def run_signature_scan(sample_path: str | Path, output_json: str | Path, config: dict[str, Any]) -> dict[str, Any]:
    sample = Path(sample_path).resolve()
    output = Path(output_json)
    output.parent.mkdir(parents=True, exist_ok=True)

    rule_files = _collect_yara_rules(config)
    signature_catalog = build_signature_catalog(config, rule_files)
    yara_result = scan_with_yara(sample, config)
    clamav_result = scan_with_clamav(sample, config)

    engines = [yara_result, clamav_result]
    matched = [engine for engine in engines if engine.get("status") == "matched"]
    unavailable = [engine for engine in engines if engine.get("status") == "unavailable"]
    not_configured = [engine for engine in engines if engine.get("status") == "not_configured"]
    errored = [engine for engine in engines if engine.get("status") == "error"]
    clean = [engine for engine in engines if engine.get("status") == "clean"]

    if matched:
        verdict = "matched_known_signature"
    elif clean:
        verdict = "no_signature_match"
    elif errored and not clean:
        verdict = "error"
    elif len(unavailable) == len(engines):
        verdict = "no_signature_engines_available"
    elif len(unavailable) + len(not_configured) == len(engines):
        verdict = "no_signature_sources_configured"
    else:
        verdict = "no_signature_match"

    result = {
        "schema_version": "1.0",
        "sample_path": str(sample),
        "verdict": verdict,
        "engines": {
            "yara": yara_result,
            "clamav": clamav_result,
        },
        "signature_catalog": signature_catalog,
        "summary": {
            "matched_engine_count": len(matched),
            "clean_engine_count": len(clean),
            "unavailable_engine_count": len(unavailable),
            "not_configured_engine_count": len(not_configured),
            "error_engine_count": len(errored),
            "total_match_count": sum(len(engine.get("matches", [])) for engine in engines),
        },
    }

    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
