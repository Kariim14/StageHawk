#!/usr/bin/env python3
"""
ghidra_runner.py
================

Python wrapper around Ghidra headless analysis.

Role in the project:
- Receive a Windows PE sample path.
- Launch Ghidra analyzeHeadless.
- Run ExtractCFG.java.
- Read /tmp/ghidra_out.json.
- Return parsed static-analysis results.

This file is the bridge between:
    Python orchestrator  --->  Ghidra headless  --->  ExtractCFG.java  --->  JSON output
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List


DEFAULT_GHIDRA_HEADLESS = Path("/opt/ghidra/support/analyzeHeadless")
DEFAULT_SCRIPT_DIR = Path.home() / "malproj" / "ghidra_scripts"
DEFAULT_SCRIPT_NAME = "ExtractCFG.java"


class GhidraRunnerError(RuntimeError):
    """Raised when Ghidra analysis fails."""


def _require_file(path: Path, label: str) -> None:
    if not path.exists():
        raise GhidraRunnerError(f"{label} does not exist: {path}")
    if not path.is_file():
        raise GhidraRunnerError(f"{label} is not a file: {path}")


def _require_dir(path: Path, label: str) -> None:
    if not path.exists():
        raise GhidraRunnerError(f"{label} does not exist: {path}")
    if not path.is_dir():
        raise GhidraRunnerError(f"{label} is not a directory: {path}")


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        raise GhidraRunnerError(f"Invalid JSON produced by Ghidra: {path}") from exc


def _validate_output(data: Dict[str, Any]) -> None:
    required_keys = [
        "program_name",
        "image_base",
        "function_count",
        "imported_dlls",
        "imported_symbols",
        "all_strings",
        "memory_sections",
        "functions",
        "suspicious_addresses",
    ]

    missing = [key for key in required_keys if key not in data]
    if missing:
        raise GhidraRunnerError(f"Ghidra output is missing keys: {missing}")


def summarize_result(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a small summary that is easier to print/read.
    The full result still remains available in the original dictionary.
    """
    suspicious_hits: List[Dict[str, Any]] = data.get("suspicious_addresses", [])

    api_counts: Dict[str, int] = {}
    useful_hits: List[Dict[str, Any]] = []

    for hit in suspicious_hits:
        api = hit.get("api", "UNKNOWN")
        api_counts[api] = api_counts.get(api, 0) + 1

        function_name = hit.get("containing_function", "")
        from_address = hit.get("from_address", "")

        # Skip import table / thunk-like hits for the human-readable summary.
        if function_name not in ("UNKNOWN", api) and from_address != "NO_REFERENCE_FOUND":
            useful_hits.append(hit)

    return {
        "program_name": data.get("program_name"),
        "image_base": data.get("image_base"),
        "function_count": data.get("function_count"),
        "imported_dll_count": len(data.get("imported_dlls", [])),
        "imported_symbol_count": len(data.get("imported_symbols", [])),
        "string_count": len(data.get("all_strings", [])),
        "memory_section_count": len(data.get("memory_sections", [])),
        "suspicious_hit_count": len(suspicious_hits),
        "useful_suspicious_hit_count": len(useful_hits),
        "api_counts": api_counts,
        "top_useful_hits": useful_hits[:25],
    }


def run_ghidra(
    sample_path: str | Path,
    output_json: str | Path | None = None,
    ghidra_headless: str | Path = DEFAULT_GHIDRA_HEADLESS,
    script_dir: str | Path = DEFAULT_SCRIPT_DIR,
    script_name: str = DEFAULT_SCRIPT_NAME,
    timeout: int = 180,
    keep_project: bool = False,
) -> Dict[str, Any]:
    """
    Run Ghidra headless against one sample.

    Parameters:
        sample_path:
            Path to the PE file to analyze.

        output_json:
            Where to copy the final JSON result.
            If None, the result is only returned as a Python dict.

        ghidra_headless:
            Path to /opt/ghidra/support/analyzeHeadless.

        script_dir:
            Directory containing ExtractCFG.java.

        script_name:
            Ghidra script name.

        timeout:
            Max seconds before killing Ghidra.

        keep_project:
            If False, delete the temporary Ghidra project after analysis.

    Returns:
        Parsed JSON dictionary produced by ExtractCFG.java.
    """
    sample_path = Path(sample_path).expanduser().resolve()
    ghidra_headless = Path(ghidra_headless).expanduser().resolve()
    script_dir = Path(script_dir).expanduser().resolve()

    _require_file(sample_path, "Sample")
    _require_file(ghidra_headless, "Ghidra analyzeHeadless")
    _require_dir(script_dir, "Ghidra script directory")
    _require_file(script_dir / script_name, "Ghidra script")

    project_root = Path(tempfile.mkdtemp(prefix="malproj_ghidra_"))
    project_name = "analysis_project"

    runtime_output = Path("/tmp/ghidra_out.json")
    run_log = project_root / "ghidra_run.log"
    script_log = project_root / "ghidra_script.log"

    if runtime_output.exists():
        runtime_output.unlink()

    cmd = [
        str(ghidra_headless),
        str(project_root),
        project_name,
        "-import",
        str(sample_path),
        "-scriptPath",
        str(script_dir),
        "-postScript",
        script_name,
        "-log",
        str(run_log),
        "-scriptlog",
        str(script_log),
    ]

    try:
        completed = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GhidraRunnerError(f"Ghidra timed out after {timeout} seconds") from exc

    if completed.returncode != 0:
        raise GhidraRunnerError(
            "Ghidra failed.\n"
            f"Return code: {completed.returncode}\n"
            f"STDOUT:\n{completed.stdout[-4000:]}\n"
            f"STDERR:\n{completed.stderr[-4000:]}\n"
            f"Run log: {run_log}\n"
            f"Script log: {script_log}"
        )

    if not runtime_output.exists():
        raise GhidraRunnerError(
            "Ghidra finished, but /tmp/ghidra_out.json was not created.\n"
            f"Run log: {run_log}\n"
            f"Script log: {script_log}"
        )

    data = _load_json(runtime_output)
    _validate_output(data)

    if output_json is not None:
        output_json = Path(output_json).expanduser().resolve()
        output_json.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(runtime_output, output_json)
        data["_saved_to"] = str(output_json)

    data["_ghidra_project_root"] = str(project_root)
    data["_ghidra_run_log"] = str(run_log)
    data["_ghidra_script_log"] = str(script_log)
    data["_summary"] = summarize_result(data)

    if not keep_project:
        shutil.rmtree(project_root, ignore_errors=True)
        data["_ghidra_project_root_deleted"] = True
    else:
        data["_ghidra_project_root_deleted"] = False

    return data


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Ghidra headless + ExtractCFG.java on a Windows PE sample."
    )
    parser.add_argument("sample", help="Path to sample EXE/DLL")
    parser.add_argument(
        "--output",
        default=str(Path.home() / "malproj" / "results" / "ghidra_out.json"),
        help="Where to save the JSON result",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Ghidra timeout in seconds",
    )
    parser.add_argument(
        "--keep-project",
        action="store_true",
        help="Keep temporary Ghidra project directory for debugging",
    )

    args = parser.parse_args()

    try:
        result = run_ghidra(
            sample_path=args.sample,
            output_json=args.output,
            timeout=args.timeout,
            keep_project=args.keep_project,
        )
    except GhidraRunnerError as exc:
        print(f"[ghidra_runner] ERROR: {exc}")
        return 1

    summary = result["_summary"]

    print("[ghidra_runner] Analysis complete")
    print(f"  Program:                 {summary['program_name']}")
    print(f"  Image base:              {summary['image_base']}")
    print(f"  Functions:               {summary['function_count']}")
    print(f"  Imported DLLs:           {summary['imported_dll_count']}")
    print(f"  Imported symbols:        {summary['imported_symbol_count']}")
    print(f"  Strings:                 {summary['string_count']}")
    print(f"  Memory sections:         {summary['memory_section_count']}")
    print(f"  Suspicious hits:         {summary['suspicious_hit_count']}")
    print(f"  Useful suspicious hits:  {summary['useful_suspicious_hit_count']}")
    print(f"  Saved JSON:              {result.get('_saved_to')}")

    print("\n[ghidra_runner] Top useful suspicious hits:")
    for hit in summary["top_useful_hits"]:
        print(
            f"  - {hit.get('api')} | "
            f"from {hit.get('from_address')} | "
            f"function {hit.get('containing_function')}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
