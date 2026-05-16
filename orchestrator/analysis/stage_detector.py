"""Static stage-transition candidate detection from Ghidra JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


API_RULES: dict[str, tuple[str, float]] = {
    "VirtualAlloc": ("memory allocation before possible unpacking or staging", 0.7),
    "VirtualAllocEx": ("remote memory allocation candidate", 0.75),
    "VirtualProtect": ("memory permission transition candidate", 0.65),
    "WriteProcessMemory": ("process injection or payload transfer candidate", 0.85),
    "CreateRemoteThread": ("remote execution transfer candidate", 0.85),
    "CreateProcessA": ("child process or hollowing transition candidate", 0.75),
    "CreateProcessW": ("child process or hollowing transition candidate", 0.75),
    "CreateFileA": ("file creation candidate", 0.55),
    "CreateFileW": ("file creation candidate", 0.55),
    "WriteFile": ("file drop/write candidate", 0.75),
    "RegSetValueExA": ("registry modification candidate", 0.55),
    "RegSetValueExW": ("registry modification candidate", 0.55),
    "connect": ("network transition or beacon candidate", 0.6),
    "send": ("network transfer candidate", 0.6),
    "recv": ("network receive candidate", 0.6),
    "SetWindowsHookExA": ("collection/key hook behavior candidate", 0.45),
    "BitBlt": ("screen capture behavior candidate", 0.45),
}

STRING_RULES: list[tuple[str, str, float]] = [
    ("dropped_stage", "observed dropped-stage filename", 0.9),
    ("STAGE 1", "observed stage marker string", 0.85),
    ("STAGE 2", "observed stage marker string", 0.85),
    ("STAGE 3", "observed stage marker string", 0.85),
    ("192.168.254.254", "network endpoint string", 0.7),
    ("Global\\FakeDropperMutex_Edu", "mutex IOC string", 0.7),
]


def detect_stage_candidates(ghidra_data: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for hit in ghidra_data.get("suspicious_addresses", []):
        api = hit.get("api", "")
        if api not in API_RULES:
            continue
        reason, confidence = API_RULES[api]
        function = hit.get("containing_function", "UNKNOWN")
        address = hit.get("from_address", "")
        key = (api, function, address)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "candidate_id": f"cand_{len(candidates) + 1:03d}",
                "reason": reason,
                "related_api": api,
                "related_function": function,
                "address_if_available": address,
                "confidence": confidence,
                "evidence": hit,
            }
        )

    for value in ghidra_data.get("all_strings", []):
        for needle, reason, confidence in STRING_RULES:
            if needle.lower() in str(value).lower():
                candidates.append(
                    {
                        "candidate_id": f"cand_{len(candidates) + 1:03d}",
                        "reason": reason,
                        "related_api": None,
                        "related_function": None,
                        "address_if_available": None,
                        "confidence": confidence,
                        "evidence": {"string": value},
                    }
                )
                break

    candidates.sort(key=lambda item: item["confidence"], reverse=True)
    for index, item in enumerate(candidates, start=1):
        item["candidate_id"] = f"cand_{index:03d}"
    return candidates


def write_stage_candidates(ghidra_json: str | Path, output_path: str | Path) -> list[dict[str, Any]]:
    data = json.loads(Path(ghidra_json).read_text(encoding="utf-8"))
    candidates = detect_stage_candidates(data)
    Path(output_path).write_text(json.dumps(candidates, indent=2), encoding="utf-8")
    return candidates
