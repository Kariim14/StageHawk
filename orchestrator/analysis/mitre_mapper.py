"""Rule-based ATT&CK-inspired behavior mapping.

This is deliberately conservative. It produces "MITRE-style" labels rather
than pretending every observation is a confirmed ATT&CK technique.
"""

from __future__ import annotations

from typing import Any


API_MAPPINGS: dict[str, dict[str, str]] = {
    "IsDebuggerPresent": {"label": "anti-analysis check", "technique_id": "T1497"},
    "CheckRemoteDebuggerPresent": {"label": "anti-analysis check", "technique_id": "T1497"},
    "GetTickCount": {"label": "timing check", "technique_id": "T1497"},
    "VirtualAlloc": {"label": "memory staging", "technique_id": "T1055-style"},
    "WriteProcessMemory": {"label": "process injection style behavior", "technique_id": "T1055"},
    "CreateRemoteThread": {"label": "remote thread execution style behavior", "technique_id": "T1055"},
    "CreateProcessA": {"label": "process creation / possible hollowing setup", "technique_id": "T1106-style"},
    "RegSetValueExA": {"label": "registry modification", "technique_id": "T1112"},
    "RegOpenKeyExA": {"label": "registry discovery/access", "technique_id": "T1012-style"},
    "connect": {"label": "network communication", "technique_id": "T1071-style"},
    "socket": {"label": "network communication setup", "technique_id": "T1071-style"},
    "WSAStartup": {"label": "network API initialization", "technique_id": "T1071-style"},
    "SetWindowsHookExA": {"label": "input capture style behavior", "technique_id": "T1056-style"},
    "BitBlt": {"label": "screen capture style behavior", "technique_id": "T1113-style"},
}


def map_behaviors(
    ghidra_data: dict[str, Any] | None = None,
    runtime_events: dict[str, Any] | None = None,
    cape_summary: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    observed: set[str] = set()
    for hit in (ghidra_data or {}).get("suspicious_addresses", []):
        if hit.get("api"):
            observed.add(str(hit["api"]))
    for event in (runtime_events or {}).get("events", []):
        if event.get("api"):
            observed.add(str(event["api"]))

    mappings: list[dict[str, str]] = []
    for api in sorted(observed):
        if api not in API_MAPPINGS:
            continue
        item = dict(API_MAPPINGS[api])
        item.update(
            {
                "source_api": api,
                "mapping_type": "ATT&CK-inspired",
                "confidence": "medium",
            }
        )
        mappings.append(item)
    for sig in (cape_summary or {}).get("signatures", []):
        for ttp in sig.get("ttps", []) or []:
            mappings.append(
                {
                    "source_api": "CAPE signature",
                    "label": sig.get("name") or "CAPE behavioral signature",
                    "technique_id": str(ttp),
                    "mapping_type": "CAPE ATT&CK/behavioral signature",
                    "confidence": "medium",
                }
            )
    return mappings
