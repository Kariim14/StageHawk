"""IOC extraction from static strings, runtime events, and artifacts."""

from __future__ import annotations

import re
from typing import Any


IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
REG_RE = re.compile(r"(?:HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|Software\\)[A-Za-z0-9_ .\\-]+")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def extract_iocs(
    ghidra_data: dict[str, Any] | None = None,
    runtime_events: dict[str, Any] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    cape_summary: dict[str, Any] | None = None,
) -> dict[str, list[str]]:
    ghidra_data = ghidra_data or {}
    runtime_events = runtime_events or {}
    artifacts = artifacts or []
    cape_summary = cape_summary or {}

    iocs: dict[str, set[str]] = {
        "hashes": set(),
        "file_paths": set(),
        "ip_addresses": set(),
        "domains": set(),
        "urls": set(),
        "registry_keys": set(),
        "mutexes": set(),
        "process_names": set(),
        "suspicious_strings": set(),
        "network_endpoints": set(),
    }

    for artifact in artifacts:
        if artifact.get("sha256"):
            iocs["hashes"].add(str(artifact["sha256"]))
        if artifact.get("path"):
            iocs["file_paths"].add(str(artifact["path"]))
        if artifact.get("destination_path"):
            iocs["file_paths"].add(str(artifact["destination_path"]))

    for text in ghidra_data.get("all_strings", []):
        value = str(text)
        for ip in IP_RE.findall(value):
            iocs["ip_addresses"].add(ip)
            iocs["network_endpoints"].add(ip)
        for reg in REG_RE.findall(value):
            iocs["registry_keys"].add(reg.rstrip())
        for domain in DOMAIN_RE.findall(value):
            if not domain.lower().endswith((".dll", ".exe", ".bin")):
                iocs["domains"].add(domain)
        if "mutex" in value.lower() or value.startswith("Global\\"):
            iocs["mutexes"].add(value)
        if value.lower().endswith((".exe", ".dll", ".bin")) or ":\\" in value:
            iocs["file_paths"].add(value)
        if any(token in value.lower() for token in ["stage", "payload", "c2", "exfil", "credential"]):
            iocs["suspicious_strings"].add(value)

    for event in runtime_events.get("events", []):
        api = event.get("api")
        args = event.get("arguments", {})
        if api == "CreateProcessA":
            iocs["process_names"].add("CreateProcessA_observed")
        if api in {"connect", "send", "recv", "socket"}:
            iocs["network_endpoints"].add(f"{api}_observed")
        for value in args.values() if isinstance(args, dict) else []:
            for ip in IP_RE.findall(str(value)):
                iocs["ip_addresses"].add(ip)

    target_file = (cape_summary.get("target") or {}).get("file") or {}
    for key in ("sha256", "sha1", "md5"):
        if target_file.get(key):
            iocs["hashes"].add(str(target_file[key]))
    if target_file.get("name"):
        iocs["file_paths"].add(str(target_file["name"]))
    behavior_summary = cape_summary.get("behavior_summary") or {}
    for key in ("file_created", "file_written", "file_deleted", "file_opened"):
        for value in behavior_summary.get(key, []) if isinstance(behavior_summary, dict) else []:
            iocs["file_paths"].add(str(value))
    for key in ("regkey_written", "regkey_opened", "regkey_deleted"):
        for value in behavior_summary.get(key, []) if isinstance(behavior_summary, dict) else []:
            iocs["registry_keys"].add(str(value))
    for value in behavior_summary.get("mutex", []) if isinstance(behavior_summary, dict) else []:
        iocs["mutexes"].add(str(value))
    network = cape_summary.get("network") or {}
    for host in network.get("hosts", []) if isinstance(network, dict) else []:
        if isinstance(host, dict) and host.get("ip"):
            iocs["ip_addresses"].add(str(host["ip"]))
        elif isinstance(host, str):
            iocs["ip_addresses"].add(host)
    for domain in network.get("domains", []) if isinstance(network, dict) else []:
        if isinstance(domain, dict) and domain.get("domain"):
            iocs["domains"].add(str(domain["domain"]))
        elif isinstance(domain, str):
            iocs["domains"].add(domain)

    return {key: sorted(values) for key, values in iocs.items()}
