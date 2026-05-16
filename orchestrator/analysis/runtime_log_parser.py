#!/usr/bin/env python3
"""
runtime_log_parser.py
=====================

Parses x64dbg runtime logs produced by MALPROJ breakpoint scripts.

Input:
- x64dbg log file containing lines like:
  [MALPROJ] HIT WriteProcessMemory | base=1000 | buffer=... | size=28

Output:
- Structured JSON events.
- Human-readable Markdown summary.

Role in project:
x64dbg runtime log -> structured runtime events -> stage graph/report later
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Any


HIT_RE = re.compile(r"^\[MALPROJ\]\s+HIT\s+([A-Za-z0-9_]+)(?:\s*\|\s*(.*))?$")


API_CATEGORY = {
    "IsDebuggerPresent": "anti_debug",
    "CheckRemoteDebuggerPresent": "anti_debug",
    "GetTickCount": "anti_debug_timing",

    "VirtualAlloc": "memory_allocation",
    "CreateMutexA": "mutex",

    "CreateProcessA": "process_creation",
    "WriteProcessMemory": "process_injection",
    "CreateRemoteThread": "process_injection",

    "WSAStartup": "network",
    "socket": "network",
    "inet_pton": "network",
    "connect": "network",

    "RegOpenKeyExA": "registry",
    "RegSetValueExA": "registry",

    "SetWindowsHookExA": "user_activity_hook",
    "UnhookWindowsHookEx": "user_activity_hook",

    "GetDC": "screen_capture",
    "BitBlt": "screen_capture",
}


API_STAGE = {
    "IsDebuggerPresent": "Stage 1",
    "CheckRemoteDebuggerPresent": "Stage 1",
    "GetTickCount": "Stage 1",
    "VirtualAlloc": "Stage 1",

    "CreateMutexA": "Stage 2",
    "CreateProcessA": "Stage 2",
    "WriteProcessMemory": "Stage 2",
    "CreateRemoteThread": "Stage 2",
    "WSAStartup": "Stage 2",
    "socket": "Stage 2",
    "inet_pton": "Stage 2",
    "connect": "Stage 2",
    "RegOpenKeyExA": "Stage 2",
    "RegSetValueExA": "Stage 2",

    "SetWindowsHookExA": "Stage 3",
    "UnhookWindowsHookEx": "Stage 3",
    "GetDC": "Stage 3",
    "BitBlt": "Stage 3",
}


def parse_key_values(blob: str | None) -> Dict[str, str]:
    args: Dict[str, str] = {}

    if not blob:
        return args

    parts = [part.strip() for part in blob.split("|")]

    for part in parts:
        if "=" not in part:
            continue

        key, value = part.split("=", 1)
        args[key.strip()] = value.strip()

    return args


def parse_runtime_log(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Runtime log not found: {path}")

    events: List[Dict[str, Any]] = []
    messages: List[str] = []

    # errors="ignore" handles any odd saved-log bytes safely.
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_number, line in enumerate(f, start=1):
            raw = line.strip()

            if "[MALPROJ]" not in raw:
                continue

            match = HIT_RE.match(raw)

            if not match:
                messages.append(raw)
                continue

            api = match.group(1)
            kv_blob = match.group(2)
            args = parse_key_values(kv_blob)

            event = {
                "event_type": "api_hit",
                "source": "x64dbg",
                "line_number": line_number,
                "api": api,
                "category": API_CATEGORY.get(api, "unknown"),
                "stage": API_STAGE.get(api, "Unknown"),
                "arguments": args,
                "raw": raw,
            }

            events.append(event)

    api_counts: Dict[str, int] = {}
    stage_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}

    for event in events:
        api = event["api"]
        stage = event["stage"]
        category = event["category"]

        api_counts[api] = api_counts.get(api, 0) + 1
        stage_counts[stage] = stage_counts.get(stage, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1

    return {
        "input_log": str(path),
        "event_count": len(events),
        "message_count": len(messages),
        "api_counts": api_counts,
        "stage_counts": stage_counts,
        "category_counts": category_counts,
        "messages": messages,
        "events": events,
    }


def write_summary(data: Dict[str, Any], path: Path) -> None:
    lines: List[str] = []

    lines.append("# x64dbg Runtime Summary")
    lines.append("")
    lines.append(f"- Input log: `{data['input_log']}`")
    lines.append(f"- API hit events: `{data['event_count']}`")
    lines.append(f"- Other MALPROJ messages: `{data['message_count']}`")
    lines.append("")

    lines.append("## Stage Counts")
    lines.append("")
    for stage, count in data["stage_counts"].items():
        lines.append(f"- {stage}: {count}")

    lines.append("")
    lines.append("## Category Counts")
    lines.append("")
    for category, count in data["category_counts"].items():
        lines.append(f"- {category}: {count}")

    lines.append("")
    lines.append("## API Counts")
    lines.append("")
    for api, count in data["api_counts"].items():
        lines.append(f"- {api}: {count}")

    lines.append("")
    lines.append("## Runtime Events")
    lines.append("")

    for i, event in enumerate(data["events"], start=1):
        args = event["arguments"]
        arg_text = ", ".join([f"{k}={v}" for k, v in args.items()]) if args else "no arguments logged"

        lines.append(f"### {i}. {event['api']}")
        lines.append(f"- Stage: `{event['stage']}`")
        lines.append(f"- Category: `{event['category']}`")
        lines.append(f"- Arguments: `{arg_text}`")
        lines.append(f"- Raw: `{event['raw']}`")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse MALPROJ x64dbg runtime log into structured JSON."
    )
    parser.add_argument("--input", required=True, help="Path to x64dbg runtime log.")
    parser.add_argument("--output", required=True, help="Path to output JSON.")
    parser.add_argument("--summary", required=True, help="Path to output Markdown summary.")

    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()
    summary_path = Path(args.summary).expanduser().resolve()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    data = parse_runtime_log(input_path)

    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    write_summary(data, summary_path)

    print("[runtime_log_parser] Parsed runtime log")
    print(f"  Input:          {input_path}")
    print(f"  Events:         {data['event_count']}")
    print(f"  Messages:       {data['message_count']}")
    print(f"  Output JSON:    {output_path}")
    print(f"  Summary:        {summary_path}")

    print("\n[runtime_log_parser] API hits:")
    for api, count in data["api_counts"].items():
        print(f"  - {api}: {count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
