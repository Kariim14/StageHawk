#!/usr/bin/env python3
"""
Fix web dashboard crashes caused by old/legacy case manifests missing fields
such as selected_backends, analysis_mode, or backend_status.

Run from the project root:
    python fix_web_legacy_cases.py
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

ROOT = Path.cwd()
TS = datetime.now().strftime("%Y%m%dT%H%M%S")

DEFAULT_BACKENDS = {
    "static": True,
    "ghidra": False,
    "cape": False,
    "x64dbg": False,
}
DEFAULT_BACKEND_STATUS = {
    "static": "unknown",
    "ghidra": "unknown",
    "cape": "unknown",
    "x64dbg": "unknown",
}


def backup(path: Path) -> Path:
    backup_path = path.with_suffix(path.suffix + f".bak_{TS}")
    backup_path.write_bytes(path.read_bytes())
    return backup_path


def patch_app_py() -> None:
    app_py = ROOT / "orchestrator" / "web" / "app.py"
    if not app_py.exists():
        print(f"[SKIP] Missing {app_py}")
        return

    original = app_py.read_text()
    text = original

    if "ChainableUndefined" not in text:
        # Put the import near the other imports.
        lines = text.splitlines()
        insert_at = 0
        for i, line in enumerate(lines):
            if line.startswith("from ") or line.startswith("import "):
                insert_at = i + 1
        lines.insert(insert_at, "from jinja2 import ChainableUndefined")
        text = "\n".join(lines) + ("\n" if original.endswith("\n") else "")

    if "templates.env.undefined = ChainableUndefined" not in text:
        # Insert after the line that creates Jinja2Templates.
        lines = text.splitlines()
        out = []
        inserted = False
        for line in lines:
            out.append(line)
            if not inserted and "Jinja2Templates" in line and "=" in line and not line.strip().startswith("#"):
                out.append("templates.env.undefined = ChainableUndefined  # tolerate legacy case manifests")
                inserted = True
        if inserted:
            text = "\n".join(out) + ("\n" if original.endswith("\n") else "")
        else:
            print("[WARN] Could not find Jinja2Templates assignment in app.py")

    if text != original:
        b = backup(app_py)
        app_py.write_text(text)
        print(f"[OK] Patched {app_py} (backup: {b})")
    else:
        print(f"[OK] app.py already safe")


def safe_template_exprs(text: str) -> str:
    replacements = {
        "case.selected_backends.static": "(case.get('selected_backends') or {}).get('static', true)",
        "case.selected_backends.ghidra": "(case.get('selected_backends') or {}).get('ghidra', false)",
        "case.selected_backends.cape": "(case.get('selected_backends') or {}).get('cape', false)",
        "case.selected_backends.x64dbg": "(case.get('selected_backends') or {}).get('x64dbg', false)",
        "case.analysis_mode": "case.get('analysis_mode', 'legacy')",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)

    # Convert case.backend_status.cape -> safe .get style for any backend key.
    text = re.sub(
        r"case\.backend_status\.([A-Za-z_][A-Za-z0-9_]*)",
        r"(case.get('backend_status') or {}).get('\1', 'unknown')",
        text,
    )
    return text


def patch_templates() -> None:
    template_dir = ROOT / "orchestrator" / "web" / "templates"
    if not template_dir.exists():
        print(f"[SKIP] Missing {template_dir}")
        return

    for name in ["dashboard.html", "case_detail.html"]:
        path = template_dir / name
        if not path.exists():
            print(f"[SKIP] Missing {path}")
            continue
        original = path.read_text()
        text = safe_template_exprs(original)
        if text != original:
            b = backup(path)
            path.write_text(text)
            print(f"[OK] Patched {path} (backup: {b})")
        else:
            print(f"[OK] {path} already safe or no matching unsafe fields")


def migrate_case_manifests() -> None:
    cases_dir = ROOT / "results" / "cases"
    if not cases_dir.exists():
        print(f"[SKIP] Missing {cases_dir}")
        return

    changed_count = 0
    for manifest in cases_dir.glob("*/case_manifest.json"):
        try:
            data = json.loads(manifest.read_text())
        except Exception as exc:
            print(f"[WARN] Could not read {manifest}: {exc}")
            continue

        changed = False
        selected = data.get("selected_backends")
        if not isinstance(selected, dict):
            data["selected_backends"] = dict(DEFAULT_BACKENDS)
            changed = True
        else:
            for k, v in DEFAULT_BACKENDS.items():
                if k not in selected:
                    selected[k] = v
                    changed = True

        if not data.get("analysis_mode"):
            data["analysis_mode"] = "legacy"
            changed = True

        backend_status = data.get("backend_status")
        if not isinstance(backend_status, dict):
            data["backend_status"] = dict(DEFAULT_BACKEND_STATUS)
            changed = True
        else:
            for k, v in DEFAULT_BACKEND_STATUS.items():
                if k not in backend_status:
                    backend_status[k] = v
                    changed = True

        for key in ["completed_steps", "skipped_steps", "failed_steps", "warnings", "errors"]:
            if key not in data or data[key] is None:
                data[key] = []
                changed = True

        if changed:
            b = backup(manifest)
            manifest.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
            changed_count += 1
            print(f"[OK] Migrated {manifest} (backup: {b})")

    print(f"[OK] Migrated {changed_count} legacy case manifest(s)")


def main() -> None:
    if not (ROOT / "orchestrator").exists():
        raise SystemExit("Run this script from the project root, for example: cd ~/malproj")

    patch_app_py()
    patch_templates()
    migrate_case_manifests()
    print("\nDone. Now run:")
    print("  source .venv/bin/activate")
    print("  python -m pytest -q")
    print("  fuser -k 8088/tcp 2>/dev/null || true")
    print("  .venv/bin/python -m orchestrator.web")


if __name__ == "__main__":
    main()
