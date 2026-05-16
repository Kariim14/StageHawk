# StageHawk Demo Checklist

## Environment

Activate the virtual environment:

```bash
cd <project-root>
source .venv/bin/activate
```

Load environment variables only when needed. Do not print them:

```bash
set -a
source .env
set +a
```

## Run Tests

```bash
cd <project-root>
source .venv/bin/activate
python -m pytest -q
```

Expected current baseline:

```text
37 passed
```

## Start Web UI

```bash
cd <project-root>
source .venv/bin/activate
set -a
source .env
set +a
fuser -k 8088/tcp
.venv/bin/python -m orchestrator.web
```

Open:

```text
http://127.0.0.1:8088
```

## Static Smoke Test

```bash
cd <project-root>
source .venv/bin/activate
python - <<'PY'
from orchestrator.core.pipeline import run_full_pipeline
from pathlib import Path
import json

result = run_full_pipeline(
    "samples/fake/fake_dropper_sample.exe",
    case_name="demo_static_smoke",
    mode="static",
)

case = Path(result["case_root"])
print(json.dumps({
    "case_id": result["case_id"],
    "status": result["current_status"],
    "warnings": result["warnings"],
    "errors": result["errors"],
    "report_json": str(case / "reports" / "final_report.json"),
    "report_md": str(case / "reports" / "final_report.md"),
}, indent=2))
PY
```

## Full CAPE Smoke Test With Fake Sample

Run only when CAPE is already available:

```bash
cd <project-root>
source .venv/bin/activate
set -a
source .env
set +a
python - <<'PY'
from orchestrator.core.pipeline import run_full_pipeline
from pathlib import Path
import json

result = run_full_pipeline(
    "samples/fake/fake_dropper_sample.exe",
    case_name="demo_full_cape_smoke",
    mode="full",
)

case = Path(result["case_root"])
timing_path = case / "case_timing.json"
print(json.dumps({
    "case_id": result["case_id"],
    "status": result["current_status"],
    "warnings": result["warnings"],
    "errors": result["errors"],
    "timing_exists": timing_path.exists(),
    "report_json": str(case / "reports" / "final_report.json"),
    "report_md": str(case / "reports" / "final_report.md"),
}, indent=2))

if timing_path.exists():
    timing = json.loads(timing_path.read_text(encoding="utf-8"))
    steps = timing.get("steps", {})
    print(json.dumps({
        "cape_related_timing": [k for k in steps if "cape" in k],
    }, indent=2))
PY
```

## Hash Reputation Test

Use the web Threat Intelligence page at:

```text
http://127.0.0.1:8088/reputation
```

Or call the API with a known sample hash. Do not include API keys in the command:

```bash
curl -s http://127.0.0.1:8088/api/reputation/hash \
  -H 'content-type: application/json' \
  -d '{"hash":"<sha256-or-md5-here>"}' | python -m json.tool
```

## URL Reputation Test

Use:

```bash
curl -s http://127.0.0.1:8088/api/reputation/url \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com/"}' | python -m json.tool
```

## Where To Find Reports

Each analysis creates a case under:

```text
results/cases/<case_id>/
```

Important outputs:

- `case_manifest.json`
- `case_timing.json`
- `static/signature_scan.json`
- `static/ghidra_out.json`
- `cape/cape_result.json`
- `cape/cape_report.json`
- `cape/cape_artifacts.json`
- `graph/stage_graph.json`
- `graph/stage_graph.md`
- `reports/final_report.json`
- `reports/final_report.md`

## Screenshots To Capture

- Dashboard case list.
- New Analysis page showing analysis modes.
- Running job progress with CAPE task status if using Full Analysis.
- Case detail page with signature quality and timing.
- Report page executive assessment.
- CAPE Sandbox section and CAPE phase timing.
- Stage graph view.
- Threat Intelligence reputation workspace.
- System Status page showing Ghidra, CAPE, safety, and web hardening.

## Demo Safety Reminders

- Do not execute samples directly on Ubuntu/controller host.
- Use only the fake sample for live demonstration unless the lab explicitly approves otherwise.
- Dynamic execution must remain CAPE-only.
- Do not show `.env` or API keys.

