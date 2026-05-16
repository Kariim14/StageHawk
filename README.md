# StageHawk

**Defensive Multi-Stage Malware Analysis Orchestrator**

StageHawk is a defensive malware-analysis orchestration project that combines static analysis, sandboxed dynamic analysis, local signatures, passive threat-intelligence lookups, artifact triage, recursive analysis, stage-graph reconstruction, and final reporting into one web-based workflow.

The project is designed for defensive malware-analysis use. It does **not** create malware, does **not** execute samples on the Ubuntu/controller host, and does **not** claim guaranteed malware detection.

---

## Overview

Malware-analysis evidence is often scattered across multiple tools:

- static-analysis output
- sandbox behavior
- dropped artifacts
- signatures
- file hashes
- URLs
- reputation results
- IOCs
- analyst notes

StageHawk solves this organization problem by collecting evidence from multiple sources and converting it into one structured case view with reports and a stage graph.

The goal is not to replace the analyst. The goal is to help the analyst understand what happened, which artifacts matter, and how the evidence should be reported.

---

## Core Workflow

```text
Sample upload / sample path
        ↓
Local YARA signature scan
        ↓
Ghidra headless static analysis
        ↓
CAPE sandbox dynamic analysis
        ↓
CAPE artifact import
        ↓
Artifact triage
        ↓
Recursive analysis where supported
        ↓
Stage graph generation
        ↓
Final JSON / Markdown report
        ↓
Web UI case view
```

---

## Analysis Modes

StageHawk supports three analysis modes:

| Mode | Description |
|---|---|
| **Full Analysis** | Runs local signatures, Ghidra static analysis, and CAPE sandbox dynamic analysis |
| **Static Only** | Runs safe static analysis only; the sample is not executed |
| **Dynamic Only** | Uses CAPE Sandbox for controlled dynamic execution inside the isolated Windows VM |

---

## Implemented Features

### Web Interface

StageHawk includes a local web interface with:

- Dashboard
- New Analysis page
- Case detail view
- Report page
- Stage graph page
- Threat Intelligence workspace
- System/config status page
- Light/Dark mode toggle
- StageHawk falcon branding and favicon
- Search/filter controls for cases

Default local URL:

```text
http://127.0.0.1:8088
```

---

### Static Analysis with Ghidra

StageHawk automates Ghidra using **Ghidra Headless**.

Ghidra is installed outside the project, commonly at:

```text
/opt/ghidra/support/analyzeHeadless
```

StageHawk uses a custom Ghidra Java script:

```text
ghidra_scripts/ExtractCFG.java
```

The script extracts static evidence such as:

- functions
- imports
- strings
- memory sections
- metadata
- suspicious API references
- possible stage indicators

The Ghidra script first writes output to:

```text
/tmp/ghidra_out.json
```

Then StageHawk copies it into the case directory:

```text
results/cases/<case_id>/static/ghidra_out.json
```

Ghidra does **not** execute the sample. It performs static analysis only.

---

### Dynamic Analysis with CAPE Sandbox

CAPE Sandbox is the active dynamic-analysis backend.

StageHawk submits the sample to CAPE, receives a task ID, waits for completion, imports the CAPE report and artifacts, then uses them in the final report and graph.

CAPE handles:

- Windows VM restore/start
- sample transfer into the guest
- controlled sample execution
- behavior collection
- signatures
- dropped artifacts
- sandbox report generation

Active VM:

```text
VM name: win10
Machinery: KVM/libvirt
```

---

### CAPE VM Isolation

The CAPE Windows VM was moved away from libvirt's default NAT network and placed on a custom isolated network.

Current isolated network state:

```text
Network: cape-isolated
Bridge: virbr-cape
Host bridge IP: 192.168.150.1
Windows VM IP: 192.168.150.105
```

Verified behavior:

- Windows VM can communicate with the CAPE host.
- Ubuntu host can reach the VM.
- Windows VM cannot reach the public internet.
- Windows VM cannot resolve external domains such as `google.com`.
- CAPE still completes dynamic analysis successfully.

This allows controlled sandbox execution while keeping the guest isolated from the public internet.

---

### Local YARA Signatures

StageHawk includes local YARA signature support.

Current local rules are stored under:

```text
signatures/yara/
```

Generic suspicious PE rules are stored in:

```text
signatures/yara/generic/
```

Example rule categories:

- suspicious Windows APIs
- PowerShell/download/execution strings
- persistence-related registry strings
- process injection API names

Important limitation:

Generic YARA rules are **heuristic triage signals**. They do not prove malware, and they do not prove malware-family attribution.

---

### Threat Intelligence

StageHawk includes passive threat-intelligence lookups.

Implemented providers:

| Type | Providers |
|---|---|
| Hash reputation | VirusTotal, MalwareBazaar |
| URL reputation | VirusTotal URL, URLhaus |

Important notes:

- Hash and URL lookups are passive.
- StageHawk does not browse submitted URLs.
- StageHawk does not download or execute submitted URLs.
- Low reputation detections are treated cautiously.
- No reputation hit does not mean a file or URL is safe.

---

### Verdict Engine

StageHawk includes a cautious verdict engine.

It separates:

| Metric | Meaning |
|---|---|
| **Evidence Score** | How much useful analysis evidence was collected |
| **Maliciousness Likelihood** | How suspicious the collected evidence appears |

The maliciousness likelihood is a heuristic score, not a calibrated machine-learning probability.

StageHawk avoids overclaiming. For example, a benign installer may produce many artifacts or sandbox events, but that does not automatically make it malware.

---

### Artifact Triage and Stage Graph

CAPE can produce many artifacts, and not all of them are meaningful stages.

StageHawk performs artifact triage so that:

- all artifacts remain available as evidence
- only selected high-value artifacts appear in the main graph

This prevents noisy sandbox artifacts from becoming a misleading fake chain.

Correct relationship style:

```text
root sample → selected artifact
root sample → selected artifact
root sample → selected artifact
```

Not:

```text
artifact 1 → artifact 2 → artifact 3
```

The final graph is intended to represent observed evidence relationships, not unsupported assumptions.

---

### Recursive Analysis

StageHawk supports recursive analysis for supported extracted artifacts.

If CAPE extracts a child artifact that StageHawk can analyze, the pipeline can run static analysis on that child artifact as well.

Unsupported files are skipped honestly with a reason, for example:

```text
not a supported PE for recursive static analysis
```

---

### Runtime Timing

StageHawk records timing data for pipeline steps.

Timing output is stored in:

```text
results/cases/<case_id>/case_timing.json
```

CAPE sub-step timing includes:

```text
cape_submission
cape_sandbox_wait
cape_import
cape_artifact_copy
cape_total
```

Timing appears in the case view and final reports.

---

### Web-Layer Hardening

StageHawk includes basic web-layer hardening:

- upload size limit
- allowed extension policy
- in-memory rate limiting
- concurrent job limit
- secret redaction
- system status visibility

API keys are not exposed through the UI or config status page.

---

## What StageHawk Does Not Claim

StageHawk is intentionally cautious.

It does **not** claim:

- guaranteed malware detection
- guaranteed safe verdicts
- execution on the Ubuntu/controller host
- public-internet execution inside the sandbox
- active x64dbg automation in the current backend

---

## x64dbg Status

The original project idea referenced x64dbg as a possible debugger-assisted dynamic analysis component.

In the current implementation:

```text
x64dbg is not active.
CAPE Sandbox is the active dynamic-analysis backend.
x64dbg is documented as future debugger-assisted enhancement only.
```

This choice keeps the current implementation safer, automated, and easier to reproduce in the pipeline.

---

## Repository Structure

```text
StageHawk/
├── config/
│   └── default.yaml
├── ghidra_scripts/
│   └── ExtractCFG.java
├── orchestrator/
│   ├── analysis/
│   │   ├── artifact_triage.py
│   │   ├── reputation_lookup.py
│   │   ├── signature_scanner.py
│   │   ├── url_reputation.py
│   │   └── verdict_engine.py
│   ├── core/
│   │   ├── config_loader.py
│   │   ├── graph_builder.py
│   │   ├── pipeline.py
│   │   ├── report_builder.py
│   │   └── timing.py
│   ├── integrations/
│   │   ├── cape_client.py
│   │   ├── ghidra_runner.py
│   │   ├── malwarebazaar_client.py
│   │   ├── urlhaus_client.py
│   │   ├── virustotal_client.py
│   │   └── virustotal_url_client.py
│   └── web/
│       ├── app.py
│       ├── templates/
│       └── static/
├── samples/
│   └── fake/
│       └── fake_dropper_sample.exe
├── signatures/
│   └── yara/
│       ├── generic/
│       ├── known_families/
│       ├── experimental/
│       └── METADATA.json
├── tests/
├── docs/
├── results/
└── README.md
```

---

## Requirements

StageHawk was developed for a Linux analysis environment.

Main components:

- Python 3
- Flask/web interface
- Ghidra
- YARA
- CAPE Sandbox
- KVM/libvirt
- Windows analysis VM
- Optional external reputation API keys

Expected Ghidra path:

```text
/opt/ghidra/support/analyzeHeadless
```

Expected CAPE path:

```text
/opt/CAPEv2
```

---

## Environment Variables

StageHawk uses a local `.env` file for API keys.

Example variable names:

```bash
VT_API_KEY="..."
MALWAREBAZAAR_API_KEY="..."
URLHAUS_AUTH_KEY="..."
ABUSEIPDB_API_KEY="..."
```

Do not commit `.env`.

`.env` should remain gitignored.

Load environment variables with:

```bash
set -a
source .env
set +a
```

---

## Setup

Clone the repository:

```bash
git clone <your-repo-url>
cd malproj
```

Create and activate the virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install project dependencies:

```bash
pip install -r requirements.txt
```

If the project uses editable install:

```bash
pip install -e .
```

---

## Running the Web Interface

From the project root:

```bash
cd /home/kareem/malproj
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

---

## Running Tests

```bash
cd /home/kareem/malproj
source .venv/bin/activate
python -m pytest -q
```

Current expected result:

```text
38 passed, 3 warnings
```

---

## Static Smoke Test

```bash
cd /home/kareem/malproj
source .venv/bin/activate
set -a
source .env
set +a

python - <<'PY'
from orchestrator.core.pipeline import run_full_pipeline
import json

result = run_full_pipeline(
    "samples/fake/fake_dropper_sample.exe",
    case_name="static_smoke",
    mode="static",
)

print(json.dumps({
    "case_id": result["case_id"],
    "status": result["current_status"],
    "warnings": result["warnings"],
    "errors": result["errors"],
    "case_root": result["case_root"],
}, indent=2))
PY
```

---

## Full CAPE Smoke Test

Only run this when CAPE is configured and the Windows VM is isolated.

```bash
cd /home/kareem/malproj
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
    case_name="full_cape_smoke",
    mode="full",
)

case = Path(result["case_root"])
cape_result = case / "cape" / "cape_result.json"
timing_path = case / "case_timing.json"

out = {
    "case_id": result["case_id"],
    "status": result["current_status"],
    "warnings": result["warnings"],
    "errors": result["errors"],
    "case_root": str(case),
    "cape_result_exists": cape_result.exists(),
    "timing_exists": timing_path.exists(),
}

if cape_result.exists():
    cape = json.loads(cape_result.read_text(encoding="utf-8"))
    summary = cape.get("summary") or {}
    out["cape_summary"] = {
        "status": cape.get("status"),
        "mode": cape.get("mode"),
        "task_id": cape.get("task_id") or summary.get("task_id"),
        "score": summary.get("score"),
        "signature_count": summary.get("signature_count"),
        "artifact_count": len(summary.get("copied_artifacts", [])),
    }

if timing_path.exists():
    timing = json.loads(timing_path.read_text(encoding="utf-8"))
    steps = timing.get("steps") or timing.get("step_durations") or {}
    out["cape_timing_keys"] = [k for k in steps.keys() if "cape" in k]

print(json.dumps(out, indent=2))
PY
```

---

## Reputation API Tests

Start the web app first, then run these from another terminal.

### Hash Reputation

```bash
curl -sS -X POST http://127.0.0.1:8088/api/reputation/hash \
  -H "Content-Type: application/json" \
  -d '{"hash":"094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"}' \
  | python -m json.tool
```

### URL Reputation

```bash
curl -sS -X POST http://127.0.0.1:8088/api/reputation/url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/"}' \
  | python -m json.tool
```

Expected safe-URL interpretation:

```text
No malicious URL reputation was found in the configured providers.
This does not guarantee the URL is safe.
```

---

## Output Files

Each analysis creates a case folder:

```text
results/cases/<case_id>/
```

Important outputs:

```text
case_manifest.json
case_timing.json
static/signature_scan.json
static/ghidra_out.json
cape/cape_result.json
reports/final_report.json
reports/final_report.md
graph/
recursive/
```

---

## Documentation

Project documentation is stored in:

```text
docs/
```

Important documents:

```text
docs/STAGEHAWK_DEMO_CHECKLIST.md
docs/STAGEHAWK_FINAL_EVIDENCE_LOG.md
```

These documents summarize the implemented system, demo checklist, discussion questions, validation results, and final evidence.

---

## Safety and Ethics

StageHawk is for defensive, academic malware-analysis work only.

Rules:

- Do not execute suspicious files on the Ubuntu/controller host.
- Dynamic execution must happen only inside the isolated CAPE Windows VM.
- Do not use the system to create, modify, or deploy malware.
- Do not use the system for offensive payload development.
- Do not run real malware unless the sandbox and legal/academic permissions are properly prepared.
- Do not expose API keys.
- Treat reports as evidence, not absolute truth.

---

## Limitations

Current limitations:

- Reputation services do not guarantee that a file or URL is safe.
- Dynamic analysis can miss behavior that does not trigger inside the sandbox.
- IP/domain enrichment is not implemented.
- Authentication is future work.
- AI Analyst Copilot is future work.
- x64dbg-assisted debugging is future work.

---

## Future Work

Planned enhancements:

- IP/domain enrichment
- authentication and user management
- better deployment packaging
- larger benign/malicious validation set
- calibrated verdict scoring
- AI Analyst Copilot
- optional x64dbg-assisted manual validation

---

## Future AI Analyst Copilot

A possible future enhancement is:

```text
StageHawk AI Analyst Copilot
```

This would be a Generative AI assistant that reads StageHawk reports, CAPE results, Ghidra findings, IOCs, stage graphs, and threat-intelligence results, then explains them to the analyst in natural language.

It is not currently implemented.

---

## Team

Project supervised by:

```text
Prof. Mohamed El-Hmahmy
```

Team:

```text
Karim Hassan
Omar Ehab Sakr
Anas Shaker
Mahmoud Ahmed
```

Arab Academy for Science, Technology & Maritime Transport  
Malware Analysis & Reverse Engineering — Conclusion Project  
May 2026

---

## Final Note

StageHawk is an evidence-driven defensive analysis orchestrator.

It does not claim perfect malware detection. It helps collect, organize, and explain analysis evidence from static tools, sandbox behavior, signatures, reputation sources, artifacts, timing, reports, and graph reconstruction.
