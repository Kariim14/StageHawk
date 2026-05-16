# Multi-Stage Dropper Orchestrator

Defensive academic malware-analysis backend for a controlled, educational multi-stage dropper workflow.

The project is being centered around one reusable backend entry point:

```bash
python -m orchestrator analyze samples/fake/fake_dropper_sample.exe --case-name fake_dropper_demo
```

Future GUI, web dashboard, or chatbot integrations should call:

```python
from orchestrator.core.pipeline import run_full_pipeline

result = run_full_pipeline("samples/fake/fake_dropper_sample.exe", case_name="fake_dropper_demo")
```

## What It Does

- Creates a structured analysis case under `results/cases/<case_id>/`.
- Registers and hashes the input sample.
- Runs or replays static Ghidra analysis, depending on config.
- Detects stage-transition candidates from Ghidra output.
- Generates an x64dbg-style breakpoint plan and script.
- Collects runtime evidence from a live run or safe fake-sample fixtures.
- Separates API hit markers from real dropped artifacts.
- Hashes and classifies collected artifacts.
- Builds a stage graph.
- Extracts IOCs and ATT&CK-inspired behavior mappings.
- Writes final JSON and Markdown reports.

## What It Does Not Do Yet

- It does not perform validated x64dbg memory-buffer dumping.
- It does not reconstruct real unpacked shellcode.
- It does not run real malware by default.
- It does not include production CAPE/Cuckoo integration yet.
- It does not fully solve ASLR-safe debugger automation yet.

## Safety Boundaries

- Do not execute samples on the Ubuntu/controller host.
- Dynamic execution is intended only inside an isolated Windows VM.
- Real malware mode is disabled by default.
- `samples/real_quarantine/` is quarantine-only placeholder storage.
- The included fake sample is educational and non-malicious by design.

## Expected Outputs

Each run creates:

```text
results/cases/<case_id>/
  case_manifest.json
  input/
  static/
  dynamic/
  extracted/
  graph/
  reports/
```

Important files:

- `case_manifest.json`
- `static/ghidra_out.json`
- `static/stage_candidates.json`
- `dynamic/breakpoint_plan.json`
- `dynamic/x64dbg_script.txt`
- `dynamic/runtime_events.json`
- `dynamic/runtime_summary.md`
- `graph/stage_graph.json`
- `graph/stage_graph.dot`
- `graph/stage_graph.md`
- `reports/final_report.json`
- `reports/final_report.md`

## Running Tests

```bash
source .venv/bin/activate
python -m pytest -q
```

Integration tests requiring Ghidra, SSH, Windows VM, x64dbg, CAPE, or Cuckoo should remain skipped by default.

## Running The Website

```bash
.venv/bin/python -m orchestrator.web
```

Open:

```text
http://127.0.0.1:8088
```

The website supports sample upload/path selection, fake demo mode, backend toggles, case status, report viewing, graph viewing, IOCs, and configuration status.

## CAPE And VM Integration

Detected local CAPE details are documented in [docs/environment_detected.md](docs/environment_detected.md).

CAPE is implemented through `orchestrator.integrations.cape_client` and is disabled by default in `config/default.yaml`. x64dbg/VM execution is also disabled by default. Enable these only when the sandbox/VM is ready.

## Submission Readiness Docs

For the final university discussion/demo, see:

- [StageHawk submission status](docs/STAGEHAWK_SUBMISSION_STATUS.md)
- [StageHawk demo checklist](docs/STAGEHAWK_DEMO_CHECKLIST.md)
- [StageHawk discussion Q&A](docs/STAGEHAWK_DISCUSSION_QA.md)
- [StageHawk final evidence log](docs/STAGEHAWK_FINAL_EVIDENCE_LOG.md)
