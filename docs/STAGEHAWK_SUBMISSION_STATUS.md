# StageHawk Submission Status

## Project Summary

StageHawk is a defensive academic malware-analysis orchestrator for studying multi-stage droppers. It accepts a sample or uploaded file, creates a structured case, performs local signature scanning, runs static analysis with Ghidra, optionally submits the sample to CAPE Sandbox for isolated dynamic analysis, imports CAPE artifacts, triages and recursively analyzes supported child artifacts, builds a stage graph, and generates JSON/Markdown/web reports with evidence-based verdicts.

## Implemented

- Web UI for starting analyses, viewing case status, reports, graphs, timing, and downloads.
- Three analysis modes: Full Analysis, Static Only, and Dynamic Only.
- Local signature scanning with YARA and optional ClamAV.
- Generic local YARA rules with quality/source metadata.
- Ghidra headless static analysis integration.
- CAPE Sandbox dynamic-analysis integration.
- CAPE report/artifact import and triage.
- Recursive static analysis for supported extracted artifacts.
- Stage graph reconstruction and graph pruning.
- IOC extraction and ATT&CK-style behavior mapping.
- Hash reputation lookup using VirusTotal and MalwareBazaar clients.
- URL reputation lookup using VirusTotal URL and URLhaus clients.
- Verdict Engine v2 with Evidence Score and Maliciousness Likelihood.
- Runtime timing, including CAPE sub-step timing.
- Deployment hardening baseline: upload size/extension policy, rate limiting, active-job limits, and secret redaction.

## Not Implemented / Future Work

- IP/domain enrichment is intentionally deferred.
- x64dbg live debugger automation is not active in the current product flow.
- Real unpacked shellcode reconstruction is future work.
- Production-grade malware-family attribution requires stronger curated signatures and analyst review.
- Distributed job scheduling, Redis-backed rate limits, authentication, and multi-user access control are future deployment work.
- Additional reputation providers and richer network-intelligence correlation can be added later.

## Active Analysis Modes

- **Full Analysis:** local signatures, Ghidra static analysis, CAPE dynamic analysis, artifact import, recursive static analysis, graph/report/verdict.
- **Static Only:** local signatures, Ghidra/static analysis, recursive static analysis where applicable, graph/report/verdict.
- **Dynamic Only:** local signatures and CAPE dynamic analysis without Ghidra static analysis.

## Active Tools / Backends

- **Static backend:** Ghidra headless.
- **Dynamic backend:** CAPE Sandbox.
- **Local signatures:** YARA, plus ClamAV when installed.
- **Reputation:** VirusTotal and MalwareBazaar for hashes; VirusTotal URL and URLhaus for URLs.
- **Reporting/UI:** FastAPI web app with JSON and Markdown exports.
- **x64dbg:** inactive and future-only.

## Safety Model

- Samples must never execute on the Ubuntu/controller host.
- Dynamic execution happens only through CAPE and its isolated Windows VM.
- Real malware mode remains disabled by default.
- x64dbg is not part of the active automated pipeline.
- Local YARA/Ghidra analysis is static and does not execute the sample.
- Upload hardening limits file size and accepted extensions.
- API/config status redacts secret values.

## CAPE Isolation Verification

Final CAPE network isolation was verified on 2026-05-11 using the fake sample `samples/fake/fake_dropper_sample.exe`. No real malware execution is claimed by this evidence.

Verified facts:

- Windows VM was moved from the libvirt default NAT network to `cape-isolated`.
- VM network source is `cape-isolated`.
- Host bridge is `virbr-cape` / `192.168.150.1`.
- Windows VM IP is `192.168.150.105`.
- Windows VM can ping `192.168.150.1`.
- Ubuntu host can ping `192.168.150.105`.
- Windows VM cannot reach `8.8.8.8`.
- Windows VM cannot resolve `google.com`.
- CAPE services are active.
- StageHawk full CAPE smoke completed successfully after isolation.

Isolation smoke result:

```yaml
case_id: 20260511T104631Z_isolated_cape_verified
status: completed
warnings: []
errors: []
cape_result_exists: true
task_id: 46
cape_mode: api
score: 8.0
signature_count: 17
artifact_count: 8
cape_timing_keys:
  - cape_total
  - cape_submission
  - cape_sandbox_wait
  - cape_import
  - cape_artifact_copy
```

This proves the sandbox can still run controlled dynamic analysis while the guest is isolated from the public internet.

## Testing Status

The current validation baseline is:

```bash
source .venv/bin/activate
python -m pytest -q
```

Expected current result:

```text
38 passed
```

The test suite covers core pipeline behavior, CAPE import, web API hardening, reputation lookups, signature scanning, report generation, artifact handling, stage detection, graph/report output, and timing.

## Demo Commands

Activate the environment:

```bash
cd <project-root>
source .venv/bin/activate
```

Run tests:

```bash
python -m pytest -q
```

Start the web UI:

```bash
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

Static smoke:

```bash
python - <<'PY'
from orchestrator.core.pipeline import run_full_pipeline
result = run_full_pipeline(
    "samples/fake/fake_dropper_sample.exe",
    case_name="submission_static_smoke",
    mode="static",
)
print(result)
PY
```

Full CAPE fake-sample smoke:

```bash
python - <<'PY'
from orchestrator.core.pipeline import run_full_pipeline
result = run_full_pipeline(
    "samples/fake/fake_dropper_sample.exe",
    case_name="submission_full_cape_smoke",
    mode="full",
)
print(result)
PY
```

## Discussion Talking Points

- StageHawk is an orchestrator, not a malware builder.
- The project separates static evidence, dynamic sandbox behavior, reputation, local signatures, and analyst interpretation.
- CAPE provides safer dynamic execution isolation than running samples directly or relying on debugger automation.
- Generic YARA matches are heuristic triage signals, not proof of malware.
- Evidence Score measures how much useful evidence was collected; Maliciousness Likelihood estimates suspiciousness from that evidence.
- Recursive analysis and graph generation help explain multi-stage behavior.

## Known Limitations

- Generic local YARA rules may be noisy and require review.
- CAPE results depend on sandbox health, VM configuration, and network setup.
- Ghidra output quality depends on the sample type and analysis timeout.
- Static-only results cannot prove a file is safe.
- Benign installers and admin tools can look suspicious in sandbox behavior.
- No current IP/domain enrichment.
- No active x64dbg automation.

## Why x64dbg Is Not Active

x64dbg is powerful for manual reverse engineering, but reliable automated debugger-assisted tracing requires careful VM control, ASLR-safe breakpoints, stable scripts, snapshot handling, and memory-dump validation. Those features are future work. Keeping x64dbg inactive avoids presenting unstable debugger automation as production behavior.

## Why CAPE Is Used Instead Of x64dbg Now

CAPE is designed for sandboxed malware execution and already provides task submission, isolated VM execution, behavior reports, signatures, dropped files, process data, and artifacts. For the current implementation, CAPE gives a safer and more defensible dynamic-analysis backend than custom x64dbg automation.

## Why Hash And URL Reputation Are Implemented, But IP/Domain Enrichment Is Future Work

Hash and URL lookups are clear, bounded, and easy to explain: they compare a sample hash or submitted URL against known external intelligence sources. IP/domain enrichment needs more careful context, because infrastructure can be shared, short-lived, benign, or reused by many unrelated services. To avoid overclaiming, StageHawk defers IP/domain enrichment until it can include stronger context and false-positive handling.
