# Architecture

The project is organized as a reusable backend automation engine.

```text
orchestrator/
  cli.py                     thin CLI wrapper
  core/                      backend orchestration services
  integrations/              tool adapters: Ghidra, x64dbg, SSH/SCP
  web/                       local FastAPI UI/API
  analysis/                  parsers, stage detection, IOC and behavior mapping
  schemas/                   JSON output contracts
```

The intended high-level flow is:

```text
sample input
  -> case creation
  -> static analysis
  -> stage candidate detection
  -> dynamic plan generation
  -> dynamic execution or safe fixture replay
  -> optional CAPE API/file import
  -> runtime evidence collection
  -> artifact extraction/classification
  -> recursive-safe child stage handling
  -> stage graph
  -> final reports
```

The CLI must stay thin. GUI/web/chatbot integrations should call `run_full_pipeline()`.
