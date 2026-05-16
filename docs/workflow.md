# Workflow

Development command:

```bash
python -m orchestrator analyze samples/fake/fake_dropper_sample.exe --case-name fake_dropper_demo
```

Default configuration uses bundled fake-sample static and runtime fixtures when live Ghidra/x64dbg execution is disabled. This keeps the pipeline reproducible without pretending that live dynamic analysis ran.

To enable live tools later, edit `config/default.yaml` or pass a separate config file and set:

```yaml
run_ghidra: true
run_windows_dynamic: true
```

Live dynamic mode should only be used with an isolated Windows VM.

Website:

```bash
.venv/bin/python -m orchestrator.web
```

Then open `http://127.0.0.1:8088`.

Tests:

```bash
source .venv/bin/activate
python -m pytest -q
```
