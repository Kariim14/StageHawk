# VM / x64dbg Integration

The backend uses:

- `orchestrator.integrations.vm_manager` for read-only VM/x64dbg status checks.
- `orchestrator.integrations.x64dbg_live_runner` as the backend wrapper for live x64dbg execution.
- Existing x64dbg preparation scripts remain in `orchestrator.integrations`.

Live Windows VM dynamic analysis is disabled by default:

```yaml
run_windows_dynamic: false
vm:
  enabled: false
  machinery: kvm
  name: win10
  ssh_host: malproj-win10
```

If enabled but the VM/SSH/x64dbg path is not ready, the pipeline marks dynamic analysis as skipped or failed honestly.

Samples are never executed on the Ubuntu/controller host.
