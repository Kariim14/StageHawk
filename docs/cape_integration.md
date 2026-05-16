# CAPE Integration

The backend integrates with CAPE through `orchestrator.integrations.cape_client`.

Supported modes:

- `api`: submit/poll/download through CAPE API when explicitly enabled.
- `file`: import existing local CAPE reports from `storage/analyses`.

Default config keeps CAPE disabled:

```yaml
cape:
  enabled: false
  mode: api
  api_base_url: http://127.0.0.1:8000
  storage_path: /opt/CAPEv2/storage/analyses
  submit_sample: false
```

When enabled, CAPE output is copied into:

```text
results/cases/<case_id>/cape/
  cape_status.json
  cape_result.json
  cape_task.json
  cape_report.json
  cape_artifacts.json
  dropped_files/
  shots/
  logs/
  cape_summary.md
```

If CAPE is unavailable or disabled, the pipeline records a clear skipped/failed status instead of crashing.

For the local May 8, 2026 environment, the bundled fake sample was submitted
through CAPE API mode and CAPE task `10` completed with a report, dropped files,
logs, and process dump artifacts imported into the case folder.

Important local note: the CAPE database machine metadata was corrected so
`win10` can service x64 tasks. The root-owned `/opt/CAPEv2/conf/kvm.conf` still
needs the same persistent correction (`arch = x64`, `tags = x64,win10`) if CAPE
reloads machines from config.
