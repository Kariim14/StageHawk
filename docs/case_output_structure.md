# Case Output Structure

```text
results/cases/<case_id>/
  case_manifest.json
  input/
    original_sample.exe
    original_sample_metadata.json
  static/
    ghidra_out.json
    stage_candidates.json
  dynamic/
    breakpoint_plan.json
    x64dbg_script.txt
    runtime_events.json
    runtime_summary.md
    raw_logs/
    evidence/
      api_hit_markers/
      dropped_files/
      memory_dumps/
      process_events/
      network_events/
      registry_events/
  extracted/
  graph/
    stage_graph.json
    stage_graph.dot
    stage_graph.md
  reports/
    final_report.json
    final_report.md
```

`case_manifest.json` tracks statuses using:

- `pending`
- `running`
- `completed`
- `failed`
- `skipped`
