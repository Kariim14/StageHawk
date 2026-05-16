# Future GUI / Web / Chatbot Integration

The backend entry point is:

```python
from orchestrator.core.pipeline import run_full_pipeline

result = run_full_pipeline(sample_path, case_name="demo")
```

Expected input:

- `sample_path`: path to a sample already stored in a safe upload/quarantine location.
- `case_name`: optional human-readable name.
- `config_path`: optional config override.
- `max_depth`: recursion limit.

Expected returned result:

- `case_id`
- `case_name`
- `current_status`
- `case_root`
- `manifest_path`
- `output_paths`
- `warnings`
- `errors`

A dashboard can render `graph/stage_graph.json`. The included FastAPI web UI already does this locally. A chatbot can summarize `reports/final_report.json` and point users to the Markdown report.
