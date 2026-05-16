# Web Interface

Run:

```bash
.venv/bin/python -m orchestrator.web
```

Open:

```text
http://127.0.0.1:8088
```

Main pages:

- `/` dashboard
- `/new` new analysis form
- `/cases/{case_id}` case detail
- `/cases/{case_id}/graph` graph view
- `/cases/{case_id}/report` report view

API endpoints:

- `GET /health`
- `GET /api/config/status`
- `GET /api/cases`
- `POST /api/analyze`
- `GET /api/jobs/{job_id}`
- `GET /api/cases/{case_id}/status`
- `GET /api/cases/{case_id}/report`
- `GET /api/cases/{case_id}/graph`
- `GET /api/cases/{case_id}/artifacts`
