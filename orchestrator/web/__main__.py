"""Run with ``python -m orchestrator.web``."""

from __future__ import annotations

import uvicorn

from orchestrator.core.config_loader import load_config


def main() -> None:
    config = load_config()
    web = config.get("web", {})
    uvicorn.run(
        "orchestrator.web.app:app",
        host=str(web.get("host", "127.0.0.1")),
        port=int(web.get("port", 8088)),
        reload=False,
    )


if __name__ == "__main__":
    main()
