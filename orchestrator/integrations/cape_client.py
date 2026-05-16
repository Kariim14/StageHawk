"""CAPE Sandbox integration.

The client supports two safe integration modes:

- API mode for reachable CAPE web/API instances.
- File import mode for existing CAPE report folders on disk.

Submission is never performed unless config explicitly enables CAPE and
``submit_sample``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from orchestrator.core.hashing import sha256_file
from orchestrator.analysis.artifact_classifier import classify_artifact


FINAL_STATUSES = {"reported", "failed_analysis", "failed_processing", "failed_reporting"}
SUCCESS_STATUSES = {"reported"}


@dataclass
class CapeStatus:
    installed: bool
    reachable: bool
    api_base_url: str | None
    install_path: str | None
    storage_path: str | None
    services: dict[str, str]
    machinery: str | None
    vm_names: list[str]
    warnings: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "installed": self.installed,
            "reachable": self.reachable,
            "api_base_url": self.api_base_url,
            "install_path": self.install_path,
            "storage_path": self.storage_path,
            "services": self.services,
            "machinery": self.machinery,
            "vm_names": self.vm_names,
            "warnings": self.warnings,
        }


class CapeClient:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.base_url = str(self.config.get("api_base_url") or "http://127.0.0.1:8000").rstrip("/")
        self.token = self.config.get("api_token")
        self.install_path = Path(str(self.config.get("install_path") or "/opt/CAPEv2"))
        self.storage_path = Path(str(self.config.get("storage_path") or self.install_path / "storage" / "analyses"))
        self.timeout = int(self.config.get("timeout_seconds") or 900)
        self.poll_interval = int(self.config.get("poll_interval_seconds") or 10)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Token {self.token}"} if self.token else {}

    def service_status(self) -> dict[str, str]:
        services = {}
        for name in ("cape.service", "cape-web.service", "cape-processor.service", "cape-rooter.service"):
            result = subprocess.run(
                ["systemctl", "is-active", name],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            services[name] = result.stdout.strip() or "unknown"
        return services

    def availability(self) -> CapeStatus:
        warnings: list[str] = []
        installed = self.install_path.exists()
        reachable = False
        try:
            response = requests.get(f"{self.base_url}/apiv2/", timeout=5)
            reachable = response.status_code < 500
        except requests.RequestException as exc:
            warnings.append(f"CAPE API/web not reachable: {exc}")

        machinery = None
        vm_names: list[str] = []
        cuckoo_conf = self.install_path / "conf" / "cuckoo.conf"
        if cuckoo_conf.exists():
            for line in cuckoo_conf.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.strip().startswith("machinery"):
                    machinery = line.split("=", 1)[-1].strip()
                    break

        if machinery:
            machine_conf = self.install_path / "conf" / f"{machinery}.conf"
            if machine_conf.exists():
                for line in machine_conf.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.strip().startswith("machines"):
                        vm_names = [part.strip() for part in line.split("=", 1)[-1].split(",") if part.strip()]
                        break

        if not installed:
            warnings.append(f"CAPE install path not found: {self.install_path}")
        if not self.storage_path.exists():
            warnings.append(f"CAPE storage path not found: {self.storage_path}")

        return CapeStatus(
            installed=installed,
            reachable=reachable,
            api_base_url=self.base_url,
            install_path=str(self.install_path),
            storage_path=str(self.storage_path),
            services=self.service_status(),
            machinery=machinery,
            vm_names=vm_names,
            warnings=warnings,
        )

    def submit_sample(
        self,
        sample_path: str | Path,
        machine: str | None = None,
        timeout: int | None = None,
        options: str | None = None,
    ) -> dict[str, Any]:
        path = Path(sample_path)
        with path.open("rb") as f:
            files = {"file": (path.name, f)}
            data = {}
            if machine:
                data["machine"] = machine
            if timeout:
                data["timeout"] = str(timeout)
            if options:
                data["options"] = options
            response = requests.post(
                f"{self.base_url}/apiv2/tasks/create/file/",
                headers=self._headers(),
                files=files,
                data=data,
                timeout=60,
            )
        response.raise_for_status()
        return response.json()

    def task_view(self, task_id: int | str) -> dict[str, Any]:
        response = requests.get(
            f"{self.base_url}/apiv2/tasks/view/{task_id}/",
            headers=self._headers(),
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def poll_task(self, task_id: int | str, progress_callback: Any | None = None) -> dict[str, Any]:
        deadline = time.time() + self.timeout
        last = {}
        while time.time() < deadline:
            last = self.task_view(task_id)
            status = str((last.get("data") or {}).get("status") or "")
            if progress_callback:
                progress_callback({"task_id": task_id, "status": status, "raw": last})
            if status in FINAL_STATUSES:
                return last
            time.sleep(self.poll_interval)
        last["poll_timeout"] = True
        return last

    def report_path_for_task(self, task_id: int | str) -> Path:
        return self.storage_path / str(task_id) / "reports" / "report.json"

    def extract_task_id(self, submission: dict[str, Any]) -> int | str | None:
        candidates = [
            submission.get("task_id"),
            submission.get("taskid"),
            (submission.get("data") or {}).get("task_id") if isinstance(submission.get("data"), dict) else None,
            (submission.get("data") or {}).get("taskid") if isinstance(submission.get("data"), dict) else None,
        ]
        task_ids = submission.get("task_ids")
        if not task_ids and isinstance(submission.get("data"), dict):
            task_ids = (submission.get("data") or {}).get("task_ids")
        if task_ids:
            candidates.append(task_ids[0])
        for value in candidates:
            if value is not None:
                return value
        return None

    def api_download(self, endpoint: str, destination: Path) -> bool:
        try:
            response = requests.get(f"{self.base_url}{endpoint}", headers=self._headers(), timeout=120)
            if response.status_code != 200 or not response.content:
                return False
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(response.content)
            return True
        except requests.RequestException:
            return False

    def find_local_report_by_sha256(self, sha256: str) -> Path | None:
        if not self.storage_path.exists():
            return None
        newest: tuple[float, Path] | None = None
        for report_path in self.storage_path.glob("*/reports/report.json"):
            try:
                data = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            target_sha = (
                data.get("target", {})
                .get("file", {})
                .get("sha256")
            )
            if target_sha == sha256:
                mtime = report_path.stat().st_mtime
                if newest is None or mtime > newest[0]:
                    newest = (mtime, report_path)
        return newest[1] if newest else None

    def latest_local_report(self) -> Path | None:
        reports = sorted(self.storage_path.glob("*/reports/report.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        return reports[0] if reports else None

    def import_report(
        self,
        report_path: str | Path,
        case_cape_dir: str | Path,
        timing_context: Any | None = None,
    ) -> dict[str, Any]:
        from orchestrator.core.timing import record_step_timing, start_step_timing

        # CAPE report parsing and artifact copying live in the same import
        # workflow. These timers use the nearest safe boundaries without changing
        # import behavior: report read/copy is cape_import, file copy/classify is
        # cape_artifact_copy.
        import_started = (
            start_step_timing(
                timing_context,
                "cape_import",
                extra={"boundary": "CAPE report read and case report copy"},
            )
            if timing_context is not None
            else None
        )
        src = Path(report_path)
        out = Path(case_cape_dir)
        out.mkdir(parents=True, exist_ok=True)
        try:
            report_data = json.loads(src.read_text(encoding="utf-8", errors="ignore"))
            task_dir = src.parents[1]

            report_dst = out / "cape_report.json"
            shutil.copy2(src, report_dst)
        except Exception as exc:
            if timing_context is not None and import_started is not None:
                record_step_timing(timing_context, "cape_import", import_started, status="failed", extra={"error": str(exc)})
            raise

        if timing_context is not None and import_started is not None:
            record_step_timing(timing_context, "cape_import", import_started, status="completed")

        copied_artifacts: list[dict[str, Any]] = []
        artifact_started = (
            start_step_timing(
                timing_context,
                "cape_artifact_copy",
                extra={"boundary": "CAPE artifact file copy and classification"},
            )
            if timing_context is not None
            else None
        )
        try:
            for rel, kind in [
                ("files", "cape_dropped_file"),
                ("selfextracted", "cape_dropped_file"),
                ("procdump", "memory_dump"),
                ("shots", "screenshot"),
                ("logs", "runtime_log"),
                ("tlsdump", "network_event"),
            ]:
                source_dir = task_dir / rel
                if not source_dir.exists():
                    continue
                dest_dir = out / ("dropped_files" if kind == "cape_dropped_file" else rel)
                dest_dir.mkdir(parents=True, exist_ok=True)
                for item in source_dir.iterdir():
                    if not item.is_file():
                        continue
                    dst = dest_dir / item.name
                    shutil.copy2(item, dst)
                    classification = classify_artifact(dst)
                    is_stage = kind == "cape_dropped_file" and classification.get("file_type") in {"pe_or_mz_like", "stage_blob", "cape_artifact"}
                    copied_artifacts.append(
                        {
                            "artifact_kind": kind,
                            "source_backend": "cape",
                            "source_path": str(item),
                            "path": str(dst),
                            "destination_path": str(dst),
                            "name": item.name,
                            "size": dst.stat().st_size,
                            "sha256": sha256_file(dst),
                            "file_type": classification.get("file_type"),
                            "is_stage_artifact": is_stage,
                            "stage_id": f"cape_artifact_{len(copied_artifacts) + 1:03d}" if is_stage else None,
                            "confidence": 0.75 if is_stage else 0.5,
                            "evidence_reference": "cape_report_import",
                            "relationship_basis": "cape_observed_artifact",
                        }
                    )
        except Exception as exc:
            if timing_context is not None and artifact_started is not None:
                record_step_timing(timing_context, "cape_artifact_copy", artifact_started, status="failed", extra={"error": str(exc)})
            raise

        if timing_context is not None and artifact_started is not None:
            record_step_timing(
                timing_context,
                "cape_artifact_copy",
                artifact_started,
                status="completed",
                extra={"artifact_count": len(copied_artifacts)},
            )

        summary = summarize_cape_report(report_data)
        summary.update(
            {
                "source_report_path": str(src),
                "case_report_path": str(report_dst),
                "task_dir": str(task_dir),
                "copied_artifacts": copied_artifacts,
            }
        )
        (out / "cape_task.json").write_text(json.dumps({"task_id": summary.get("task_id"), "task_dir": str(task_dir)}, indent=2), encoding="utf-8")
        (out / "cape_artifacts.json").write_text(json.dumps(copied_artifacts, indent=2), encoding="utf-8")
        write_cape_summary(summary, out / "cape_summary.md")
        return summary

    def import_zip_payloads(self, task_id: int | str, case_cape_dir: str | Path, endpoint: str) -> list[dict[str, Any]]:
        zip_path = Path(case_cape_dir) / f"cape_{task_id}_payloads.zip"
        if not self.api_download(endpoint, zip_path):
            return []
        extracted_dir = Path(case_cape_dir) / "api_payloads"
        extracted_dir.mkdir(parents=True, exist_ok=True)
        records: list[dict[str, Any]] = []
        try:
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(extracted_dir)
        except zipfile.BadZipFile:
            return records
        for item in extracted_dir.rglob("*"):
            if item.is_file():
                records.append(
                    {
                        "artifact_kind": "cape_dropped_file",
                        "source_backend": "cape_api",
                        "path": str(item),
                        "name": item.name,
                        "size": item.stat().st_size,
                        "sha256": sha256_file(item),
                    }
                )
        return records


def summarize_cape_report(report: dict[str, Any]) -> dict[str, Any]:
    info = report.get("info", {})
    behavior = report.get("behavior", {})
    cape = report.get("CAPE", {})
    signatures = report.get("signatures") or []
    network = report.get("network") or {}
    target = report.get("target", {})
    return {
        "task_id": info.get("id"),
        "score": report.get("malscore"),
        "status": report.get("malstatus"),
        "target": target,
        "machine": info.get("machine"),
        "duration": info.get("duration"),
        "signature_count": len(signatures),
        "signatures": [
            {
                "name": sig.get("name"),
                "description": sig.get("description"),
                "severity": sig.get("severity"),
                "ttps": sig.get("ttps", []),
            }
            for sig in signatures
        ],
        "process_count": len(behavior.get("processes") or []),
        "process_tree": behavior.get("processtree") or [],
        "behavior_summary": behavior.get("summary") or {},
        "network": network,
        "cape_payload_count": len(cape.get("payloads") or []),
        "cape_config_count": len(cape.get("configs") or []),
        "ttps": report.get("ttps") or [],
    }


def write_cape_summary(summary: dict[str, Any], path: str | Path) -> None:
    lines = [
        "# CAPE Summary",
        "",
        f"- Task ID: `{summary.get('task_id')}`",
        f"- Score: `{summary.get('score')}`",
        f"- Status: `{summary.get('status')}`",
        f"- Signatures: `{summary.get('signature_count')}`",
        f"- Processes: `{summary.get('process_count')}`",
        f"- CAPE payloads: `{summary.get('cape_payload_count')}`",
        "",
        "## Signatures",
        "",
    ]
    for sig in summary.get("signatures", []):
        lines.append(f"- `{sig.get('name')}` severity `{sig.get('severity')}`")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
