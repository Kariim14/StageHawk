"""Read-only VM/x64dbg environment checks and safe file transfer helpers."""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class VMStatus:
    configured: bool
    machinery: str
    vm_name: str | None
    state: str | None
    snapshots: list[dict[str, str]]
    ssh_host: str | None
    ssh_reachable: bool
    x64dbg_path: str | None
    warnings: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "configured": self.configured,
            "machinery": self.machinery,
            "vm_name": self.vm_name,
            "state": self.state,
            "snapshots": self.snapshots,
            "ssh_host": self.ssh_host,
            "ssh_reachable": self.ssh_reachable,
            "x64dbg_path": self.x64dbg_path,
            "warnings": self.warnings,
        }


def _run(cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)


def check_vm_status(config: dict[str, Any] | None = None) -> VMStatus:
    config = config or {}
    machinery = str(config.get("provider") or config.get("machinery") or "kvm")
    vm_name = config.get("name")
    warnings: list[str] = []
    state = None
    snapshots: list[dict[str, str]] = []

    if machinery == "kvm" and shutil.which("virsh") and vm_name:
        result = _run(["virsh", "domstate", str(vm_name)])
        if result.returncode == 0:
            state = result.stdout.strip()
        else:
            warnings.append(result.stderr.strip() or f"virsh could not query {vm_name}")
        snap_result = _run(["virsh", "snapshot-list", str(vm_name)])
        if snap_result.returncode == 0:
            for line in snap_result.stdout.splitlines()[2:]:
                parts = line.split()
                if parts:
                    snapshots.append({"name": parts[0], "raw": line.strip()})
    elif machinery == "virtualbox":
        warnings.append("VirtualBox support detected only if VBoxManage is installed.")
    else:
        warnings.append("VM machinery not configured or virsh unavailable.")

    ssh_host = config.get("ssh_host")
    ssh_reachable = False
    if ssh_host:
        ssh = _run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", str(ssh_host), "echo OK"], timeout=5)
        ssh_reachable = ssh.returncode == 0 and "OK" in ssh.stdout
        if not ssh_reachable:
            warnings.append(f"SSH host not reachable in batch mode: {ssh_host}")

    configured = bool(vm_name and state)
    return VMStatus(
        configured=configured,
        machinery=machinery,
        vm_name=str(vm_name) if vm_name else None,
        state=state,
        snapshots=snapshots,
        ssh_host=str(ssh_host) if ssh_host else None,
        ssh_reachable=ssh_reachable,
        x64dbg_path=str(config.get("x64dbg_path")) if config.get("x64dbg_path") else None,
        warnings=warnings,
    )


def start_vm_if_needed(config: dict[str, Any]) -> dict[str, Any]:
    status = check_vm_status(config)
    if status.state and status.state.lower() == "running":
        return {"status": "already_running", "vm_status": status.as_dict()}
    if not config.get("auto_start", False):
        return {"status": "skipped", "reason": "VM is not running and auto_start is disabled", "vm_status": status.as_dict()}
    machinery = str(config.get("provider") or config.get("machinery") or "kvm")
    vm_name = config.get("name")
    if machinery != "kvm" or not shutil.which("virsh") or not vm_name:
        return {"status": "failed", "reason": "Only KVM virsh auto-start is implemented", "vm_status": status.as_dict()}
    if config.get("restore_snapshot_before_run"):
        snap = config.get("snapshot_name")
        if not snap:
            return {"status": "failed", "reason": "restore_snapshot_before_run enabled but no snapshot_name set", "vm_status": status.as_dict()}
        restore = _run(["virsh", "snapshot-revert", str(vm_name), str(snap)])
        if restore.returncode != 0:
            return {"status": "failed", "reason": restore.stderr.strip() or "snapshot restore failed", "vm_status": status.as_dict()}
    result = _run(["virsh", "start", str(vm_name)])
    if result.returncode != 0 and "already active" not in result.stderr.lower():
        return {"status": "failed", "reason": result.stderr.strip() or "virsh start failed", "vm_status": status.as_dict()}
    return {"status": "started", "vm_status": check_vm_status(config).as_dict()}


def wait_for_ssh(config: dict[str, Any]) -> dict[str, Any]:
    deadline = time.time() + int(config.get("wait_for_ssh_seconds") or 180)
    ssh_host = config.get("ssh_host")
    if not ssh_host:
        return {"status": "failed", "reason": "ssh_host is not configured"}
    while time.time() < deadline:
        status = check_vm_status(config)
        if status.ssh_reachable:
            return {"status": "reachable", "vm_status": status.as_dict()}
        time.sleep(5)
    return {"status": "failed", "reason": f"SSH did not become reachable for {ssh_host}", "vm_status": check_vm_status(config).as_dict()}
