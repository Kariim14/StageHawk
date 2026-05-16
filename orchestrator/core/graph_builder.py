"""Stage dependency graph reconstruction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _build_stage_graph_raw(
    input_metadata: dict[str, Any],
    extracted_artifacts: list[dict[str, Any]],
    iocs: dict[str, list[str]] | None = None,
    mitre_mappings: list[dict[str, str]] | None = None,
    cape_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cape_summary = (cape_result or {}).get("summary", {})
    nodes: list[dict[str, Any]] = [
        {
            "stage_id": "root",
            "name": input_metadata.get("name", "original_sample"),
            "file_path": input_metadata.get("path"),
            "sha256": input_metadata.get("sha256"),
            "size": input_metadata.get("size"),
            "file_type": "input_sample",
            "source_type": "user_supplied_sample",
            "source_backend": "input",
            "static_summary": {},
            "dynamic_summary": {},
            "cape_summary": cape_summary,
            "iocs": iocs or {},
            "mitre_techniques": mitre_mappings or [],
            "analysis_status": "completed",
            "case_output_paths": {},
        }
    ]
    edges: list[dict[str, Any]] = []

    sorted_artifacts = sorted(
        [item for item in extracted_artifacts if item.get("graph_include", item.get("is_stage_artifact"))],
        key=lambda item: int(item.get("stage_number") or 999),
    )

    parent = "root"
    for artifact in sorted_artifacts:
        stage_id = str(artifact.get("stage_id") or f"stage_{len(nodes):03d}")
        nodes.append(
            {
                "stage_id": stage_id,
                "name": Path(str(artifact.get("source_path", stage_id))).name,
                "file_path": artifact.get("destination_path") or artifact.get("path"),
                "sha256": artifact.get("sha256"),
                "size": artifact.get("size"),
                "file_type": artifact.get("file_type"),
                "source_type": artifact.get("artifact_role") or artifact.get("artifact_kind"),
                "source_backend": artifact.get("source_backend", "x64dbg" if str(artifact.get("evidence_reference", "")).startswith("x64dbg") else "runtime"),
                "static_summary": artifact.get("static_summary", {}),
                "dynamic_summary": {
                    "evidence_reference": artifact.get("evidence_reference"),
                    "relationship_basis": artifact.get("relationship_basis"),
                },
                "cape_summary": artifact.get("cape_summary", {}),
                "iocs": {},
                "mitre_techniques": [],
                "analysis_status": artifact.get("analysis_status", "static_skipped"),
                "case_output_paths": {
                    "metadata": str(Path(str(artifact.get("destination_path", ""))).parent / "metadata.json")
                    if artifact.get("destination_path")
                    else None
                },
            }
        )
        edges.append(
            {
                "edge_id": f"edge_{len(edges) + 1:03d}",
                "parent_stage": parent,
                "child_stage": stage_id,
                "transition_reason": artifact.get("artifact_triage_reason") or "high-value artifact selected for stage graph",
                "observed_backend": artifact.get("source_backend", "x64dbg" if artifact.get("artifact_kind") != "cape_dropped_file" else "cape"),
                "observed_api_or_event": artifact.get("source_api_or_event") or artifact.get("artifact_kind") or "dropped_file",
                "confidence": artifact.get("confidence", 0.7),
                "evidence_reference": artifact.get("evidence_reference"),
                "evidence_source": "cape_observed"
                if artifact.get("artifact_kind") == "cape_dropped_file"
                else ("x64dbg_observed" if artifact.get("relationship_basis", "").startswith("observed") else "filename_inference"),
            }
        )
        parent = stage_id

    return {
        "schema_version": "1.0",
        "graph_type": "stage_dependency_graph",
        "nodes": nodes,
        "edges": edges,
        "limitations": [
            "Memory buffer dumping is not implemented yet.",
            "Relationships are only direct observations when backed by collected files/logs.",
        ],
    }






def _normalize_cape_artifact_edges(graph: dict[str, Any]) -> dict[str, Any]:
    """Normalize CAPE artifact relationships.

    CAPE dropped-file evidence usually proves:
        root sample execution -> observed artifact

    It does not prove:
        artifact A -> artifact B -> artifact C

    Unless a true real_parent_stage is explicitly available, CAPE artifact edges
    are normalized to root -> artifact.
    """
    for edge in graph.get("edges", []):
        child = str(
            edge.get("child_stage")
            or edge.get("child")
            or edge.get("to")
            or edge.get("target")
            or edge.get("target_stage")
            or ""
        )

        evidence_text = " ".join(
            str(edge.get(k) or "").lower()
            for k in [
                "evidence_source",
                "observed_event",
                "observed_api_or_event",
                "observed_backend",
                "relationship_basis",
                "transition_reason",
                "edge_type",
            ]
        )

        is_cape_artifact_edge = (
            child.startswith("cape_artifact_")
            or "cape_observed" in evidence_text
            or "cape_dropped_file" in evidence_text
            or "cape artifact" in evidence_text
            or str(edge.get("observed_backend") or "").lower() == "cape"
        )

        # Important:
        # parent_stage may already contain a fake sequential parent.
        # Only real_parent_stage should prevent root normalization.
        explicit_real_parent = edge.get("real_parent_stage")

        if is_cape_artifact_edge and not explicit_real_parent:
            edge["parent_stage"] = "root"
            edge["parent"] = "root"
            edge["from"] = "root"
            edge["source"] = "root"
            edge["source_stage"] = "root"

            if child:
                edge["child_stage"] = child
                edge["child"] = child
                edge["to"] = child
                edge["target"] = child
                edge["target_stage"] = child

            edge["observed_event"] = edge.get("observed_event") or "cape_dropped_file"
            edge["observed_api_or_event"] = edge.get("observed_api_or_event") or "cape_dropped_file"
            edge["evidence_source"] = edge.get("evidence_source") or "cape_observed"
            edge["transition_reason"] = "CAPE artifact observed during root sample execution"

    return _normalize_cape_artifact_edges(graph)


def _write_graph_outputs_raw(graph: dict[str, Any], output_dir: str | Path) -> dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "stage_graph.json"
    dot_path = out / "stage_graph.dot"
    md_path = out / "stage_graph.md"

    json_path.write_text(json.dumps(graph, indent=2), encoding="utf-8")

    dot_lines = ["digraph stage_graph {"]
    for node in graph.get("nodes", []):
        label = f"{node.get('stage_id')}\\n{node.get('name')}"
        dot_lines.append(f'  "{node.get("stage_id")}" [label="{label}"];')
    for edge in graph.get("edges", []):
        label = edge.get("observed_api_or_event") or edge.get("transition_reason")
        dot_lines.append(
            f'  "{edge.get("parent_stage")}" -> "{edge.get("child_stage")}" [label="{label}"];'
        )
    dot_lines.append("}")
    dot_path.write_text("\n".join(dot_lines) + "\n", encoding="utf-8")

    md_lines = ["# Stage Graph", ""]
    for node in graph.get("nodes", []):
        md_lines.append(f"- `{node.get('stage_id')}`: {node.get('name')} ({node.get('file_type')})")
    if graph.get("edges"):
        md_lines.extend(["", "## Edges", ""])
        for edge in graph.get("edges", []):
            md_lines.append(
                f"- `{edge.get('parent_stage')}` -> `{edge.get('child_stage')}` "
                f"via `{edge.get('observed_api_or_event')}` "
                f"({edge.get('evidence_source')}, confidence {edge.get('confidence')})"
            )
    else:
        md_lines.extend(["", "No child stage artifacts were collected in this run."])
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    return {
        "stage_graph_json": str(json_path),
        "stage_graph_dot": str(dot_path),
        "stage_graph_md": str(md_path),
    }


# === StageHawk graph edge normalization wrappers v2 ===

def _force_cape_edges_to_root(graph):
    """Force CAPE observed dropped-file relationships to root -> artifact.

    CAPE evidence normally proves that artifacts were observed during the root
    sample execution. It does not prove artifact_004 dropped artifact_009 unless
    CAPE gives a real parent relationship.
    """
    if not isinstance(graph, dict):
        return graph

    for edge in graph.get("edges", []) or []:
        if not isinstance(edge, dict):
            continue

        child = str(
            edge.get("child_stage")
            or edge.get("child")
            or edge.get("to")
            or edge.get("target")
            or edge.get("target_stage")
            or ""
        )

        evidence_text = " ".join(
            str(edge.get(k) or "").lower()
            for k in (
                "evidence_source",
                "observed_event",
                "observed_api_or_event",
                "observed_backend",
                "relationship_basis",
                "transition_reason",
                "edge_type",
            )
        )

        is_cape_artifact_edge = (
            child.startswith("cape_artifact_")
            or str(edge.get("observed_backend") or "").lower() == "cape"
            or "cape_observed" in evidence_text
            or "cape_dropped_file" in evidence_text
        )

        # Only preserve a non-root parent if future code explicitly sets a real parent.
        has_real_parent = bool(edge.get("real_parent_stage"))

        if is_cape_artifact_edge and not has_real_parent:
            edge["parent_stage"] = "root"
            edge["parent"] = "root"
            edge["from"] = "root"
            edge["source"] = "root"
            edge["source_stage"] = "root"

            if child:
                edge["child_stage"] = child
                edge["child"] = child
                edge["to"] = child
                edge["target"] = child
                edge["target_stage"] = child

            edge["observed_event"] = "cape_dropped_file"
            edge["observed_api_or_event"] = "cape_dropped_file"
            edge["evidence_source"] = "cape_observed"
            edge["transition_reason"] = "CAPE artifact observed during root sample execution"

    return graph


def build_stage_graph(*args, **kwargs):
    graph = _build_stage_graph_raw(*args, **kwargs)
    return _force_cape_edges_to_root(graph)


def write_graph_outputs(graph, *args, **kwargs):
    graph = _force_cape_edges_to_root(graph)
    return _write_graph_outputs_raw(graph, *args, **kwargs)

