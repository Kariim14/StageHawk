import json

from orchestrator.core.graph_builder import build_stage_graph, write_graph_outputs
from orchestrator.core.report_builder import build_final_report, write_final_report


def test_graph_and_report_generation(tmp_path):
    input_metadata = {
        "name": "root.exe",
        "path": "/tmp/root.exe",
        "sha256": "a" * 64,
        "size": 10,
    }
    artifact = {
        "stage_id": "stage_002",
        "stage_number": 2,
        "source_path": "dropped_stage2.bin",
        "destination_path": str(tmp_path / "artifact.bin"),
        "sha256": "b" * 64,
        "size": 18,
        "file_type": "stage_blob",
        "artifact_kind": "dropped_file",
        "is_stage_artifact": True,
        "confidence": 0.9,
        "evidence_reference": "runtime_dropped_file",
        "relationship_basis": "observed_file_name_from_runtime_output",
    }

    graph = build_stage_graph(input_metadata, [artifact], {}, [])
    paths = write_graph_outputs(graph, tmp_path / "graph")

    assert len(graph["nodes"]) == 2
    assert graph["edges"][0]["evidence_source"] == "x64dbg_observed"
    assert paths["stage_graph_json"].endswith("stage_graph.json")

    report = build_final_report(
        manifest={"case_id": "case1", "case_name": "case", "current_status": "completed", "timestamps": {}},
        input_metadata=input_metadata,
        static_summary={"function_count": 1},
        stage_candidates=[],
        runtime_events={"event_count": 0},
        artifacts=[artifact],
        graph=graph,
        iocs={},
        mitre_mappings=[],
    )
    report_paths = write_final_report(report, tmp_path / "reports")

    assert json.loads((tmp_path / "reports" / "final_report.json").read_text())["case"]["case_id"] == "case1"
    assert report_paths["final_report_md"].endswith("final_report.md")


def test_report_explains_generic_signature_quality(tmp_path):
    signature_scan_path = tmp_path / "static" / "signature_scan.json"
    signature_scan_path.parent.mkdir()
    signature_scan_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "sample_path": str(tmp_path / "sample.exe"),
                "verdict": "matched_known_signature",
                "engines": {
                    "yara": {
                        "engine": "yara",
                        "available": True,
                        "rules_loaded": ["signatures/yara/generic/stagehawk_generic_suspicious_pe.yar"],
                        "status": "matched",
                        "matches": [
                            {
                                "rule": "StageHawk_Generic_Test",
                                "source_rule_file": "signatures/yara/generic/stagehawk_generic_suspicious_pe.yar",
                                "collection": "generic",
                                "quality": "generic",
                                "confidence_meaning": "heuristic triage signal, not confirmed malware",
                                "raw": "StageHawk_Generic_Test sample.exe",
                            }
                        ],
                        "match_count": 1,
                        "error": None,
                    },
                    "clamav": {
                        "engine": "clamav",
                        "available": False,
                        "status": "unavailable",
                        "matches": [],
                        "match_count": 0,
                        "error": "clamscan binary not found",
                    },
                },
                "signature_catalog": {
                    "metadata_loaded": True,
                    "metadata_path": "signatures/yara/METADATA.json",
                    "collections": {
                        "generic": {
                            "quality": "generic",
                            "confidence_meaning": "heuristic triage signal, not confirmed malware",
                            "rule_files": ["signatures/yara/generic/stagehawk_generic_suspicious_pe.yar"],
                        },
                        "known_families": {
                            "quality": "known_family",
                            "confidence_meaning": "verified attributed family rule when populated",
                            "rule_files": [],
                        },
                        "experimental": {
                            "quality": "experimental",
                            "confidence_meaning": "research/testing signal only",
                            "rule_files": [],
                        },
                    },
                },
                "summary": {
                    "matched_engine_count": 1,
                    "clean_engine_count": 0,
                    "unavailable_engine_count": 1,
                    "not_configured_engine_count": 0,
                    "error_engine_count": 0,
                    "total_match_count": 1,
                },
            }
        ),
        encoding="utf-8",
    )

    report = build_final_report(
        manifest={
            "case_id": "case_sig_quality",
            "case_name": "signature quality",
            "current_status": "completed",
            "timestamps": {},
            "output_paths": {"signature_scan": str(signature_scan_path)},
        },
        input_metadata={"name": "sample.exe", "sha256": "a" * 64, "size": 10},
        static_summary={},
        stage_candidates=[],
        runtime_events={"event_count": 0},
        artifacts=[],
        graph={"nodes": [], "edges": []},
        iocs={},
        mitre_mappings=[],
    )
    write_final_report(report, tmp_path / "reports")

    final_report = json.loads((tmp_path / "reports" / "final_report.json").read_text(encoding="utf-8"))
    markdown = (tmp_path / "reports" / "final_report.md").read_text(encoding="utf-8")

    assert final_report["signature_quality"]["match_quality_counts"]["generic"] == 1
    assert "Generic local YARA rules are heuristic triage signals" in markdown
    assert "they do not confirm malware by themselves" in markdown
    assert "Known-family attribution is only valid" in markdown
    assert "The ClamAV engine was unavailable" in markdown


def test_report_preserves_cape_substep_timing(tmp_path):
    timing_path = tmp_path / "case_timing.json"
    timing_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "case_id": "case_cape_timing",
                "status": "completed",
                "duration_seconds": 5.0,
                "total_duration_seconds": 5.0,
                "steps": {
                    "cape_submission": {"status": "completed", "duration_seconds": 0.1},
                    "cape_sandbox_wait": {"status": "completed", "duration_seconds": 3.2},
                    "cape_import": {"status": "completed", "duration_seconds": 0.4},
                    "cape_artifact_copy": {"status": "completed", "duration_seconds": 0.2},
                    "cape_total": {"status": "completed", "duration_seconds": 4.0},
                },
            }
        ),
        encoding="utf-8",
    )
    report = build_final_report(
        manifest={"case_id": "case_cape_timing", "case_name": "case", "current_status": "completed", "timestamps": {}},
        input_metadata={"name": "root.exe", "path": "/tmp/root.exe", "sha256": "a" * 64, "size": 10},
        static_summary={},
        stage_candidates=[],
        runtime_events={"event_count": 0},
        artifacts=[],
        graph={"nodes": [], "edges": []},
        iocs={},
        mitre_mappings=[],
        backend_status={"cape_result": {"status": "completed", "mode": "file_import", "summary": {"signature_count": 0}}},
    )

    write_final_report(report, tmp_path / "reports")

    final_json = json.loads((tmp_path / "reports" / "final_report.json").read_text(encoding="utf-8"))
    markdown = (tmp_path / "reports" / "final_report.md").read_text(encoding="utf-8")

    assert "cape_submission" in final_json["timing"]["steps"]
    assert "cape_artifact_copy" in final_json["timing"]["steps"]
    assert "### CAPE Phase Timing" in markdown
    assert "`cape_submission`" in markdown
    assert "`cape_sandbox_wait`" in markdown
