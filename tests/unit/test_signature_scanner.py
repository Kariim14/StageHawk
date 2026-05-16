import json
import shutil

import pytest

from orchestrator.analysis.signature_scanner import run_signature_scan, scan_with_yara


def _skip_without_yara() -> None:
    if not shutil.which("yara"):
        pytest.skip("yara binary is not available")


def _scanner_config(rule_dir):
    return {
        "signature_rules_dirs": [str(rule_dir)],
        "signature_rule_files": [],
        "signature_scan_timeout_seconds": 30,
        "clamscan_binary": "__stagehawk_test_missing_clamscan__",
    }


def _write_metadata(root, rule_file="signatures/yara/generic/test_rule.yar"):
    (root / "METADATA.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "purpose": "test metadata",
                "rule_collections": {
                    "generic": {"rule_files": [rule_file]},
                    "known_families": {"rule_files": []},
                    "experimental": {"rule_files": []},
                },
                "quality_policy": [],
                "safety_notes": [],
                "last_updated": "2026-05-10",
            }
        ),
        encoding="utf-8",
    )


def test_yara_rule_file_is_discovered_recursively_and_used(tmp_path):
    _skip_without_yara()
    rule_dir = tmp_path / "rules"
    nested_dir = rule_dir / "nested"
    nested_dir.mkdir(parents=True)
    rule_file = nested_dir / "stagehawk_test_rule.yar"
    rule_file.write_text(
        """
rule StageHawk_Test_Discovery
{
    strings:
        $marker = "STAGEHAWK_TEST_DISCOVERY_MARKER"
    condition:
        $marker
}
""",
        encoding="utf-8",
    )
    sample = tmp_path / "sample.bin"
    sample.write_text("benign test fixture with STAGEHAWK_TEST_DISCOVERY_MARKER", encoding="utf-8")

    result = scan_with_yara(sample, _scanner_config(rule_dir))

    assert result["status"] == "matched"
    assert str(rule_file.resolve()) in result["rules_loaded"]
    assert result["matches"][0]["rule"] == "StageHawk_Test_Discovery"
    assert result["matches"][0]["source_rule_file"] == str(rule_file.resolve())


def test_signature_catalog_is_included_when_metadata_is_present(tmp_path):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    _write_metadata(rule_dir)
    sample = tmp_path / "sample.bin"
    sample.write_text("benign test fixture without local signature rules", encoding="utf-8")
    output_json = tmp_path / "signature_scan.json"

    result = run_signature_scan(sample, output_json, _scanner_config(rule_dir))

    catalog = result["signature_catalog"]
    assert catalog["metadata_loaded"] is True
    assert catalog["metadata_path"] == str(rule_dir / "METADATA.json")
    assert catalog["collections"]["generic"]["quality"] == "generic"
    assert catalog["collections"]["generic"]["confidence_meaning"] == (
        "heuristic triage signal, not confirmed malware"
    )
    assert catalog["collections"]["known_families"]["rule_files"] == []


def test_matching_yara_rule_produces_signature_scan_match_output(tmp_path):
    _skip_without_yara()
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    rule_file = rule_dir / "stagehawk_test_match.yar"
    rule_file.write_text(
        """
rule StageHawk_Test_Match_Output
{
    strings:
        $marker = "STAGEHAWK_TEST_MATCH_OUTPUT_MARKER"
    condition:
        $marker
}
""",
        encoding="utf-8",
    )
    sample = tmp_path / "sample.bin"
    sample.write_text("benign test fixture with STAGEHAWK_TEST_MATCH_OUTPUT_MARKER", encoding="utf-8")
    output_json = tmp_path / "out" / "signature_scan.json"

    result = run_signature_scan(sample, output_json, _scanner_config(rule_dir))
    persisted = json.loads(output_json.read_text(encoding="utf-8"))

    assert result["verdict"] == "matched_known_signature"
    assert result["summary"]["total_match_count"] >= 1
    assert result["engines"]["yara"]["status"] == "matched"
    assert any(
        match["rule"] == "StageHawk_Test_Match_Output"
        for match in result["engines"]["yara"]["matches"]
    )
    assert result["engines"]["clamav"]["status"] == "unavailable"
    assert persisted == result


def test_generic_yara_match_is_enriched_as_heuristic_evidence(tmp_path):
    _skip_without_yara()
    rule_dir = tmp_path / "rules"
    generic_dir = rule_dir / "generic"
    generic_dir.mkdir(parents=True)
    rule_file = generic_dir / "stagehawk_test_generic.yar"
    _write_metadata(rule_dir, rule_file=str(rule_file))
    rule_file.write_text(
        """
rule StageHawk_Test_Generic_Heuristic
{
    strings:
        $marker = "STAGEHAWK_TEST_GENERIC_HEURISTIC_MARKER"
    condition:
        $marker
}
""",
        encoding="utf-8",
    )
    sample = tmp_path / "sample.bin"
    sample.write_text("benign test fixture with STAGEHAWK_TEST_GENERIC_HEURISTIC_MARKER", encoding="utf-8")
    output_json = tmp_path / "signature_scan.json"

    result = run_signature_scan(sample, output_json, _scanner_config(rule_dir))
    match = next(
        item
        for item in result["engines"]["yara"]["matches"]
        if item["rule"] == "StageHawk_Test_Generic_Heuristic"
    )

    assert match["collection"] == "generic"
    assert match["quality"] == "generic"
    assert match["confidence_meaning"] == "heuristic triage signal, not confirmed malware"
    assert result["signature_catalog"]["collections"]["generic"]["rule_files"] == [str(rule_file)]


def test_empty_yara_rule_directory_reports_honest_not_configured_status(tmp_path):
    rule_dir = tmp_path / "empty_rules"
    rule_dir.mkdir()
    sample = tmp_path / "sample.bin"
    sample.write_text("benign test fixture without local signature rules", encoding="utf-8")
    output_json = tmp_path / "signature_scan.json"

    result = run_signature_scan(sample, output_json, _scanner_config(rule_dir))

    assert result["verdict"] in {
        "no_signature_sources_configured",
        "no_signature_engines_available",
    }
    assert result["summary"]["total_match_count"] == 0
    assert result["engines"]["yara"]["matches"] == []
    assert result["engines"]["yara"]["status"] in {"not_configured", "unavailable"}
    if result["engines"]["yara"]["available"]:
        assert result["verdict"] == "no_signature_sources_configured"
        assert result["engines"]["yara"]["status"] == "not_configured"
    assert result["engines"]["clamav"]["status"] == "unavailable"
    assert "signature_catalog" in result
    assert result["signature_catalog"]["metadata_loaded"] is False
