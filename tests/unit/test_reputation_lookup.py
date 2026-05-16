from orchestrator.analysis.reputation_lookup import classify_hash, lookup_hash_reputation


def test_classify_hash_types():
    assert classify_hash("a" * 32) == "md5"
    assert classify_hash("b" * 40) == "sha1"
    assert classify_hash("c" * 64) == "sha256"
    assert classify_hash("not-a-hash") is None


def test_lookup_hash_without_api_keys_is_unavailable(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("MALWAREBAZAAR_API_KEY", raising=False)

    result = lookup_hash_reputation(
        "a" * 64,
        {
            "virustotal": {"api_key": None},
            "malwarebazaar": {"api_key": None},
        },
    )

    assert result["status"] == "completed"
    assert result["hash_type"] == "sha256"
    assert result["verdict"] == "reputation_providers_unavailable"
    assert result["providers"]["virustotal"]["status"] == "unavailable"
    assert result["providers"]["malwarebazaar"]["status"] == "unavailable"


def test_lookup_hash_rejects_invalid_input():
    result = lookup_hash_reputation("hello")
    assert result["status"] == "invalid"
    assert result["verdict"] == "invalid_input"
