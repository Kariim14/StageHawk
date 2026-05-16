from orchestrator.core.hashing import sha256_file


def test_sha256_file(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")

    assert sha256_file(sample) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
