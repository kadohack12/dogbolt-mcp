"""Offline tests for the pure helpers in dogbolt_mcp.

These do not touch the network: they cover path validation, name
normalization, result filtering and progress accounting, which are the parts
that encode the (verified) Dogbolt API semantics.
"""

import dogbolt_mcp as db
import httpx


def test_normalize_name_strips_punctuation():
    assert db.normalize_name("rev.ng") == "revng"
    assert db.normalize_name("Hex-Rays") == "hexrays"
    assert db.normalize_name("BinaryNinja") == "binaryninja"


def test_validate_binary_path_missing(tmp_path):
    assert "n'existe pas" in db.validate_binary_path(str(tmp_path / "nope"))


def test_validate_binary_path_empty(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert "vide" in db.validate_binary_path(str(empty))


def test_validate_binary_path_too_large(tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(b"\x00" * (db.MAX_UPLOAD_BYTES + 1))
    assert "2 Mo" in db.validate_binary_path(str(big))


def test_validate_binary_path_ok(tmp_path):
    good = tmp_path / "ok.bin"
    good.write_bytes(b"\x7fELF")
    assert db.validate_binary_path(str(good)) is None


def test_validate_binary_path_blank():
    assert db.validate_binary_path("") is not None


def _result(name, error=None, version="1.0"):
    return {
        "decompiler": {"name": name, "version": version},
        "error": error,
        "download_url": "https://example.invalid/code" if error is None else None,
        "analysis_time": 1.5,
    }


def test_select_results_filters_by_target():
    results = [_result("Ghidra"), _result("angr"), _result("Hex-Rays")]
    picked = db.select_results(results, "ghidra")
    assert [r["decompiler"]["name"] for r in picked] == ["Ghidra"]


def test_select_results_all_keeps_everything():
    results = [_result("Ghidra"), _result("angr")]
    assert len(db.select_results(results, "all")) == 2
    assert len(db.select_results(results, None)) == 2


def test_select_results_no_match():
    assert db.select_results([_result("Ghidra")], "binaryninja") == []


def test_select_results_matches_normalized_punctuation():
    results = [_result("rev.ng")]
    assert db.select_results(results, "revng") == results


def test_summarize_counts_states():
    outcome = db.FetchOutcome(
        results=[
            _result("Ghidra"),
            _result("angr"),
            _result("RetDec", error="crash"),
        ],
        count=5,
        seen=3,
    )
    summary = db.summarize(outcome, expected=13)
    assert summary == {
        "uploaded_count": 5,
        "finished": 2,
        "failed": 1,
        "pending": 2,
        "expected_total": 13,
    }


def test_server_exposes_expected_tools():
    for expected in (
        "list_available_decompilers",
        "get_decompilations_status",
        "decompile_binary",
    ):
        assert hasattr(db, expected)


def test_sha256_file_matches_hashlib(tmp_path):
    import hashlib

    payload = b"\x7fELF" + b"hello world" * 1000
    f = tmp_path / "bin"
    f.write_bytes(payload)
    assert db.sha256_file(f) == hashlib.sha256(payload).hexdigest()


def test_cache_roundtrip(tmp_path):
    cache_file = tmp_path / "cache.json"
    db.save_cache({"abc": "id-1"}, cache_file)
    assert db.load_cache(cache_file) == {"abc": "id-1"}


def test_load_cache_missing_file(tmp_path):
    assert db.load_cache(tmp_path / "absent.json") == {}


def test_load_cache_corrupt_file(tmp_path):
    bad = tmp_path / "cache.json"
    bad.write_text("{not valid json")
    assert db.load_cache(bad) == {}


def test_load_cache_non_dict(tmp_path):
    bad = tmp_path / "cache.json"
    bad.write_text("[1, 2, 3]")
    assert db.load_cache(bad) == {}


def test_retry_after_reads_header():
    request = httpx.Request("POST", "https://dogbolt.org/api/binaries/")
    response = httpx.Response(429, headers={"Retry-After": "6"}, request=request)
    assert db._retry_after(response, default=10) == 6.0


def test_retry_after_default_when_absent():
    request = httpx.Request("POST", "https://dogbolt.org/api/binaries/")
    response = httpx.Response(429, request=request)
    assert db._retry_after(response, default=10) == 10.0


def test_retry_after_default_when_garbage():
    request = httpx.Request("POST", "https://dogbolt.org/api/binaries/")
    response = httpx.Response(429, headers={"Retry-After": "soon"}, request=request)
    assert db._retry_after(response, default=7) == 7.0
