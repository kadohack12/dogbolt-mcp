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


# --------------------------------------------------------------------------- #
# Engine selection
# --------------------------------------------------------------------------- #
def test_resolve_engines_single_name():
    assert db.resolve_engines("Ghidra") == ["Ghidra"]


def test_resolve_engines_comma_string():
    assert db.resolve_engines("ghidra, hex-rays , binaryninja") == [
        "ghidra",
        "hex-rays",
        "binaryninja",
    ]


def test_resolve_engines_list():
    assert db.resolve_engines(["Ghidra", "angr"]) == ["Ghidra", "angr"]


def test_resolve_engines_all_means_everything():
    assert db.resolve_engines("all") is None
    assert db.resolve_engines(["all"]) is None


def test_resolve_engines_empty_and_none():
    assert db.resolve_engines(None) is None
    assert db.resolve_engines("") is None
    assert db.resolve_engines("  ") is None
    assert db.resolve_engines([]) is None


def test_best_by_name_keeps_highest_version():
    results = [
        _result("Ghidra", version="10.0"),
        _result("Ghidra", version="12.1"),
        _result("angr", version="9.0"),
    ]
    best = db._best_by_name(results)
    assert best["Ghidra"]["decompiler"]["version"] == "12.1"
    assert set(best) == {"Ghidra", "angr"}


def test_match_engines_multi_and_normalized():
    results = [_result("Ghidra"), _result("rev.ng"), _result("Snowman")]
    picked = db.match_engines(results, ["ghidra", "revng"])
    assert {r["decompiler"]["name"] for r in picked} == {"Ghidra", "rev.ng"}


def test_select_results_with_list_selector():
    results = [_result("Ghidra"), _result("angr"), _result("Hex-Rays")]
    picked = db.select_results(results, ["ghidra", "hex-rays"])
    assert {r["decompiler"]["name"] for r in picked} == {"Ghidra", "Hex-Rays"}


def test_select_results_dedups_versions():
    results = [
        _result("Ghidra", version="10.0"),
        _result("Ghidra", version="12.1"),
    ]
    picked = db.select_results(results, "ghidra")
    assert len(picked) == 1
    assert picked[0]["decompiler"]["version"] == "12.1"


# --------------------------------------------------------------------------- #
# output_dir helpers
# --------------------------------------------------------------------------- #
def test_safe_component():
    assert db._safe_component("Hex-Rays") == "hex-rays"
    assert db._safe_component("rev.ng") == "rev.ng"
    assert db._safe_component("a/b c") == "a-b-c"


def test_summarize_code_counts():
    code = "\n".join(f"line {i}" for i in range(50))
    summary = db.summarize_code(code, preview_lines=10)
    assert summary["lines"] == 50
    assert summary["size_kb"] > 0
    assert summary["preview"].count("\n") == 9
    assert summary["preview"].startswith("line 0")


def test_write_code_file_creates_dir_and_file(tmp_path):
    out = tmp_path / "nested" / "decompiled"
    code = "int main() {\n  return 0;\n}\n"
    summary = db.write_code_file(str(out), "crackme", "Hex-Rays", code)
    written = out / "crackme.hex-rays.c"
    assert written.is_file()
    assert written.read_text() == code
    assert summary["path"] == str(written.resolve())
    assert summary["lines"] == 3


def test_write_code_file_overwrites(tmp_path):
    db.write_code_file(str(tmp_path), "b", "Ghidra", "old")
    summary = db.write_code_file(str(tmp_path), "b", "Ghidra", "new")
    assert (tmp_path / "b.ghidra.c").read_text() == "new"
    assert summary["lines"] == 1


def test_format_duration():
    assert db.format_duration(4.81234) == "4.81s"
    assert db.format_duration(None) == "-"
    assert db.format_duration("n/a") == "-"


def test_build_comparison_table_has_header_and_rows():
    rows = [
        {
            "engine": "Hex-Rays",
            "status": "Succès",
            "time": "1.20s",
            "lines": 142,
            "detail": "`tiny.hex-rays.c`",
        },
        {
            "engine": "Ghidra",
            "status": "Échec",
            "time": "-",
            "lines": "-",
            "detail": "boom",
        },
    ]
    table = db.build_comparison_table(rows)
    assert table.splitlines()[0].startswith("| Moteur |")
    assert "| Hex-Rays | Succès | 1.20s | 142 |" in table
    assert "| Ghidra | Échec |" in table


def test_comparison_rows_from_entries(tmp_path):
    decompilations = [
        {"decompiler": "Ghidra", "analysis_time": 4.8, "file": "/x/b.ghidra.c", "lines": 210},
        {"decompiler": "Hex-Rays", "analysis_time": 1.2, "code": "int main(){}\n"},
        {"decompiler": "RetDec", "analysis_time": None, "error": "crash"},
    ]
    rows = db._comparison_rows(decompilations)
    by_engine = {r["engine"]: r for r in rows}
    assert by_engine["Ghidra"]["detail"] == "`b.ghidra.c`"
    assert by_engine["Ghidra"]["lines"] == 210
    assert by_engine["Hex-Rays"]["lines"] == 1
    assert by_engine["Hex-Rays"]["detail"] == "inline"
    assert by_engine["RetDec"]["status"] == "Échec"


def test_server_exposes_compare_tool():
    assert hasattr(db, "compare_decompilers")
