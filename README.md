# Dogbolt MCP server

[![CI](https://github.com/kadohack12/dogbolt-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/kadohack12/dogbolt-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-compatible-6E4AFF.svg)](https://modelcontextprotocol.io)
[![Tests](https://img.shields.io/badge/tests-37%20passed-brightgreen.svg)](tests/test_dogbolt_mcp.py)
[![Dogbolt](https://img.shields.io/badge/dogbolt.org-public%20API-orange.svg)](https://dogbolt.org)

An [MCP](https://modelcontextprotocol.io) server that lets an LLM (Claude
Desktop, Cursor, ...) send a binary to [dogbolt.org](https://dogbolt.org) and
read back the C code produced by its fleet of decompilers (Ghidra,
Hex-Rays/IDA, Binary Ninja, angr, Snowman, RetDec, Reko, ...).

Dogbolt is asynchronous: you upload a binary, it returns an id, and a set of
workers decompile it in the background. This server hides the polling loop and
returns the finished results.

> Reverse engineering · Decompiler · Binary analysis · Model Context Protocol

**Tags:** `mcp` · `model-context-protocol` · `mcp-server` · `dogbolt` ·
`decompiler` · `reverse-engineering` · `reverse-engineering-tools` ·
`binary-analysis` · `ghidra` · `hex-rays` · `ida-pro` · `binary-ninja` · `angr` ·
`retdec` · `snowman` · `security-tools` · `malware-analysis` · `python` ·
`claude-desktop` · `cursor` · `llm` · `ai-tools` · `llm-tools`

## ⚠️ Privacy and fair use

* Dogbolt stores **every uploaded binary publicly**. Never submit secrets,
  private keys, or proprietary/confidential binaries.
* The service is public and free: do not loop requests or hammer it.
* Maximum file size: **2 MB** (enforced both here and by Dogbolt).

## Install

```bash
pip install "mcp[cli]" httpx      # runtime
pip install -e ".[dev]"           # for tests
```

Works with `mcp` 1.x (`FastMCP`) and 2.x (`MCPServer`); the import is chosen
automatically.

## Tools

| Tool | Purpose |
| --- | --- |
| `list_available_decompilers` | Distinct decompilers and their versions |
| `decompile_binary` | Upload a binary and wait for the decompiled C |
| `compare_decompilers` | Decompile with several engines and compare them |
| `get_decompilations_status` | Progress/state of an already-uploaded binary |

### `decompile_binary`

`decompile_binary(file_path, target_decompiler="Ghidra", timeout_seconds=180,
include_code=True, max_chars_per_decompiler=20000, output_dir=None)`:

* `target_decompiler` — a name (`Ghidra`, `Hex-Rays`, `BinaryNinja`, `angr`,
  `rev.ng`, ...), a comma-separated list, or `all` for every decompiler.
* `include_code=False` — return only status, to avoid flooding the context.
* Sources are truncated to `max_chars_per_decompiler` characters.
* `output_dir` — when set, write each source to `<binary>.<engine>.c` in that
  directory (created if needed) and return only a compact summary per engine
  (path, line count, size, head preview) instead of the code. Ideal for large
  outputs.

### `compare_decompilers`

`compare_decompilers(file_path, engines=["Ghidra", "Hex-Rays", "BinaryNinja"],
output_dir=None, timeout_seconds=180, max_chars_per_decompiler=8000)`:

* One upload is shared across engines (same SHA256 cache).
* Returns a Markdown comparison table plus per-engine details:

  ```
  | Moteur       | Statut | Temps  | Lignes | Fichier / Résumé   |
  | ---          | ---    | ---    | ---    | ---                |
  | Hex-Rays     | Succès | 3.32s  | 137    | `tiny.hex-rays.c`  |
  | BinaryNinja  | Succès | 10.49s | 86     | `tiny.binaryninja.c` |
  | Ghidra       | Succès | 46.71s | 135    | `tiny.ghidra.c`    |
  ```

* `engines` accepts a list or a comma-separated string.
* With `output_dir`, files are written and only summaries are returned;
  otherwise the code is returned inline (truncated).

Every call returns a dict containing `binary_id`, `sha256`, `from_cache` and a
`link` (`https://dogbolt.org/?id=<id>`) so results stay reachable later.

## SHA256 cache and rate limiting

Dogbolt stores binaries under their SHA256 and **de-duplicates uploads**: the
same bytes return the same `binary_id` without re-analysing. Uploads are also
throttled (`429` with a `Retry-After` header).

This server exploits both:

* it hashes the file locally and keeps a `{sha256: binary_id}` cache, so a
  repeated file skips the upload entirely (`from_cache: true` in the result);
* on `429` it waits for `Retry-After` and retries (up to 3 times), instead of
  hammering the public service.

Cache location: `~/.cache/dogbolt-mcp/cache.json`. Override with
`DOGBOLT_CACHE`, or disable with `DOGBOLT_CACHE_DISABLE=1`.

Note: a cached `binary_id` is still re-polled, because Dogbolt may have run
additional decompilers since the first analysis.


## Corrected API contract

The endpoints and fields below were verified against the live service
(2026-11). A naive client gets several of these wrong:

* `GET  /api/decompilers/` — public, **paginated** (`{count, next, previous,
  results}`); returns one row per *version*, so de-duplicate by name.
* `POST /api/binaries/` — public, multipart field `file`. Returns
  `{"id", "download_url", "decompilations_url"}`. Use `decompilations_url`
  directly instead of rebuilding the URL.
* `GET  /api/binaries/<id>/decompilations/` — public, **paginated**. Each item:
  `{"decompiler": {"name", "version", ...}, "error": null|str,
  "download_url": str, "analysis_time": float, "created": str}`.
* `GET  /api/binaries/<id>/` — **requires authentication** (401), so it is not
  used.

Two traps:

1. **There is no `status` field.** A decompiler is finished once its result
   appears in the list with `error is null`; a failure has a non-null `error`.
   Do not wait for a `"completed"` string.
2. **The code URL is `download_url`, not `decompiled_file`.**

Dogbolt runs 13 decompilers today; `expected_total` (default 13) controls when
`target_decompiler="all"` stops waiting.

Two more behaviours worth knowing:

* Uploads are **content-addressed by SHA256**: re-sending identical bytes
  returns the same `binary_id` (the S3 key in `download_url` equals the file's
  SHA256), so the same file is never analysed twice.
* `POST /api/binaries/` is **throttled**: over the limit it answers `429` with
  `{"detail": "Request was throttled. Expected available in N seconds."}` and a
  `Retry-After` header. Respect it.


## Configuration

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS),
`%APPDATA%\Claude\claude_desktop_config.json` (Windows) or
`~/.config/Claude/claude_desktop_config.json` (Linux):

```json
{
  "mcpServers": {
    "dogbolt": {
      "command": "python",
      "args": ["/chemin/absolu/vers/dogbolt_mcp.py"]
    }
  }
}
```

Set `DOGBOLT_BASE_URL` to point at a self-hosted instance (default
`https://dogbolt.org`). `DOGBOLT_CACHE` overrides the cache path and
`DOGBOLT_CACHE_DISABLE=1` disables it.

### Inspector

```bash
npx @modelcontextprotocol/inspector python dogbolt_mcp.py
```

## Tests

```bash
python3 -m pytest -q
```

The suite is offline: it covers path validation, name normalization, result
filtering and progress accounting. Network calls were validated manually
against the live API.

## Usage example

> "Décompile /tmp/crackme.bin avec Ghidra et Binary Ninja via Dogbolt, puis
> explique ce que fait `main`."

The assistant calls `decompile_binary` and analyses the returned C.

> "Compare la décompilation de /tmp/crackme.bin avec Ghidra, Hex-Rays et
> Binary Ninja, et écris les résultats dans /tmp/out."

The assistant calls `compare_decompilers` with `output_dir`, gets a comparison
table plus the written file paths, and can then open the files it needs.

## License

[MIT](LICENSE) — free to use, modify and redistribute.

## Contributing

Issues and pull requests are welcome. Run the test suite before opening a PR:

```bash
pip install "mcp[cli]" httpx pytest
python -m pytest -q
```

## Star history

[![Star History Chart](https://api.star-history.com/svg?repos=kadohack12/dogbolt-mcp&type=Date)](https://star-history.com/#kadohack12/dogbolt-mcp&Date)

