# Dogbolt MCP server

An [MCP](https://modelcontextprotocol.io) server that lets an LLM (Claude
Desktop, Cursor, ...) send a binary to [dogbolt.org](https://dogbolt.org) and
read back the C code produced by its fleet of decompilers (Ghidra,
Hex-Rays/IDA, Binary Ninja, angr, Snowman, RetDec, Reko, ...).

Dogbolt is asynchronous: you upload a binary, it returns an id, and a set of
workers decompile it in the background. This server hides the polling loop and
returns the finished results.

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
| `get_decompilations_status` | Progress/state of an already-uploaded binary |

`decompile_binary(file_path, target_decompiler="Ghidra", timeout_seconds=180,
include_code=True, max_chars_per_decompiler=20000)`:

* `target_decompiler` — a name (`Ghidra`, `Hex-Rays`, `BinaryNinja`, `angr`,
  `rev.ng`, ...) or `all` to wait for every decompiler.
* `include_code=False` — return only status, to avoid flooding the context.
* Sources are truncated to `max_chars_per_decompiler` characters.

Every call returns a dict containing `binary_id` and a `link`
(`https://dogbolt.org/?id=<id>`) so results stay reachable later.

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
`https://dogbolt.org`).

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
