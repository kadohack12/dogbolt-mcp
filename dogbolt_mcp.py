"""MCP server exposing the public dogbolt.org decompiler service to LLMs.

Dogbolt runs a fixed set of decompilers (Ghidra, Hex-Rays/IDA, Binary Ninja,
angr, Snowman, RetDec, ...) over an uploaded binary and exposes the resulting
C code through a small public REST API.

Verified API contract (dogbolt.org, 2026-11):

* ``GET  /api/decompilers/``                       public, paginated
* ``POST /api/binaries/`` (multipart field ``file``) public, returns
  ``{"id", "download_url", "decompilations_url"}``
* ``GET  /api/binaries/<id>/decompilations/``      public, paginated:
  ``{"count", "next", "previous", "results": [...]}`` where each result is
  ``{"decompiler": {"name", "version", ...}, "error": null|str,
  "download_url": str, "analysis_time": float, "created": str}``
* ``GET  /api/binaries/<id>/``                     requires authentication (401)

There is no ``status`` field: a decompiler is finished once its result appears
in the list with ``error is null`` and a ``download_url``. The frontend polls
until it has seen one result per expected decompiler.

Privacy: uploaded binaries are stored publicly. Never send secrets or
proprietary binaries. Fair use: do not hammer the public service.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

# stdout is the JSON-RPC channel for the stdio transport; keep it clean and
# silence httpx's per-request INFO logging on stderr.
logging.getLogger("httpx").setLevel(logging.WARNING)

try:  # mcp >= 2 renamed FastMCP to MCPServer
    from mcp.server.mcpserver import MCPServer as _MCPServer
except ImportError:  # pragma: no cover - depends on installed SDK
    from mcp.server.fastmcp import FastMCP as _MCPServer


BASE_URL = os.environ.get("DOGBOLT_BASE_URL", "https://dogbolt.org").rstrip("/")
USER_AGENT = "Dogbolt-MCP-Client/1.0"
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 180
# Dogbolt runs a fixed fleet of decompilers; used to know when "all" is done.
EXPECTED_DECOMPILERS = 13
_PAGE_SIZE = 100
# Sources whose text is almost always useless to an LLM and would blow up the
# context window if returned verbatim.
_NOISY_DECOMPILERS = {"angr", "RetDec"}

# Dogbolt de-duplicates uploads by SHA256: re-sending the same bytes returns
# the same ``binary_id``. Uploads are also throttled (HTTP 429). A local cache
# keyed by content hash therefore avoids both a redundant upload and a 429.
CACHE_PATH = Path(
    os.environ.get(
        "DOGBOLT_CACHE",
        Path.home() / ".cache" / "dogbolt-mcp" / "cache.json",
    )
).expanduser()
CACHE_ENABLED = os.environ.get("DOGBOLT_CACHE_DISABLE", "") == ""

server = _MCPServer("dogbolt")


# --------------------------------------------------------------------------- #
# Pure helpers (no network, unit-tested)
# --------------------------------------------------------------------------- #
def sha256_file(path: Path) -> str:
    """Stream a file through SHA256 (the key Dogbolt stores binaries under)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_cache(path: Path = CACHE_PATH) -> Dict[str, str]:
    """Read the ``{sha256: binary_id}`` cache, tolerating a missing/corrupt file."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except (OSError, ValueError):
        pass
    return {}


def save_cache(cache: Dict[str, str], path: Path = CACHE_PATH) -> None:
    """Persist the cache atomically; failures are non-fatal."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(cache, handle)
        os.replace(tmp, path)
    except OSError:
        pass


def validate_binary_path(file_path: str) -> Optional[str]:
    """Return an error message, or ``None`` when the path is a valid binary."""
    if not file_path:
        return "Erreur : aucun chemin de fichier fourni."
    path = Path(file_path).expanduser()
    if not path.is_file():
        return f"Erreur : le fichier '{file_path}' n'existe pas."
    size = path.stat().st_size
    if size == 0:
        return f"Erreur : le fichier '{file_path}' est vide."
    if size > MAX_UPLOAD_BYTES:
        return (
            f"Erreur : Dogbolt refuse les fichiers de plus de 2 Mo "
            f"({size} octets)."
        )
    return None


def normalize_name(name: str) -> str:
    """Collapse a decompiler name for tolerant matching (``rev.ng`` -> ``revng``)."""
    return "".join(ch for ch in name.lower() if ch.isalnum())


def resolve_engines(target: Any) -> Optional[List[str]]:
    """Normalize an engine selector into a list of tokens.

    Accepts a single name, a comma-separated string, or a list. Returns
    ``None`` to mean "every decompiler" (selector empty, ``all``, or absent).
    """
    if target is None:
        return None
    if isinstance(target, str):
        parts = [p.strip() for p in target.split(",") if p.strip()]
    else:
        parts = [str(p).strip() for p in target if str(p).strip()]
    if not parts or any(normalize_name(p) == "all" for p in parts):
        return None
    return parts


def _best_by_name(results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Keep the highest-version result per decompiler name (the frontend rule)."""
    best: Dict[str, Dict[str, Any]] = {}
    for item in results:
        info = item.get("decompiler") or {}
        name = info.get("name")
        if not name:
            continue
        current = best.get(name)
        if current is None or str(info.get("version", "")) > str(
            (current.get("decompiler") or {}).get("version", "")
        ):
            best[name] = item
    return best


def match_engines(
    results: List[Dict[str, Any]], engines: List[str]
) -> List[Dict[str, Any]]:
    """Best result per engine whose name matches any requested token."""
    wanted = [normalize_name(e) for e in engines]
    return [
        item
        for name, item in _best_by_name(results).items()
        if any(token in normalize_name(name) for token in wanted)
    ]


def select_results(
    results: List[Dict[str, Any]], target: Any = None
) -> List[Dict[str, Any]]:
    """Keep results for ``target`` (a name, comma list, ``all`` or ``None``)."""
    engines = resolve_engines(target)
    if engines is None:
        return list(_best_by_name(results).values())
    return match_engines(results, engines)


def _safe_component(name: str) -> str:
    """Turn an engine name into a filesystem-safe lowercase token."""
    safe = "".join(
        ch if ch.isalnum() or ch in "-_." else "-" for ch in name.lower()
    )
    return safe.strip(".-") or "engine"


def summarize_code(code: str, preview_lines: int = 25) -> Dict[str, Any]:
    """Compact description of a C source: line count, size, head preview."""
    lines = code.splitlines()
    return {
        "lines": len(lines),
        "size_kb": round(len(code.encode("utf-8")) / 1024, 1),
        "preview": "\n".join(lines[:preview_lines]),
    }


def write_code_file(
    output_dir: str, binary_stem: str, engine_name: str, code: str
) -> Dict[str, Any]:
    """Write ``<stem>.<engine>.c`` into ``output_dir`` and return a summary."""
    directory = Path(output_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{binary_stem}.{_safe_component(engine_name)}.c"
    target.write_text(code, encoding="utf-8")
    info = summarize_code(code)
    info["path"] = str(target.resolve())
    return info


def format_duration(value: Any) -> str:
    """Render an ``analysis_time`` (seconds) as e.g. ``4.81s``."""
    try:
        return f"{float(value):.2f}s"
    except (TypeError, ValueError):
        return "-"


def build_comparison_table(rows: List[Dict[str, Any]]) -> str:
    """Render the per-engine summary as a Markdown table."""
    lines = [
        "| Moteur | Statut | Temps | Lignes | Fichier / Résumé |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            "| {engine} | {status} | {time} | {lines} | {detail} |".format(**row)
        )
    return "\n".join(lines)


@dataclass
class FetchOutcome:
    """Result of a single poll of the decompilations endpoint."""

    results: List[Dict[str, Any]] = field(default_factory=list)
    count: int = 0
    next_url: Optional[str] = None
    seen: int = 0

    @property
    def finished(self) -> int:
        return sum(1 for item in self.results if item.get("error") is None)


def summarize(outcome: FetchOutcome, expected: int) -> Dict[str, Any]:
    """Progress report: how many decompilers finished / failed / are pending."""
    failed = [item for item in outcome.results if item.get("error") is not None]
    return {
        "uploaded_count": outcome.count,
        "finished": outcome.finished,
        "failed": len(failed),
        "pending": max(outcome.count - outcome.seen, 0),
        "expected_total": expected,
    }


# --------------------------------------------------------------------------- #
# Network layer
# --------------------------------------------------------------------------- #
async def _get_json(
    client: httpx.AsyncClient, url: str
) -> Any:  # pragma: no cover - exercised against the live API
    response = await client.get(url)
    response.raise_for_status()
    return response.json()


async def fetch_all_results(
    client: httpx.AsyncClient, url: str
) -> FetchOutcome:  # pragma: no cover - exercised against the live API
    """Follow the pagination chain of a list endpoint and collect every item."""
    outcome = FetchOutcome()
    next_url: Optional[str] = url
    while next_url:
        data = await _get_json(client, next_url)
        if not isinstance(data, dict):
            break
        outcome.results.extend(data.get("results", []))
        outcome.count = data.get("count", len(outcome.results))
        next_url = data.get("next")
    outcome.seen = len(outcome.results)
    return outcome


async def _download_code(
    client: httpx.AsyncClient, url: str, max_chars: Optional[int]
) -> str:
    response = await client.get(url)
    if response.status_code != 200:
        return f"[échec du téléchargement du code : HTTP {response.status_code}]"
    text = response.text
    if max_chars is not None and len(text) > max_chars:
        return text[:max_chars] + f"\n\n[... tronqué à {max_chars} caractères]"
    return text


async def _upload_binary(
    client: httpx.AsyncClient, path: Path, max_retries: int = 3
) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Upload ``path`` and return ``(payload, error)``.

    Retries on HTTP 429 using the server's ``Retry-After`` hint, honouring the
    public service's fair-use policy.
    """
    for attempt in range(max_retries + 1):
        with open(path, "rb") as handle:
            response = await client.post(
                f"{BASE_URL}/api/binaries/",
                files={"file": (path.name, handle, "application/octet-stream")},
            )
        if response.status_code == 413:
            return None, "Erreur : Dogbolt refuse les binaires de plus de 2 Mo."
        if response.status_code == 429:
            if attempt == max_retries:
                detail = _detail(response) or "trop de requêtes"
                return None, f"Erreur : Dogbolt limite le débit ({detail})."
            delay = _retry_after(response, default=10)
            await asyncio.sleep(delay)
            continue
        response.raise_for_status()
        return response.json(), None
    return None, "Erreur : échec de l'upload après plusieurs tentatives."


def _detail(response: httpx.Response) -> Optional[str]:
    try:
        return response.json().get("detail")
    except ValueError:
        return None


def _retry_after(response: httpx.Response, default: int) -> float:
    raw = response.headers.get("Retry-After")
    try:
        return max(float(raw), 0.0)
    except (TypeError, ValueError):
        return float(default)


async def _ensure_binary(
    client: httpx.AsyncClient, path: Path, digest: str
) -> tuple[Optional[str], bool, Optional[str]]:
    """Return ``(binary_id, uploaded, error)``, reusing the SHA256 cache."""
    cache = load_cache() if CACHE_ENABLED else {}
    cached = cache.get(digest)
    if cached:
        return cached, False, None
    data, upload_error = await _upload_binary(client, path)
    if upload_error:
        return None, False, upload_error
    binary_id = data.get("id")
    if not binary_id:
        return None, False, "Erreur : aucun identifiant retourné par Dogbolt."
    if CACHE_ENABLED:
        cache[digest] = binary_id
        save_cache(cache)
    return binary_id, True, None


async def _poll_until(
    client: httpx.AsyncClient,
    results_url: str,
    target: Any,
    expected: int,
    timeout_seconds: int,
    poll_interval: int = 5,
) -> tuple[List[Dict[str, Any]], Dict[str, Any], int]:
    """Poll until ``expected`` matching results are ready (or the timeout)."""
    elapsed = 0
    selected: List[Dict[str, Any]] = []
    progress: Dict[str, Any] = {}
    while elapsed < timeout_seconds:
        await asyncio.sleep(poll_interval)
        elapsed += poll_interval
        outcome = await fetch_all_results(client, results_url)
        progress = summarize(outcome, expected)
        selected = select_results(outcome.results, target)
        if len(selected) >= expected:
            break
    return selected, progress, elapsed


async def _analyse(
    file_path: str,
    selector: Any,
    expected: int,
    timeout_seconds: int,
    output_dir: Optional[str] = None,
    include_code: bool = True,
    max_chars: int = 20000,
) -> Dict[str, Any]:
    """Upload (or reuse) a binary, wait for the engines, and collect their code.

    When ``output_dir`` is set, each C source is written to disk and the entry
    carries a compact summary instead of the full text.
    """
    error = validate_binary_path(file_path)
    if error:
        return {"error": error}

    path = Path(file_path).expanduser().resolve()
    digest = sha256_file(path)

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT}, timeout=60.0
    ) as client:
        binary_id, uploaded, upload_error = await _ensure_binary(
            client, path, digest
        )
        if upload_error:
            return {"error": upload_error}

        results_url = f"{BASE_URL}/api/binaries/{binary_id}/decompilations/"
        selected, progress, elapsed = await _poll_until(
            client, results_url, selector, expected, timeout_seconds
        )

        payload: Dict[str, Any] = {
            "binary_id": binary_id,
            "link": f"{BASE_URL}/?id={binary_id}",
            "sha256": digest,
            "from_cache": not uploaded,
            "elapsed_seconds": elapsed,
            "progress": progress,
        }

        entries: List[Dict[str, Any]] = []
        for item in selected:
            info = item.get("decompiler") or {}
            name = info.get("name", "inconnu")
            entry: Dict[str, Any] = {
                "decompiler": name,
                "version": info.get("version"),
                "analysis_time": item.get("analysis_time"),
            }
            if item.get("error") is not None:
                entry["error"] = item["error"]
            elif item.get("download_url"):
                wants_full = output_dir is not None
                if wants_full:
                    code = await _download_code(client, item["download_url"], None)
                    summary = write_code_file(output_dir, path.stem, name, code)
                    entry["file"] = summary["path"]
                    entry["lines"] = summary["lines"]
                    entry["size_kb"] = summary["size_kb"]
                    entry["preview"] = summary["preview"]
                elif include_code:
                    if normalize_name(name) in _NOISY_DECOMPILERS:
                        entry["note"] = (
                            "Sortie volumineuse et peu fiable ; extrait tronqué."
                        )
                    entry["code"] = await _download_code(
                        client, item["download_url"], max_chars
                    )
            entries.append(entry)

        payload["decompilations"] = entries
        return payload


def _comparison_rows(decompilations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Turn per-engine entries into rows for the Markdown comparison table."""
    rows = []
    for entry in decompilations:
        if entry.get("error"):
            status, detail = "Échec", entry["error"][:60]
            lines = "-"
        elif "file" in entry:
            status, detail = "Succès", f"`{Path(entry['file']).name}`"
            lines = entry.get("lines", "-")
        elif "code" in entry:
            status = "Succès"
            lines = len(entry["code"].splitlines())
            detail = "inline"
        else:
            status, detail, lines = "Succès", "-", "-"
        rows.append(
            {
                "engine": entry.get("decompiler", "?"),
                "status": status,
                "time": format_duration(entry.get("analysis_time")),
                "lines": lines,
                "detail": detail,
            }
        )
    return rows


# --------------------------------------------------------------------------- #
# MCP tools
# --------------------------------------------------------------------------- #
@server.tool()
async def list_available_decompilers(limit: int = 50) -> Dict[str, Any]:
    """List the decompilers available on Dogbolt.

    The API returns one entry per (decompiler, version) pair, so the list is
    long. The response is de-duplicated by name, keeping the highest version.

    :param limit: Maximum number of distinct decompilers to return.
    """
    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT}, timeout=15.0
    ) as client:
        outcome = await fetch_all_results(
            client, f"{BASE_URL}/api/decompilers/"
        )

    best: Dict[str, Dict[str, Any]] = {}
    for entry in outcome.results:
        name = entry.get("name", "inconnu")
        current = best.get(name)
        if current is None or str(entry.get("version", "")) > str(
            current.get("version", "")
        ):
            best[name] = entry

    decompilers = sorted(best.values(), key=lambda e: e.get("name", ""))
    return {
        "count": len(decompilers),
        "decompilers": decompilers[:limit],
    }


@server.tool()
async def get_decompilations_status(
    binary_id: str, expected_total: int = EXPECTED_DECOMPILERS
) -> Dict[str, Any]:
    """Report decompilation progress for a binary already uploaded to Dogbolt.

    :param binary_id: The ``id`` returned when the binary was uploaded.
    :param expected_total: Number of decompilers expected (Dogbolt runs 13).
    """
    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT}, timeout=20.0
    ) as client:
        outcome = await fetch_all_results(
            client, f"{BASE_URL}/api/binaries/{binary_id}/decompilations/"
        )

    return {
        "binary_id": binary_id,
        "link": f"{BASE_URL}/?id={binary_id}",
        "progress": summarize(outcome, expected_total),
        "results": [
            {
                "decompiler": (item.get("decompiler") or {}).get("name"),
                "version": (item.get("decompiler") or {}).get("version"),
                "error": item.get("error"),
                "analysis_time": item.get("analysis_time"),
            }
            for item in outcome.results
        ],
    }


@server.tool()
async def decompile_binary(
    file_path: str,
    target_decompiler: str = "Ghidra",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    include_code: bool = True,
    max_chars_per_decompiler: int = 20000,
    output_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Upload a local binary (<2MB) to Dogbolt and return the decompiled C code.

    The binary is stored publicly on dogbolt.org. Do not submit secrets or
    proprietary/confidential binaries.

    Dogbolt de-duplicates by SHA256, so an identical file reuses the previous
    analysis instead of being uploaded again; a local cache makes that reuse
    instant across runs.

    :param file_path: Absolute path to the local binary.
    :param target_decompiler: A decompiler (``Ghidra``, ``Hex-Rays``,
        ``BinaryNinja``, ``angr``), a comma-separated list, or ``all``.
    :param timeout_seconds: Maximum time to wait for results.
    :param include_code: When False, only report status (avoids flooding the
        context with large C sources).
    :param max_chars_per_decompiler: Truncate each C source to this many
        characters (ignored when ``output_dir`` is set).
    :param output_dir: When set, write each source to
        ``<binary>.<engine>.c`` in this directory and return only a compact
        summary (path, line count, size, head preview) instead of the code.
    """
    target = resolve_engines(target_decompiler)
    expected = EXPECTED_DECOMPILERS if target is None else len(target)

    payload = await _analyse(
        file_path,
        target,
        expected,
        timeout_seconds,
        output_dir=output_dir,
        include_code=include_code,
        max_chars=max_chars_per_decompiler,
    )
    if "error" in payload:
        return payload

    payload["target_decompiler"] = target_decompiler
    if not payload["decompilations"]:
        payload["status"] = "timeout"
        payload["message"] = (
            "Aucun résultat pour le décompilateur demandé dans le délai. "
            f"Consultez {BASE_URL}/?id={payload['binary_id']} plus tard."
        )
    else:
        payload["status"] = (
            "ok" if len(payload["decompilations"]) >= expected else "partial"
        )
    return payload


@server.tool()
async def compare_decompilers(
    file_path: str,
    engines: Any = ("Ghidra", "Hex-Rays", "BinaryNinja"),
    output_dir: Optional[str] = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_chars_per_decompiler: int = 8000,
) -> Dict[str, Any]:
    """Decompile one binary with several engines and compare their output.

    A single upload is shared across engines (same SHA256 cache). Returns a
    Markdown comparison table plus per-engine details.

    :param file_path: Absolute path to the local binary.
    :param engines: Engines to compare, as a list or comma-separated string
        (e.g. ``["Ghidra", "Hex-Rays", "BinaryNinja"]``).
    :param output_dir: When set, write each source to ``<binary>.<engine>.c``
        and return only a compact summary per engine.
    :param timeout_seconds: Maximum time to wait for the selected engines.
    :param max_chars_per_decompiler: Truncation when returning code inline.
    """
    engine_list = resolve_engines(engines) or ["Ghidra", "Hex-Rays", "BinaryNinja"]
    payload = await _analyse(
        file_path,
        engine_list,
        len(engine_list),
        timeout_seconds,
        output_dir=output_dir,
        include_code=output_dir is None,
        max_chars=max_chars_per_decompiler,
    )
    if "error" in payload:
        return payload

    payload["engines"] = engine_list
    payload["status"] = (
        "ok" if len(payload["decompilations"]) >= len(engine_list) else "partial"
    )
    payload["comparison"] = build_comparison_table(
        _comparison_rows(payload["decompilations"])
    )
    return payload


if __name__ == "__main__":
    server.run()
