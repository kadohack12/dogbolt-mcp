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

server = _MCPServer("dogbolt")


# --------------------------------------------------------------------------- #
# Pure helpers (no network, unit-tested)
# --------------------------------------------------------------------------- #
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


def select_results(
    results: List[Dict[str, Any]], target: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Keep only finished results, optionally filtered by ``target``.

    ``target`` matches the decompiler name case-insensitively as a substring
    after normalization; ``all``/``None`` keep every finished result.
    """
    wanted = normalize_name(target or "")
    selected: List[Dict[str, Any]] = []
    for item in results:
        decompiler = item.get("decompiler") or {}
        name = decompiler.get("name", "inconnu")
        if wanted and wanted != "all" and wanted not in normalize_name(name):
            continue
        selected.append(item)
    return selected


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
    client: httpx.AsyncClient, url: str, max_chars: int
) -> str:
    response = await client.get(url)
    if response.status_code != 200:
        return f"[échec du téléchargement du code : HTTP {response.status_code}]"
    text = response.text
    if len(text) > max_chars:
        return text[:max_chars] + f"\n\n[... tronqué à {max_chars} caractères]"
    return text


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
) -> Dict[str, Any]:
    """Upload a local binary (<2MB) to Dogbolt and return the decompiled C code.

    The binary is stored publicly on dogbolt.org. Do not submit secrets or
    proprietary/confidential binaries.

    :param file_path: Absolute path to the local binary.
    :param target_decompiler: Decompiler to wait for (e.g. ``Ghidra``,
        ``Hex-Rays``, ``BinaryNinja``, ``angr``), or ``all`` to wait for every
        decompiler.
    :param timeout_seconds: Maximum time to wait for results.
    :param include_code: When False, only report status (useful to avoid
        flooding the context with large C sources).
    :param max_chars_per_decompiler: Truncate each C source to this many
        characters.
    """
    error = validate_binary_path(file_path)
    if error:
        return {"error": error}

    path = Path(file_path).expanduser().resolve()
    target = (target_decompiler or "all").strip()
    wait_for_all = normalize_name(target) == "all"
    expected = EXPECTED_DECOMPILERS if wait_for_all else 1

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT}, timeout=60.0
    ) as client:
        with open(path, "rb") as handle:
            upload = await client.post(
                f"{BASE_URL}/api/binaries/",
                files={"file": (path.name, handle, "application/octet-stream")},
            )
        if upload.status_code == 413:
            return {"error": "Erreur : Dogbolt refuse les binaires de plus de 2 Mo."}
        if upload.status_code == 429:
            detail = upload.json().get("detail", "trop de requêtes")
            return {"error": f"Erreur : Dogbolt limite le débit ({detail})."}
        upload.raise_for_status()
        data = upload.json()

        binary_id = data.get("id")
        if not binary_id:
            return {"error": "Erreur : aucun identifiant retourné par Dogbolt."}

        results_url = data.get(
            "decompilations_url",
            f"{BASE_URL}/api/binaries/{binary_id}/decompilations/",
        )

        elapsed = 0
        poll_interval = 5
        selected: List[Dict[str, Any]] = []
        last_progress: Dict[str, Any] = {}

        while elapsed < timeout_seconds:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

            outcome = await fetch_all_results(client, results_url)
            last_progress = summarize(outcome, expected)
            selected = select_results(outcome.results, target)
            if len(selected) >= expected:
                break

        payload: Dict[str, Any] = {
            "binary_id": binary_id,
            "link": f"{BASE_URL}/?id={binary_id}",
            "target_decompiler": target,
            "elapsed_seconds": elapsed,
            "progress": last_progress,
        }

        if not selected:
            payload["status"] = "timeout"
            payload["message"] = (
                "Aucun résultat pour le décompilateur demandé dans le délai. "
                f"Consultez {BASE_URL}/?id={binary_id} plus tard."
            )
            return payload

        decompilations = []
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
            elif include_code and item.get("download_url"):
                if normalize_name(name) in _NOISY_DECOMPILERS:
                    entry["note"] = (
                        "Sortie volumineuse et peu fiable ; extrait tronqué."
                    )
                entry["code"] = await _download_code(
                    client, item["download_url"], max_chars_per_decompiler
                )
            decompilations.append(entry)

        payload["status"] = "ok" if len(selected) >= expected else "partial"
        payload["decompilations"] = decompilations
        return payload


if __name__ == "__main__":
    server.run()
