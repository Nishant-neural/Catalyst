"""Phase 3 (part): Cache dependency analysis by package+version+hash.

Key = package@version-sha256(source). Stored as JSON in .reachcache/.
First project pays the parse cost, every later project reuses it.
Never cache project code, only dependencies. Invalidate on hash change.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


PARSER_VERSION = "pyreach-ast-0.1.0"


def cache_key(package: str, version: str, source_hash: str,
              artifact_hash: str = "", parser_version: str = PARSER_VERSION) -> str:
    """ChatGPT fix: include artifact hash + parser version in the key.

    A source archive and an installed wheel are not guaranteed to
    contain the same files, and a parser change invalidates old entries.
    Prefer the installed distribution artifact where possible.
    """
    return f"{package}@{version}-{source_hash[:12]}-{artifact_hash[:12]}-{parser_version}"


def source_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


class Cache:
    def __init__(self, directory: str | Path = ".reachcache"):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.hits = 0
        self.misses = 0

    def _path(self, key: str) -> Path:
        # Windows fix (19 Nov 2026, found from Nishant's mkdocs-llm-2.json):
        # the LLM cache key is "llm:<model>:<sha16>", and the model slug
        # contains ":" (cohere/north-mini-code:free). ":" is illegal in a
        # Windows filename, so every LLM cache get/put on his machine
        # raised OSError Errno 22 — and the resolver's generic except
        # then mislabelled that local error as "network_error", so the
        # LLM looked dead-network when it had never even been reached.
        # Only "/" and "@" were sanitised before; now every character
        # Windows forbids in a filename (<>:"/\|?* and controls) becomes
        # "_", and a trailing dot/space (also illegal there) is stripped.
        # Linux filenames allowed ":" all along, which is why the VM's
        # tests never caught this. get/put are also best-effort now: a
        # cache is not storage, so a failed read is a miss and a failed
        # write is skipped, never an exception into the caller.
        safe = "".join("_" if (c in '<>:"/\\|?*' or ord(c) < 32) else c
                       for c in key)
        safe = safe.replace("@", "_at_").rstrip(". ")
        return self.dir / f"{safe}.json"

    def get(self, key: str):
        p = self._path(key)
        try:
            if p.exists():
                self.hits += 1
                return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass  # unreadable cache entry == a miss, not a crash
        self.misses += 1
        return None

    def put(self, key: str, data: dict) -> None:
        try:
            self._path(key).write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError:
            pass  # best-effort cache: a failed write never fails a scan
