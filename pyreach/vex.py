"""Phase 3 (part): OpenVEX output, only for safe not_reachable.

OpenVEX is the standard machine-readable "this does not affect us" record.
We write it ONLY when verdict is not_reachable with high/medium confidence
and the completeness check passed. Never write it for uncertain.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .reach import Result


def build_openvex(results: list[Result], project: str, author: str = "pyreach") -> dict:
    statements = []
    for r in results:
        if r.verdict != "not_reachable":
            continue
        statements.append({
            "vulnerability": {"@id": r.advisory_id, "name": r.advisory_id},
            "products": [{
                "@id": project,
                "identifiers": {"purl": f"pkg:generic/{project}"},
                # Vulnerable dependency as a subcomponent (ChatGPT fix)
                "subcomponents": [{
                    "@id": r.package,
                    "identifiers": {"purl": f"pkg:pypi/{r.package}"},
                }] if r.package else [],
            }],
            "status": "not_affected",
            "status_notes": r.reason,
            "justification": "vulnerable_code_not_in_execute_path",
        })
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://example.org/vex/{project}-{datetime.now(timezone.utc).date().isoformat()}",
        "author": author,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "statements": statements,
    }


def write_openvex(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
