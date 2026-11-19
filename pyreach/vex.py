"""Phase 3 (part): OpenVEX output, only for safe not_reachable.

OpenVEX is the standard machine-readable "this does not affect us" record.
We write it ONLY when verdict is not_reachable with high/medium confidence
and the completeness check passed. Never write it for uncertain.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .reach import Result


def build_openvex(results: list[Result], project: str,
                  graph_clean: bool | dict[str, bool] = True,
                  author: str = "pyreach") -> dict:
    """OpenVEX output, aggregated at the advisory level (ChatGPT Critical
    2, 19 Nov 2026): a not_affected statement is about a vulnerability +
    product, not about one candidate function. It is emitted for an
    advisory ONLY when EVERY candidate for that advisory is not_reachable
    with high/medium confidence AND the graph is clean for that advisory.
    graph_clean may be a single bool (the old whole-run ledger) or a
    per-advisory dict (Phase 13): the per-advisory gate is the precise
    one — fully parsed, no unresolved imports or entry points, no
    dynamic site still unresolved after Phase 4, and no ambiguous edge
    or unresolved-attr site matching that advisory's targets. A global
    count (e.g. PyYAML's own 64 ambiguous edges inside the parsed
    dependency) must not block a statement for a target none of them
    can be. If even one candidate is reachable or uncertain, no statement
    is emitted for that advisory at all — emitting not_affected next to a
    reachable finding in the same report contradicted the tool's own
    results. Uncertain results never produce VEX."""
    by_adv: dict[str, list[Result]] = {}
    for r in results:
        by_adv.setdefault(r.advisory_id, []).append(r)
    statements = []
    for adv_id, rs in by_adv.items():
        clean = (graph_clean.get(adv_id, False)
                 if isinstance(graph_clean, dict) else graph_clean)
        if not clean:
            continue
        if not all(r.verdict == "not_reachable"
                   and r.confidence in ("high", "medium") for r in rs):
            continue
        pkg = rs[0].package
        notes = "; ".join(f"{r.vulnerable_function}: {r.reason}" for r in rs)
        statements.append({
            "vulnerability": {"@id": adv_id, "name": adv_id},
            "products": [{
                "@id": project,
                "identifiers": {"purl": f"pkg:generic/{project}"},
                # Vulnerable dependency as a subcomponent (ChatGPT fix)
                "subcomponents": [{
                    "@id": pkg,
                    "identifiers": {"purl": f"pkg:pypi/{pkg}"},
                }] if pkg else [],
            }],
            "status": "not_affected",
            "status_notes": notes,
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
