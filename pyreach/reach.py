"""Phase 2 (part): Reachability by BFS. Fail-closed.

Verdicts:
- reachable: BFS from entry points hits a vulnerable function. Path is evidence.
- not_reachable: BFS searched everything, no path, no dynamic trigger on
  the way, no ambiguous edge touching the target, and the vulnerable
  function list is high/medium confidence.
- uncertain: anything else. Never downgrade reachable to not_reachable.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .advisory import Advisory
from .callgraph import Graph


@dataclass
class Result:
    advisory_id: str
    package: str
    vulnerable_function: str
    verdict: str  # reachable | not_reachable | uncertain
    confidence: str  # high | medium | low
    path: list[str] = field(default_factory=list)
    reason: str = ""
    function_confidence: str = "medium"


def bfs_path(graph: Graph, starts: set[str], target: str) -> list[str] | None:
    """Shortest path from any start to target, or None."""
    # Target may be a simple name or qualified; resolve to qualified nodes
    targets = {t for t in graph.functions if t == target or t.endswith("." + target) or t.split(".")[-1] == target}
    if not targets:
        return None
    seen: dict[str, str | None] = {s: None for s in starts}
    q: deque[str] = deque(starts)
    while q:
        cur = q.popleft()
        if cur in targets:
            path = [cur]
            while seen[cur] is not None:
                cur = seen[cur]  # type: ignore
                path.append(cur)
            return list(reversed(path))
        for nxt in graph.edges.get(cur, set()):
            if nxt not in seen:
                seen[nxt] = cur
                q.append(nxt)
    return None


def _has_dynamic_near(graph: Graph, starts: set[str]) -> bool:
    """True if any dynamic trigger is reachable from starts."""
    visited: set[str] = set(starts)
    q: deque[str] = deque(starts)
    while q:
        cur = q.popleft()
        for d in graph.dynamic:
            if d["caller"] == cur:
                return True
        for nxt in graph.edges.get(cur, set()):
            if nxt not in visited:
                visited.add(nxt)
                q.append(nxt)
    return False


def analyze(advisories: list[Advisory], graph: Graph, entrypoints: set[str]) -> list[Result]:
    results: list[Result] = []
    dynamic_near = _has_dynamic_near(graph, entrypoints)
    for adv in advisories:
        if not adv.vulnerable_functions:
            results.append(Result(
                advisory_id=adv.id, package=adv.package,
                vulnerable_function="", verdict="uncertain", confidence="low",
                reason="No vulnerable function list: no fix commit found. Cannot prove not-reachable.",
                function_confidence="low",
            ))
            continue
        for vf in adv.vulnerable_functions:
            path = bfs_path(graph, entrypoints, vf.qualified)
            if path:
                results.append(Result(
                    advisory_id=adv.id, package=adv.package,
                    vulnerable_function=vf.qualified, verdict="reachable",
                    confidence="high" if vf.confidence == "high" else "medium",
                    path=path,
                    reason=f"Call path from entry point: {' -> '.join(path)}",
                    function_confidence=vf.confidence,
                ))
                continue
            # No path. Can we safely say not_reachable?
            if vf.confidence == "low":
                verdict, conf = "uncertain", "low"
                reason = "Vulnerable function list is low confidence, cannot prove absence."
            elif dynamic_near:
                verdict, conf = "uncertain", "low"
                reason = "No static path found, but a dynamic trigger (getattr/importlib/plugin) is reachable, so a hidden path may exist."
            elif graph.ambiguous:
                verdict, conf = "uncertain", "medium"
                reason = "No static path found, but ambiguous calls exist that could resolve to the vulnerable function."
            else:
                verdict, conf = "not_reachable", "high" if vf.confidence == "high" else "medium"
                reason = "BFS from all real entry points found no path, no dynamic trigger, no ambiguous edge."
            results.append(Result(
                advisory_id=adv.id, package=adv.package,
                vulnerable_function=vf.qualified, verdict=verdict,
                confidence=conf, path=[], reason=reason,
                function_confidence=vf.confidence,
            ))
    return results
