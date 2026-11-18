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


def _is_library_internal(qualified: str) -> bool:
    """True for functions the project never calls directly — the library
    calls them internally. E.g. FullConstructor.construct_python_object_new.
    Public APIs the project calls (yaml.load, yaml.full_load) are NOT internal.
    Note: add_multi_constructor is the registration call, not a vulnerable
    function — it is not internal either, it is just not a candidate."""
    return "construct_" in qualified


def _target_in_graph(graph: Graph, target: str) -> bool:
    return any(t == target or t.endswith("." + target) or t.split(".")[-1] == target
               for t in graph.functions)


def propagate_library_internals(results: list[Result]) -> list[Result]:
    """If a public loader (yaml.load / yaml.full_load) is reachable, then a
    library-internal constructor it uses internally is reachable too, even
    though the project never calls it directly and the dependency source
    was not parsed. Without this, yaml.load reachable + construct_* 
    not_reachable would be a false not-reachable — the worst failure."""
    by_adv: dict[str, list[Result]] = {}
    for r in results:
        by_adv.setdefault(r.advisory_id, []).append(r)
    for adv_id, rs in by_adv.items():
        apis = [r for r in rs if r.verdict == "reachable"
                and (r.vulnerable_function.endswith(".load")
                     or r.vulnerable_function.endswith(".full_load")
                     or r.vulnerable_function in ("load", "full_load"))]
        if not apis:
            continue
        api = apis[0]
        for r in rs:
            if r.verdict == "uncertain" and _is_library_internal(r.vulnerable_function):
                r.verdict = "reachable"
                r.confidence = "medium"
                r.path = list(api.path) + [r.vulnerable_function]
                r.reason = (f"Reached inside the library via {api.vulnerable_function} "
                            f"(library internal, dependency source not parsed): "
                            f"{' -> '.join(r.path)}")
    return results


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
            # No path, and the target is a library internal that the project
            # never calls directly: we cannot prove not_reachable, because
            # the dependency source was not parsed and the library may call
            # it internally when a public API is used. Fail closed -> uncertain.
            if _is_library_internal(vf.qualified) and not _target_in_graph(graph, vf.qualified):
                results.append(Result(
                    advisory_id=adv.id, package=adv.package,
                    vulnerable_function=vf.qualified, verdict="uncertain",
                    confidence="medium", path=[],
                    reason="Library-internal function, dependency source not parsed; "
                           "cannot prove not-reachable. Reachable if a public loader "
                           "that uses it is reachable (see propagate_library_internals).",
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
    return propagate_library_internals(results)
