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
    # A candidate ending in .__init__ is invoked by constructing the
    # class (Retry(...) calls Retry.__init__), and the call graph records
    # constructor calls as calls to the class, not to __init__ — so a
    # .__init__ target also matches the class node (19 Nov 2026: this
    # is what makes urllib3 Retry.__init__ reachable from requests,
    # which constructs a Retry in every HTTPAdapter).
    targets = set()
    for t in (target, target.removesuffix(".__init__")):
        targets |= {n for n in graph.functions
                    if n == t or n.endswith("." + t) or n.split(".")[-1] == t}
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


def reachable_functions(graph: Graph, starts: set[str]) -> set[str]:
    """Functions reachable from starts over static edges (BFS). Shared by
    the dynamic/ambiguous checks so they only count triggers in code
    that can actually execute from an entry point."""
    seen: set[str] = set(starts)
    q: deque[str] = deque(starts)
    while q:
        cur = q.popleft()
        for nxt in graph.edges.get(cur, set()):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return seen


def reachable_modules(graph: Graph, starts: set[str]) -> set[str]:
    """Modules that can execute: modules of entry functions + modules
    they import, transitively (over graph.file_imports)."""
    seeds: set[str] = set()
    for s in starts:
        info = graph.functions.get(s)
        if info is not None:
            mod = graph.module_by_file.get(info.file)
            if mod is not None:
                seeds.add(mod)
    reached = set(seeds)
    stack = list(seeds)
    while stack:
        cur = stack.pop()
        for nxt in graph.file_imports.get(cur, set()):
            if nxt not in reached:
                reached.add(nxt)
                stack.append(nxt)
    return reached


def site_can_run(graph: Graph, starts: set[str], reached: set[str],
                 modules: set[str], site: dict) -> bool:
    """Can the code at this dynamic / unresolved-attr site execute?
    True if its caller is reachable from entries over static edges, or
    it sits in module top-level code of a reachable module, or in an
    implicitly-invoked dunder method (e.g. __getattr__) of a reachable
    module. A dunder is never called by name, so BFS alone misses it —
    but attribute access invokes it at runtime, so a dynamic site
    inside it is a real hole. Found 19 Nov 2026 on MkDocs: the
    config_options.py:549 getattr inside Optional.__getattr__ was
    dropped by the BFS-only filter, so Phase 4 claimed 'all 5 sites
    resolved' while 2 real sites were never examined."""
    caller = site["caller"]
    if caller in reached:
        return True
    mod = graph.module_by_file.get(site["file"])
    if mod is None or mod not in modules:
        return False
    if caller.endswith(".<module>"):
        return True
    fname = caller.split(".")[-1]
    return fname.startswith("__") and fname.endswith("__")


def _has_dynamic_near(graph: Graph, starts: set[str]) -> bool:
    """True if any dynamic trigger is in code that can execute."""
    reached = reachable_functions(graph, starts)
    modules = reachable_modules(graph, starts)
    return any(site_can_run(graph, starts, reached, modules, d)
               for d in graph.dynamic)


def _has_ambiguous_for(graph: Graph, starts: set[str], target: str) -> bool:
    """True if an ambiguous edge in code that can execute could resolve
    to the target. Target-specific (19 Nov 2026): an ambiguous call to
    unrelated names in dead code no longer blocks not_reachable for
    this target."""
    reached = reachable_functions(graph, starts)
    modules = reachable_modules(graph, starts)
    simple = target.split(".")[-1]
    for caller, cands in graph.ambiguous.items():
        info = graph.functions.get(caller)
        site = {"caller": caller, "file": info.file if info else ""}
        if not site_can_run(graph, starts, reached, modules, site):
            continue
        if any(c == target or c.endswith("." + target)
               or c.split(".")[-1] == simple for c in cands):
            return True
    return False


def _is_project_function(graph: Graph, target: str) -> bool:
    """True if the target is a function defined in project code (not an
    external library node)."""
    return any(
        (t == target or t.endswith("." + target)
         or t.split(".")[-1] == target)
        and graph.functions[t].file != "external"
        for t in graph.functions
    )


def _is_library_internal(qualified: str, graph: Graph) -> bool:
    """General rule (19 Nov 2026, replaces the old 'construct_' heuristic,
    which only covered PyYAML constructors): a candidate is
    library-internal when the project never calls it directly AND it is
    not addressable as a public API name from project code. Public =
    its first dotted segment is a module the project imports (yaml.load
    — the project imports yaml), or it is a bare name (full_load,
    FullLoader — importable from the package top level), or it is a
    project function. Anything else (FullConstructor.construct_python_
    object) can only be reached through the dependency's own code, which
    was not parsed — so it cannot be not_reachable."""
    if _is_project_function(graph, qualified):
        return False
    if "." not in qualified:
        return False  # bare name: top-level package API
    return qualified.split(".")[0] not in graph.imported_modules


def _unresolved_attr_for(graph: Graph, target: str, starts: set[str]) -> list[dict]:
    """Unresolved attribute call sites whose attribute name is the
    target's simple name (ChatGPT Critical 1, 19 Nov 2026): parser.load()
    where parser's type is unknown may invoke the target, so it must
    block not_reachable. Sites with other attribute names cannot call
    this target (the attribute name is fixed), so they do not block it.
    Only sites in code that can execute count (site_can_run): an
    unresolved call in a dead module is not a hole."""
    simple = target.split(".")[-1]
    reached = reachable_functions(graph, starts)
    modules = reachable_modules(graph, starts)
    return [u for u in graph.unresolved_attrs
            if u["attr"] == simple
            and site_can_run(graph, starts, reached, modules, u)]


def _referenced_in_project(graph: Graph, target: str) -> bool:
    """True if the target's name is referenced in project code without
    being called (ChatGPT Critical 2: Loader=yaml.FullLoader). Such a
    reference may be invoked later — by the framework, a callback, a
    registry — so the target cannot be not_reachable."""
    if target in graph.referenced_dotted:
        return True
    simple = target.split(".")[-1]
    if "." not in target:
        # Bare candidate (FullLoader, full_load): a dotted reference to
        # it (yaml.FullLoader as an argument) counts, and so does a bare
        # imported name (from yaml import full_load; Loader=full_load).
        if any(d.endswith("." + target) for d in graph.referenced_dotted):
            return True
    for vals in graph.imports_by_file.values():
        for local, qualified in vals.items():
            if qualified == target and local in graph.referenced_names:
                return True
    if "." not in target and simple in graph.referenced_names:
        return True
    return False


def _target_in_graph(graph: Graph, target: str) -> bool:
    return any(t == target or t.endswith("." + target) or t.split(".")[-1] == target
               for t in graph.functions)


def propagate_library_internals(results: list[Result], graph: Graph) -> list[Result]:
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
            if r.verdict == "uncertain" and _is_library_internal(r.vulnerable_function, graph):
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
        # Which of this advisory's import names had their source parsed
        # (Phase 11): used below to say plainly when a candidate was
        # not found in parsed source, instead of claiming the source
        # was never parsed.
        parsed_imports = ({vf.qualified.split(".")[0]
                           for vf in adv.vulnerable_functions}
                          & graph.dependency_parsed_modules)
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
                # A one-node path means the candidate itself is an entry
                # point (a public-API function with the same name). That
                # is a real reachable only when the candidate was
                # identified at function level (high confidence). A
                # medium/low text candidate matching a same-named project
                # attribute is not proof the vulnerable code runs: the
                # Werkzeug form-parse advisory mentions
                # Request.max_content_length in its text, and Flask's own
                # Request.max_content_length property matched it — a
                # vacuous 1-node "reachable" (19 Nov 2026). Fail closed.
                if len(path) == 1 and vf.confidence != "high":
                    results.append(Result(
                        advisory_id=adv.id, package=adv.package,
                        vulnerable_function=vf.qualified, verdict="uncertain",
                        confidence="low", path=[],
                        reason="Candidate matches a public name but no call "
                               "path into the vulnerable code was found "
                               "(single-node match on a medium/low-confidence "
                               "text candidate).",
                        function_confidence=vf.confidence,
                    ))
                    continue
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
            # When the advisory's package WAS parsed and this name is not
            # in it, say so: the name may be a text artefact from the fix
            # commit (e.g. huntr.com, scraped from a commit message).
            if _is_library_internal(vf.qualified, graph) and not _target_in_graph(graph, vf.qualified):
                if parsed_imports:
                    reason = ("Library-internal function, not found in the parsed "
                              f"{', '.join(sorted(parsed_imports))} source; "
                              "cannot prove not-reachable from a name that may "
                              "be a text artefact rather than a real function.")
                else:
                    reason = ("Library-internal function, dependency source not parsed; "
                              "cannot prove not-reachable. Reachable if a public loader "
                              "that uses it is reachable (see propagate_library_internals).")
                results.append(Result(
                    advisory_id=adv.id, package=adv.package,
                    vulnerable_function=vf.qualified, verdict="uncertain",
                    confidence="medium", path=[], reason=reason,
                    function_confidence=vf.confidence,
                ))
                continue
            # No path. An unresolved attribute call with the target's
            # simple name (parser.load() where parser's type is unknown)
            # may invoke it — never not_reachable (Critical 1).
            attr_sites = _unresolved_attr_for(graph, vf.qualified, entrypoints)
            if attr_sites:
                site = attr_sites[0]
                results.append(Result(
                    advisory_id=adv.id, package=adv.package,
                    vulnerable_function=vf.qualified, verdict="uncertain",
                    confidence="low", path=[],
                    reason=(f"No static path found, but an unresolved attribute call "
                            f".{site['attr']}() at {site['file']}:{site['line']} may "
                            f"invoke {vf.qualified} (object type unknown)."),
                    function_confidence=vf.confidence,
                ))
                continue
            # No path, but the target's name is referenced without being
            # called (Loader=yaml.FullLoader): it may be invoked through
            # the reference, so it cannot be not_reachable (Critical 2).
            if _referenced_in_project(graph, vf.qualified):
                results.append(Result(
                    advisory_id=adv.id, package=adv.package,
                    vulnerable_function=vf.qualified, verdict="uncertain",
                    confidence="low", path=[],
                    reason=(f"No static path found, but {vf.qualified} is referenced "
                            f"in project code without being called (e.g. passed as an "
                            f"argument) and may be invoked through that reference."),
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
            elif _has_ambiguous_for(graph, entrypoints, vf.qualified):
                verdict, conf = "uncertain", "medium"
                reason = "No static path found, but an ambiguous call in reachable code could resolve to the vulnerable function."
            else:
                verdict, conf = "not_reachable", "high" if vf.confidence == "high" else "medium"
                reason = "BFS from all real entry points found no path, no dynamic trigger, no ambiguous edge."
            results.append(Result(
                advisory_id=adv.id, package=adv.package,
                vulnerable_function=vf.qualified, verdict=verdict,
                confidence=conf, path=[], reason=reason,
                function_confidence=vf.confidence,
            ))
    return propagate_library_internals(results, graph)
