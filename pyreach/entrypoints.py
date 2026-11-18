"""Phase 3: Real entry points only. Dead code does not count.

App mode: main(), CLI commands, Flask/Django/FastAPI routes, __main__ blocks.
Library mode: public API in __all__ or public (non-underscore) top-level
functions in __init__.py / public modules.
If we cannot find any entry point, fall back to public functions only
and mark the result low-confidence, never to every function.

Phase 3 hardening (built 18 Nov, after the base):
  1. console_scripts were only in the *evidence* function, not in the
     BFS roots. A CLI tool whose only entry is pyproject [project.scripts]
     fell back to "all public functions", so dead() became an entry and
     a dead-code call looked reachable. console_scripts now feed
     find_entrypoints() directly.
  2. Django: urlpatterns in urls.py — path("...", views.fn) — resolve the
     view to its function, preferring the views module. Function views only;
     class-based views (MyView.as_view()) are noted as unsupported, not guessed.
  3. Decorators: FastAPI/Blueprint .put/.delete/.patch added, click.group
     and .command( added. (click.command and .route/.get/.post were there.)
  4. Library mode prefers __all__ in __init__.py when present, resolved
     to qualified functions. The old code took ALL public functions, so an
     unexported-but-public helper was an entry. __all__ is the package's
     own statement of its public surface.
  5. __main__ guard: prefer the same-module function of that name instead
     of any project-wide simple-name match.
  6. __init__.py public functions are entries ONLY in library mode.
     The old code added them in app mode too.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .callgraph import Graph

ROUTE_DECORATORS = (
    ".route", ".get", ".post", ".put", ".delete", ".patch",
    "click.command", "click.group", ".command(", "app.command",
)


def _resolve_simple(graph: Graph, name: str, prefer_module: str | None = None) -> str | None:
    """Resolve a simple function name to a qualified function.
    Prefer `prefer_module` (e.g. views), then same-module, then unique.
    External library functions (file="external", e.g. yaml.load) are
    never candidates: a console_script or route pointing at "load"
    must resolve to a project function, not to the library it calls."""
    cands = [q for q in graph.functions
             if q.split(".")[-1] == name
             and graph.functions[q].file != "external"]
    if not cands:
        return None
    if prefer_module:
        same = [q for q in cands if q.startswith(prefer_module + ".")]
        if len(same) == 1:
            return same[0]
    if len(cands) == 1:
        return cands[0]
    return None  # ambiguous: do not guess


def _console_scripts(root: Path) -> dict[str, str]:
    """pyproject [project.scripts] -> {script_name: target 'mod:func'}."""
    try:
        import tomllib
        pp = root / "pyproject.toml"
        if pp.exists():
            data = tomllib.loads(pp.read_text(encoding="utf-8"))
            return dict(data.get("project", {}).get("scripts", {}))
    except Exception:
        return {}
    return {}


def _dunder_all(root: Path) -> list[str] | None:
    """__all__ from the top-level __init__.py, or None if absent."""
    for init in root.rglob("__init__.py"):
        try:
            tree = ast.parse(init.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "__all__":
                        if isinstance(node.value, (ast.List, ast.Tuple)):
                            names = []
                            for e in node.value.elts:
                                if isinstance(e, ast.Constant) and isinstance(e.value, str):
                                    names.append(e.value)
                            return names
    return None


def _django_views(root: Path, graph: Graph) -> dict[str, str]:
    """urls.py urlpatterns -> {qualified_view: evidence}.
    Handles path('...', views.fn), path('...', fn), re_path(...).
    Class-based views (MyView.as_view()) are unsupported, not guessed."""
    out: dict[str, str] = {}
    for p in root.rglob("urls.py"):
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            fname = ""
            if isinstance(func, ast.Name):
                fname = func.id
            elif isinstance(func, ast.Attribute):
                fname = func.attr
            if fname not in ("path", "re_path"):
                continue
            if len(node.args) < 2:
                continue
            view = node.args[1]
            # views.fn or fn
            if isinstance(view, ast.Attribute) and isinstance(view.value, ast.Name):
                prefer = view.value.id  # 'views'
                q = _resolve_simple(graph, view.attr, prefer_module=prefer)
                if q:
                    out[q] = f"Django urlpatterns: {ast.unparse(node)[:80]} -> {q}()"
            elif isinstance(view, ast.Name):
                q = _resolve_simple(graph, view.id)
                if q:
                    out[q] = f"Django urlpatterns: {ast.unparse(node)[:80]} -> {q}()"
            # view.as_view() (class-based) or include(): skip, do not guess.
    return out


def find_entrypoints_with_evidence(root: str | Path, graph: Graph) -> dict[str, str]:
    """Entry points WITH evidence: why each one is a real start.
    A function named main() is not automatically an entry point — it
    must actually be invoked. A route handler is invoked by framework
    dispatch, not by a direct call in your code, so we record a
    conceptual edge: framework_dispatcher -> handler.
    console_scripts in pyproject.toml are also real entries."""
    root = Path(root)
    evidence: dict[str, str] = {}
    for name, target in _console_scripts(root).items():
        func = target.split(":")[-1].split(".")[-1]
        q = _resolve_simple(graph, func)
        if q:
            evidence[q] = f"console_scripts entry '{name}' -> {target}"
    for q, why in _django_views(root, graph).items():
        evidence[q] = why
    entries, _note = find_entrypoints(root, graph)
    for q in entries:
        evidence.setdefault(q, "main / route / public API (see find_entrypoints)")
    if _dunder_all(root) is not None:
        for q in entries:
            if q in evidence and "main / route" in evidence[q]:
                pass
    for q in entries:
        if q.endswith(".<module>"):
            evidence[q] = "top-level module code runs on import"
    # Annotate route handlers with framework-dispatch evidence
    for p in sorted(root.rglob("*.py")):
        try:
            src = p.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src, filename=str(p))
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for d in node.decorator_list:
                    text = ast.unparse(d) if hasattr(ast, "unparse") else ""
                    if any(k in text for k in ROUTE_DECORATORS):
                        q = _resolve_simple(graph, node.name)
                        if q:
                            evidence[q] = f"framework dispatch: {text} -> {node.name}() (framework invokes handler, no direct call in code)"
    return evidence


def find_entrypoints(root: str | Path, graph: Graph) -> tuple[set[str], str]:
    root = Path(root)
    entries: set[str] = set()
    mode = "app"
    # Detect library mode: pyproject with [project] and no main.py / cli.py
    has_main = any((root / n).exists() for n in ("main.py", "cli.py", "app.py"))
    if not has_main and (root / "pyproject.toml").exists():
        mode = "library"

    # console_scripts: real entries, resolved to qualified functions.
    for _name, target in _console_scripts(root).items():
        func = target.split(":")[-1].split(".")[-1]
        mod = target.split(":")[0].rsplit(".", 1)[0] if ":" in target else ""
        q = _resolve_simple(graph, func, prefer_module=mod or None)
        if q:
            entries.add(q)

    # Django urlpatterns
    for q in _django_views(root, graph):
        entries.add(q)

    for p in sorted(root.rglob("*.py")):
        try:
            src = p.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src, filename=str(p))
        except (SyntaxError, OSError):
            continue
        rel = str(p.relative_to(root))
        module = rel.replace("/", ".").removesuffix(".py").removesuffix(".__init__")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{module}.{node.name}" if module else node.name
                # main()
                if node.name == "main":
                    entries.add(q)
                # Decorators: @app.route, @app.get, @click.command, etc.
                for d in node.decorator_list:
                    text = ast.unparse(d) if hasattr(ast, "unparse") else ""
                    if any(k in text for k in ROUTE_DECORATORS):
                        entries.add(q)
                # Public API in __init__ — library mode only (Phase 3 fix).
                if mode == "library" and rel.endswith("__init__.py") and not node.name.startswith("_"):
                    entries.add(q)
        # __main__ guard: any function called inside it is an entry.
        # Prefer the same-module function of that name.
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                test = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
                if '__name__' in test and '__main__' in test:
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                            q = _resolve_simple(graph, sub.func.id, prefer_module=module)
                            if q:
                                entries.add(q)
    # Phase 2: top-level module code runs on import, so a <module>
    # pseudo-node with outgoing calls is a real entry point. Without
    # this, a project that calls yaml.load at import time (no main())
    # would be missed entirely.
    for q in graph.functions:
        if q.endswith(".<module>") and graph.edges.get(q):
            entries.add(q)
    if mode == "library":
        # Prefer __all__ when the package declares it: it is the package's
        # own statement of its public surface. Otherwise all public funcs.
        all_names = _dunder_all(root)
        if all_names is not None:
            lib_entries = set()
            for name in all_names:
                q = _resolve_simple(graph, name)
                if q:
                    lib_entries.add(q)
            if lib_entries:
                return lib_entries, "library: __all__ is the entry surface"
        for q in graph.functions:
            # External library functions are NOT entries. Bug found
            # 19 Nov 2026 by scanning real MkDocs: yaml.load, os.path.join
            # and every other external node were added as library entries,
            # so BFS found yaml.load as its own entry with path
            # ["yaml.load"] — a reachable verdict with no real evidence
            # chain. An entry point must be project code that runs.
            if graph.functions[q].file == "external":
                continue
            if not q.split(".")[-1].startswith("_"):
                # Only if module is public (not _private)
                if "._" not in q:
                    entries.add(q)
        # Library mode is broader by design; note it in the reason string.
        return entries, "library: public API is the entry surface"
    if not entries:
        # Fallback: public functions only, low confidence — project
        # functions only, never external library nodes (same bug).
        entries = {q for q in graph.functions
                   if not q.split(".")[-1].startswith("_")
                   and graph.functions[q].file != "external"}
        return entries, "fallback: no main/route found, used public functions only"
    return entries, f"app: {len(entries)} entry point(s)"
