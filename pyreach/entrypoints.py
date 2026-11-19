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


def _is_route_decorator(text: str) -> bool:
    """True for framework route decorators. False for lookalikes such as
    @mock.patch (19 Nov 2026: the '.patch' substring matched mock.patch
    and created 123 phantom entry points on MkDocs)."""
    if "mock.patch" in text or text.startswith("mock."):
        return False
    return any(k in text for k in ROUTE_DECORATORS)


def _entry_module(rel: str) -> str:
    """Module name for a file path relative to the project root, matching
    callgraph._module_name exactly (a root __init__.py is module '', a
    pkg/__init__.py is module 'pkg'). The old inline computation gave
    '__init__' for a root __init__.py, which matched no graph function."""
    parts = rel.replace("/", ".").removesuffix(".py").split(".")
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _program_modules(root: Path, graph: Graph, mode: str) -> set[str]:
    """Modules that can actually execute as programs: files named
    main/app/cli/__main__, modules with an `if __name__ == "__main__"`
    guard, console-script target modules, the only module of a
    single-file project, and (library mode) top-level __init__ modules
    — importing the library executes them."""
    programs: set[str] = set()
    py_files = sorted(root.rglob("*.py"))
    for p in py_files:
        rel = str(p.relative_to(root))
        module = _entry_module(rel)
        if p.stem in ("main", "app", "cli", "__main__"):
            programs.add(module)
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                test = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
                if "__name__" in test and "__main__" in test:
                    programs.add(module)
                    break
    if len(py_files) == 1:
        p = py_files[0]
        programs.add(_entry_module(str(p.relative_to(root))))
    if mode == "library":
        for p in py_files:
            if p.name == "__init__.py":
                programs.add(_entry_module(str(p.relative_to(root))))
    for target in _console_scripts(root).values():
        mod = target.split(":")[0]
        if mod:
            programs.add(mod)
    return programs


def _reachable_modules(root: Path, graph: Graph, mode: str) -> set[str]:
    """Program modules + modules they import, transitively (over the
    project import graph). A module in this set can execute; anything
    else is dead code for entry-point purposes."""
    programs = _program_modules(root, graph, mode)
    reached = set(programs)
    stack = list(programs)
    while stack:
        cur = stack.pop()
        for nxt in graph.file_imports.get(cur, set()):
            if nxt not in reached:
                reached.add(nxt)
                stack.append(nxt)
    return reached


def find_unsupported_entrypoints(root: str | Path, graph: Graph) -> list[str]:
    """Entry points the analyser detected but cannot model (ChatGPT §5):
    class-based Django views (MyView.as_view()) and console-script
    targets that do not resolve to a project function. Reported in the
    ledger, never guessed."""
    root = Path(root)
    out: list[str] = []
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
            if fname not in ("path", "re_path") or len(node.args) < 2:
                continue
            view = node.args[1]
            if (isinstance(view, ast.Call) and isinstance(view.func, ast.Attribute)
                    and view.func.attr == "as_view"):
                cls = ast.unparse(view.func.value) if hasattr(ast, "unparse") else "?"
                out.append(f"{p.relative_to(root)}: class-based view {cls}.as_view() is unsupported")
    for name, target in _console_scripts(root).items():
        func = target.split(":")[-1].split(".")[-1]
        # The part before ":" IS the module ("pkg.mod:func"), not a
        # qualified function path — do not strip its last segment.
        # (19 Nov 2026: the old rsplit made prefer_module "yamllint"
        # for "yamllint.cli:run", which matched two def run and failed
        # to resolve a real entry point.)
        mod = target.split(":")[0] if ":" in target else ""
        if not _resolve_simple(graph, func, prefer_module=mod or None):
            out.append(f"console_scripts '{name}' -> '{target}' does not resolve to a project function")
    return out


def _resolve_simple(graph: Graph, name: str, prefer_module: str | None = None) -> str | None:
    """Resolve a simple function name to a qualified function.
    Prefer `prefer_module` (e.g. views), then same-module, then unique.
    External library functions (file="external", e.g. yaml.load) are
    never candidates: a console_script or route pointing at "load"
    must resolve to a project function, not to the library it calls."""
    cands = [q for q in graph.functions
             if q.split(".")[-1] == name
             and graph.functions[q].file != "external"
             and graph.functions[q].file not in graph.dependency_files]
    if not cands:
        return None
    if prefer_module:
        # "Defined in the preferred module" means the qualified name
        # is exactly <module>.<name>. A startswith check is wrong
        # here: prefer "kedro.framework.cli" would also match
        # "kedro.framework.cli.cli.main" AND
        # "kedro.framework.cli.cli.KedroCLI.main" (two different
        # functions in a submodule), call that ambiguous, and never
        # reach the re-export below. Exact equality keeps submodule
        # functions out of this step entirely.
        same = [q for q in cands if q == prefer_module + "." + name]
        if same:
            return same[0]
        # No definition in the preferred module: the entry may be
        # re-exported there (cookiecutter's __main__.py does
        # `from cookiecutter.cli import main`; kedro's cli/__init__.py
        # does `from .cli import main`). Follow that module's imports
        # one level — but only to a project function, never an external.
        # The visitor records a relative import as written
        # (`from .cli import main` -> "cli.main"), so also try it
        # joined to the preferred module's package; that join is only
        # correct for a level-1 relative import, and it only fires
        # when the joined name is a real project function.
        for fpath, mod in graph.module_by_file.items():
            if mod == prefer_module:
                target = graph.imports_by_file.get(fpath, {}).get(name)
                if target:
                    for cand in (target, f"{prefer_module}.{target}"):
                        if (cand in graph.functions
                                and graph.functions[cand].file != "external"
                                and graph.functions[cand].file
                                not in graph.dependency_files):
                            return cand
        # No re-export found; fall through to the unique-name rule.
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
        # Same module rule as find_entrypoints: the part before ":"
        # is the full module — without prefer_module, two `def run`
        # make this ambiguous and the evidence falls back to generic.
        mod = target.split(":")[0] if ":" in target else ""
        q = _resolve_simple(graph, func, prefer_module=mod or None)
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
                    if _is_route_decorator(text):
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
        # See the same note in find_unsupported_entrypoints: the part
        # before ":" is the full module, do not strip its last segment.
        mod = target.split(":")[0] if ":" in target else ""
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
        module = _entry_module(rel)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{module}.{node.name}" if module else node.name
                # main() is NOT an entry point by itself (ChatGPT Critical
                # 4, 19 Nov 2026): a helper called main() in a module
                # nothing runs is dead code. It becomes reachable only by
                # being called — from a __main__ guard, a console script,
                # or another entry (the BFS follows those edges).
                # Decorators: @app.route, @app.get, @click.command, etc.
                for d in node.decorator_list:
                    text = ast.unparse(d) if hasattr(ast, "unparse") else ""
                    if _is_route_decorator(text):
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
    # Phase 2: top-level module code runs on import — but only for
    # modules that can actually execute (ChatGPT Critical 4, 19 Nov 2026):
    # program modules and modules they import, transitively. A module
    # nothing imports and nobody runs is dead code, not an entry point
    # (never_imported.py's top-level yaml.load used to be reachable).
    reachable_mods = _reachable_modules(root, graph, mode)
    for q in graph.functions:
        if q.endswith(".<module>") and graph.edges.get(q):
            mod = q[: -len(".<module>")] if q != "<module>" else ""
            if mod in reachable_mods:
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
                    continue
                # A name in __all__ may be a class (Session, Request):
                # there is no function node for the class itself, but
                # constructing it is public API use — add its __init__
                # (19 Nov 2026: requests' __all__ lists Session but
                # Session.__init__ was never an entry, so the Retry path
                # from Session construction was invisible).
                for fn in graph.functions:
                    if fn.endswith(f".{name}.__init__") and graph.functions[fn].file != "external" and graph.functions[fn].file not in graph.dependency_files:
                        lib_entries.add(fn)
            if lib_entries:
                # __all__ defines the library surface, but it must not
                # discard entries found by other means (console scripts,
                # routes, __main__ guards): kedro's root __all__ has 4
                # names while its `kedro` console script is how the
                # tool is actually run, and the early return dropped
                # it. Merge, don't replace (19 Nov 2026).
                entries |= lib_entries
                return entries, "library: __all__ is the entry surface"
        for q in graph.functions:
            # External library functions are NOT entries. Bug found
            # 19 Nov 2026 by scanning real MkDocs: yaml.load, os.path.join
            # and every other external node were added as library entries,
            # so BFS found yaml.load as its own entry with path
            # ["yaml.load"] — a reachable verdict with no real evidence
            # chain. An entry point must be project code that runs.
            # Merged dependency functions (Phase 11) are real code but
            # still not project entries: the dependency runs only when
            # project code calls into it.
            if graph.functions[q].file == "external":
                continue
            if graph.functions[q].file in graph.dependency_files:
                continue
            if not q.split(".")[-1].startswith("_"):
                # Only if module is public (not _private)
                if "._" not in q:
                    entries.add(q)
        # Library mode is broader by design; note it in the reason string.
        return entries, "library: public API is the entry surface"
    if not entries:
        # Fallback: public functions only, low confidence — project
        # functions only, never external library nodes (same bug) and
        # never merged dependency functions (Phase 11).
        entries = {q for q in graph.functions
                   if not q.split(".")[-1].startswith("_")
                   and graph.functions[q].file != "external"
                   and graph.functions[q].file not in graph.dependency_files}
        return entries, "fallback: no main/route found, used public functions only"
    return entries, f"app: {len(entries)} entry point(s)"
