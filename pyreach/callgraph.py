"""Phase 2: Call graph from AST only. Never import or execute code.

Nodes are qualified functions: module.Class.method or module.func.
Edges are calls. Ambiguous calls (same method name in 2+ places) are
kept as ambiguous edges, never silently resolved to one target.
Dynamic triggers are recorded, not resolved here.

Phase 2 hardening (built 18 Nov, after the base):
  1. Nested functions: the old visitor set current=None after a nested
     def, so calls in the outer function AFTER the nested def were dropped.
     Now current is saved/restored, like a stack.
  2. Top-level module code is a pseudo-node `module.<module>`. A project
     that calls yaml.load at import time (no main()) was previously missed
     entirely — its calls were dropped because current was None.
  3. `self.` / `cls.` resolve to the enclosing class: self.helper() in
     class Loader -> module.Loader.helper, even when another class also
     has a helper() (old code went ambiguous -> uncertain).
  4. Dotted chains: a.b.load() is reconstructed as a full dotted name,
     with the base resolved through imports. The old code returned just
     'load' for a non-Name base, losing the module.
  5. `import a.b.c` binds 'a', not 'a.b.c'. The old map was wrong.
  6. Assignment aliases: `load = yaml.load` then `load(f)` is a real
     call to yaml.load. Tracked per file, like imports.
  7. Star imports: `from helpers import *` records helpers as a star
     source; a simple name that is ambiguous project-wide resolves to
     the star-imported module first, before going ambiguous.
  8. Pass 2 rebuilds edges from raw_calls only. The old code kept raw
     unqualified edges alongside resolved ones, and created external
     nodes for ANY dotted call — including self.helper and config.load
     (a local variable), which polluted the graph and could false-match
     a vulnerable target by simple name. External nodes are now created
     only when the base is a known import.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

DYNAMIC_NAMES = {
    "getattr", "setattr", "eval", "exec", "__import__",
    "globals", "locals",
}
DYNAMIC_ATTRS = {"import_module", "import_string"}


@dataclass
class FuncInfo:
    qualified: str
    file: str
    start: int
    end: int
    name: str


@dataclass
class Graph:
    functions: dict[str, FuncInfo] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=dict)  # caller -> callees
    ambiguous: dict[str, set[str]] = field(default_factory=dict)
    dynamic: list[dict] = field(default_factory=list)  # {file, line, kind, caller}
    raw_calls: list[dict] = field(default_factory=list)
    # 19 Nov 2026, ChatGPT review fix (Critical 1): attribute calls on
    # objects of unknown type (parser.load() where parser's type is
    # unknown) were dropped silently, so the analyser could claim
    # not_reachable for a function that really is called. They are now
    # recorded here, never silently dropped: {file, line, caller, attr}.
    unresolved_attrs: list[dict] = field(default_factory=list)
    # Names referenced in project code without being called (e.g. a class
    # passed as an argument: Loader=yaml.FullLoader). A vulnerable
    # function referenced this way cannot be not_reachable: something may
    # invoke it through the reference. Dotted forms (yaml.FullLoader) and
    # bare imported names (full_load) are tracked separately.
    referenced_dotted: set[str] = field(default_factory=set)
    referenced_names: set[str] = field(default_factory=set)
    # Per-file imports (local name -> qualified target) and the project
    # import graph (module -> project modules it imports), for entry-point
    # module reachability and for unresolved-import detection.
    imports_by_file: dict[str, dict[str, str]] = field(default_factory=dict)
    file_imports: dict[str, set[str]] = field(default_factory=dict)
    imported_modules: set[str] = field(default_factory=set)
    unresolved_imports: list[str] = field(default_factory=list)
    # Absolute file path -> module name, for deciding whether a dynamic /
    # unresolved site's code can execute (reach.site_can_run): a site in
    # a dunder method of a module imported by reachable code runs at
    # runtime even though nothing calls the dunder by name.
    module_by_file: dict[str, str] = field(default_factory=dict)


class _FileVisitor(ast.NodeVisitor):
    def __init__(self, module: str, file: str, graph: Graph):
        self.module = module
        self.file = file
        self.graph = graph
        self.imports: dict[str, str] = {}  # local name -> qualified target
        self.aliases: dict[str, str] = {}  # x = yaml.load -> x -> yaml.load
        self.star_imports: list[str] = []  # modules imported with *
        self.current: str | None = None
        self.class_stack: list[str] = []
        self._ensure_module_node()

    def _ensure_module_node(self):
        q = f"{self.module}.<module>" if self.module else "<module>"
        self.graph.functions[q] = FuncInfo(
            qualified=q, file=self.file, start=1,
            end=0, name="<module>",
        )
        self.graph.edges.setdefault(q, set())
        self.module_node = q

    def visit_Import(self, node):
        for a in node.names:
            # `import a.b.c` binds 'a', not 'a.b.c'.
            if a.asname:
                self.imports[a.asname] = a.name
            else:
                self.imports[a.name.split(".")[0]] = a.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for a in node.names:
            if a.name == "*":
                if mod:
                    self.star_imports.append(mod)
                continue
            local = a.asname or a.name
            self.imports[local] = f"{mod}.{a.name}" if mod else a.name
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node):
        self._enter_func(node)
        self.generic_visit(node)
        self.current = self._stack.pop()

    def visit_AsyncFunctionDef(self, node):
        self._enter_func(node)
        self.generic_visit(node)
        self.current = self._stack.pop()

    def _enter_func(self, node):
        if not hasattr(self, "_stack"):
            self._stack = []
        self._stack.append(self.current)
        prefix = ".".join(self.class_stack)
        base = f"{prefix}.{node.name}" if prefix else node.name
        q = f"{self.module}.{base}" if self.module else base
        self.current = q
        self.graph.functions[q] = FuncInfo(
            qualified=q, file=self.file,
            start=node.lineno, end=getattr(node, "end_lineno", node.lineno),
            name=node.name,
        )
        self.graph.edges.setdefault(q, set())

    def visit_Assign(self, node):
        # Alias: load = yaml.load  /  load = yaml.load as a Name/Attribute.
        # Only single-target, single-value assignments.
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            # import_module alias: mod = importlib.import_module("yaml")
            # then mod.load(...) is yaml.load. Phase 4: without this the
            # call was attr-unresolved and dropped — a missed reachable.
            if isinstance(node.value, ast.Call):
                mod_name = self._import_module_name(node.value)
                if mod_name:
                    self.aliases[target] = mod_name
                    self.generic_visit(node)
                    return
            resolved, _kind = self._resolve_expr(node.value)
            if resolved and resolved != target:
                self.aliases[target] = resolved
        self.generic_visit(node)

    def _import_module_name(self, node) -> str | None:
        """importlib.import_module("yaml") -> "yaml"; __import__("yaml") -> "yaml".
        Only a string literal first argument counts. Anything else is unknown."""
        func = node.func
        is_import_module = (
            isinstance(func, ast.Attribute) and func.attr == "import_module"
        ) or (isinstance(func, ast.Name) and func.id == "__import__")
        if not is_import_module or not node.args:
            return None
        arg = node.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
        return None

    def _dotted(self, node) -> str | None:
        """Reconstruct a dotted name from Name / Attribute chains."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._dotted(node.value)
            if base is None:
                return None
            return f"{base}.{node.attr}"
        return None

    def _resolve_expr(self, node):
        """Resolve an expression to a qualified name + kind.
        Returns (qualified_or_None, kind) where kind is direct/attr/dynamic."""
        if isinstance(node, ast.Name):
            if node.id in DYNAMIC_NAMES:
                return node.id, "dynamic"
            if node.id in self.aliases:
                return self.aliases[node.id], "direct"
            return self.imports.get(node.id, node.id), "direct"
        if isinstance(node, ast.Attribute):
            if node.attr in DYNAMIC_ATTRS:
                return node.attr, "dynamic"
            # Constructor call as receiver: Loader().load_config() ->
            # module.Loader.load_config. The receiver is a Call, not a
            # Name, so _dotted() returns None — handle it here.
            if isinstance(node.value, ast.Call):
                recv, _ = self._resolve_expr(node.value.func)
                if recv:
                    cls = recv.split(".")[-1]
                    prefix = f"{self.module}.{cls}" if self.module else cls
                    return f"{prefix}.{node.attr}", "attr"
                return node.attr, "attr-unresolved"
            dotted = self._dotted(node)
            if dotted is None:
                return node.attr, "attr"
            parts = dotted.split(".")
            base = parts[0]
            # self.helper / cls.helper -> enclosing class
            if base in ("self", "cls") and self.class_stack:
                cls = ".".join(self.class_stack)
                prefix = f"{self.module}.{cls}" if self.module else cls
                return f"{prefix}.{'.'.join(parts[1:])}", "attr"
            if base in self.imports:
                resolved_base = self.imports[base]
                return f"{resolved_base}.{'.'.join(parts[1:])}", "attr"
            if base in self.aliases:
                return f"{self.aliases[base]}.{'.'.join(parts[1:])}", "attr"
            # Unknown object (local variable, parameter): keep only the
            # attribute name, marked as unresolved-object. Pass 2 will
            # try simple-name resolution, and will NOT create an external
            # node for it — config.load is not yaml.load.
            return node.attr, "attr-unresolved"
        return None, "unknown"

    def _callee_name(self, func):
        return self._resolve_expr(func)

    def visit_Call(self, node):
        caller = self.current if self.current is not None else self.module_node
        callee, kind = self._callee_name(node.func)
        if callee:
            self.graph.raw_calls.append({
                "caller": caller, "callee_raw": callee,
                "file": self.file, "line": node.lineno, "kind": kind,
            })
            if kind == "dynamic":
                self.graph.dynamic.append({
                    "file": self.file, "line": node.lineno,
                    "kind": callee, "caller": caller,
                })
        self.generic_visit(node)


def _module_name(path: Path, root: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def build_graph(root: str | Path) -> Graph:
    """Build a call graph for all .py files under root (AST only)."""
    root = Path(root)
    graph = Graph()
    py_files = sorted(root.rglob("*.py"))
    # Pass 1: collect functions + raw calls. Keep per-file star imports
    # and aliases for pass 2: the visitor is per-file, so re-derive them
    # from the AST here (cheap, and keeps build_graph stateless).
    star_by_file: dict[str, list[str]] = {}
    for p in py_files:
        try:
            src = p.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src, filename=str(p))
        except (SyntaxError, OSError):
            continue
        visitor = _FileVisitor(_module_name(p, root), str(p), graph)
        visitor.visit(tree)
        star_by_file[str(p)] = visitor.star_imports
        graph.imports_by_file[str(p)] = dict(visitor.imports)
        graph.module_by_file[str(p)] = _module_name(p, root)
    # Pass 2: resolve raw calls to qualified functions. Edges are rebuilt
    # from raw_calls only — no raw unqualified edges survive.
    by_simple: dict[str, list[str]] = {}
    for q in graph.functions:
        by_simple.setdefault(q.split(".")[-1], []).append(q)
        by_simple.setdefault(q, []).append(q)
    # Which files star-import which modules, for disambiguation.
    star_modules: dict[str, set[str]] = {}
    for f, mods in star_by_file.items():
        star_modules[f] = set(mods)
    # Top-level packages defined in this project (mkdocs, cookiecutter,
    # ...). A dotted call whose base is NOT one of these cannot be a
    # project function — it is a library call like yaml.load.
    project_tops = {q.split(".")[0] for q in graph.functions}
    for call in graph.raw_calls:
        if call["kind"] == "dynamic":
            continue
        raw = call["callee_raw"]
        caller = call["caller"]
        kind = call["kind"]
        if raw in graph.functions:
            graph.edges.setdefault(caller, set()).add(raw)
            continue
        # Dotted library call FIRST, before simple-name fallback.
        # Bug found 19 Nov 2026 by scanning real MkDocs: `yaml.load`
        # was resolved to `FakeEntryPoint.load` — a test fake — because
        # the simple-name fallback below ran first and "load" matched
        # exactly one project function, in a different module. A dotted
        # call names its module explicitly: yaml.load cannot be
        # FakeEntryPoint.load. The same-name fallback is only for bare
        # / unresolved-object calls, never for a dotted import call.
        # Guard: if the base IS a project top-level package, this could
        # be a project function (e.g. self.load resolved to
        # mkdocs...load), so fall through to the normal resolution.
        if ("." in raw and kind in ("attr", "direct")
                and raw.split(".")[0] not in project_tops):
            graph.functions[raw] = FuncInfo(
                qualified=raw, file="external", start=0, end=0,
                name=raw.split(".")[-1],
            )
            graph.edges.setdefault(caller, set()).add(raw)
            continue
        simple = raw.split(".")[-1]
        cands = by_simple.get(simple, [])
        mod = ".".join(caller.split(".")[:-1])
        same = [c for c in cands if c.startswith(mod + ".")]
        if len(same) == 1:
            graph.edges.setdefault(caller, set()).add(same[0])
            continue
        # Star-import disambiguation: prefer a candidate from a module
        # this file star-imported. E.g. `from helpers import *` with
        # helpers.parse_config and legacy.parse_config both defined.
        if len(cands) > 1:
            star_mods = star_modules.get(call["file"], set())
            star_cands = [c for c in cands
                          if any(c == m + "." + simple or c.startswith(m + ".")
                                 for m in star_mods)]
            if len(star_cands) == 1:
                graph.edges.setdefault(caller, set()).add(star_cands[0])
                continue
            graph.ambiguous.setdefault(caller, set()).update(cands)
            continue
        if len(cands) == 1:
            graph.edges.setdefault(caller, set()).add(cands[0])
            continue
        # 0 candidates: external library call. Keep it ONLY if the base
        # is a known import (kind attr with an imported base, or a direct
        # import target). Unknown-object calls (config.load) and bare
        # names are dropped — creating an external node for them polluted
        # the graph and could false-match a target by simple name.
        if "." in raw and kind == "attr":
            graph.functions[raw] = FuncInfo(
                qualified=raw, file="external", start=0, end=0,
                name=raw.split(".")[-1],
            )
            graph.edges.setdefault(caller, set()).add(raw)
        elif "." in raw and kind == "direct":
            # Direct dotted name from an import, e.g. yaml.load via
            # `from yaml import load` already resolves via imports, but
            # a dotted direct call with no project match is external.
            graph.functions[raw] = FuncInfo(
                qualified=raw, file="external", start=0, end=0,
                name=raw.split(".")[-1],
            )
            graph.edges.setdefault(caller, set()).add(raw)
        # kind == "attr-unresolved" or bare name with 0 candidates: drop
        # the edge — but NEVER silently (ChatGPT Critical 1, 19 Nov 2026).
        # An unresolved attribute call is recorded so reachability can
        # mark a matching target uncertain instead of not_reachable.
        if kind == "attr-unresolved":
            graph.unresolved_attrs.append({
                "file": call["file"], "line": call["line"],
                "caller": caller, "attr": raw.split(".")[-1],
            })
    # Drop empty module pseudo-nodes (no top-level calls) AFTER pass 2,
    # so they do not become spurious entry points. This must run after
    # resolution: at pass-1 time their edge sets are still empty even
    # when top-level calls exist, because edges are built in pass 2.
    for q in list(graph.functions):
        if q.endswith(".<module>") and not graph.edges.get(q):
            del graph.functions[q]
            graph.edges.pop(q, None)
    _analyze_imports(root, py_files, graph)
    _collect_references(root, py_files, graph)
    return graph


def _dotted_expr(node) -> str | None:
    """Reconstruct a dotted name from Name / Attribute chains (module-level
    twin of _FileVisitor._dotted, for the reference pass below)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_expr(node.value)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None


def _collect_references(root: Path, py_files: list[Path], graph: Graph) -> None:
    """Names referenced in project code WITHOUT being called (ChatGPT
    Critical 2: a class passed as an argument, e.g. Loader=yaml.
    FullLoader). A vulnerable function referenced this way cannot be
    not_reachable: something may invoke it through the reference.

    A call is NOT a reference: the Attribute/Name that is the function
    part of a Call is skipped, so a call from dead code does not by
    itself block not_reachable (dead code does not count — the BFS rule).
    Bare names count only when they are imported names in that file, so
    a local variable that happens to share a name is not a reference.
    """
    for p in py_files:
        try:
            src = p.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src, filename=str(p))
        except (SyntaxError, OSError):
            continue
        parent: dict[object, object] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parent[child] = node
        imports = graph.imports_by_file.get(str(p), {})
        for node in ast.walk(tree):
            par = parent.get(node)
            if isinstance(par, ast.Call) and par.func is node:
                continue  # a call, not a reference
            if isinstance(node, ast.Attribute):
                dotted = _dotted_expr(node)
                if not dotted:
                    continue
                graph.referenced_dotted.add(dotted)
                parts = dotted.split(".")
                if parts[0] in imports:
                    resolved = imports[parts[0]]
                    if len(parts) > 1:
                        resolved = resolved + "." + ".".join(parts[1:])
                    graph.referenced_dotted.add(resolved)
            elif isinstance(node, ast.Name):
                if node.id in imports:
                    graph.referenced_names.add(node.id)


def _record_import(target: str, rel: str, lineno: int,
                   project_modules: set[str], project_tops: set[str],
                   imported: set[str], graph: Graph) -> None:
    """Record one imported module name: as a project import if it (or its
    longest project prefix) is a project module, else as unresolved when
    it names a project top-level package that does not resolve.
    Third-party imports are fine and are silently ignored."""
    if not target:
        return
    parts = target.split(".")
    for i in range(len(parts), 0, -1):
        prefix = ".".join(parts[:i])
        if prefix in project_modules:
            imported.add(prefix)
            return
    if parts[0] in project_tops:
        graph.unresolved_imports.append(
            f"{rel}:{lineno}: cannot resolve import '{target}'")


def _analyze_imports(root: Path, py_files: list[Path], graph: Graph) -> None:
    """Project import graph + unresolved imports (ChatGPT review, §5).

    Re-derived from the AST (like star imports above): relative imports
    are resolved against the file's package, so `from . import foo` in
    pkg/sub/mod.py means pkg.sub.foo, not top-level foo.
    Records graph.file_imports (module -> project modules it imports),
    graph.imported_modules (every top-level module imported anywhere,
    project + third-party), and graph.unresolved_imports.
    """
    project_modules = {_module_name(p, root) for p in py_files}
    project_tops = {m.split(".")[0] for m in project_modules if m}
    for p in py_files:
        try:
            src = p.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src, filename=str(p))
        except (SyntaxError, OSError):
            continue
        module = _module_name(p, root)
        rel = str(p.relative_to(root))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    _record_import(a.name, rel, node.lineno,
                                   project_modules, project_tops,
                                   imported, graph)
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    # Relative import: resolve against the file's package.
                    # For __init__.py the module IS the package; otherwise
                    # the package is the module minus its last segment.
                    if p.name == "__init__.py":
                        pkg = module
                    else:
                        pkg = module.rsplit(".", 1)[0] if "." in module else module
                    for _ in range(node.level - 1):
                        pkg = pkg.rsplit(".", 1)[0] if "." in pkg else ""
                    base = (pkg + "." + node.module) if node.module else pkg
                    for a in node.names:
                        if a.name == "*":
                            _record_import(base, rel, node.lineno,
                                           project_modules, project_tops,
                                           imported, graph)
                        else:
                            _record_import(base + "." + a.name if base else a.name,
                                           rel, node.lineno, project_modules,
                                           project_tops, imported, graph)
                elif node.module:
                    _record_import(node.module, rel, node.lineno,
                                   project_modules, project_tops,
                                   imported, graph)
                    # `from pkg import sub` imports the submodule too
                    # when sub is a module: record it if it exists.
                    for a in node.names:
                        if a.name != "*":
                            _record_import(node.module + "." + a.name,
                                           rel, node.lineno, project_modules,
                                           project_tops, imported, graph)
        graph.file_imports[module] = imported
    graph.imported_modules = {
        v.split(".")[0]
        for vals in graph.imports_by_file.values()
        for v in vals.values()
    }
