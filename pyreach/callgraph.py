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
            resolved, _kind = self._resolve_expr(node.value)
            if resolved and resolved != target:
                self.aliases[target] = resolved
        self.generic_visit(node)

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
    for call in graph.raw_calls:
        if call["kind"] == "dynamic":
            continue
        raw = call["callee_raw"]
        caller = call["caller"]
        kind = call["kind"]
        if raw in graph.functions:
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
        # kind == "attr-unresolved" or bare name with 0 candidates: drop.
    # Drop empty module pseudo-nodes (no top-level calls) AFTER pass 2,
    # so they do not become spurious entry points. This must run after
    # resolution: at pass-1 time their edge sets are still empty even
    # when top-level calls exist, because edges are built in pass 2.
    for q in list(graph.functions):
        if q.endswith(".<module>") and not graph.edges.get(q):
            del graph.functions[q]
            graph.edges.pop(q, None)
    return graph
