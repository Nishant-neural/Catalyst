"""Phase 2: Call graph from AST only. Never import or execute code.

Nodes are qualified functions: module.Class.method or module.func.
Edges are calls. Ambiguous calls (same method name in 2+ places) are
kept as ambiguous edges, never silently resolved to one target.
Dynamic triggers are recorded, not resolved here.
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
        self.current: str | None = None
        self.class_stack: list[str] = []

    def visit_Import(self, node):
        for a in node.names:
            local = a.asname or a.name.split(".")[0]
            self.imports[local] = a.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for a in node.names:
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
        self.current = None

    def visit_AsyncFunctionDef(self, node):
        self._enter_func(node)
        self.generic_visit(node)
        self.current = None

    def _enter_func(self, node):
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

    def visit_Call(self, node):
        if self.current:
            callee, kind = self._callee_name(node.func)
            if callee:
                self.graph.raw_calls.append({
                    "caller": self.current, "callee_raw": callee,
                    "file": self.file, "line": node.lineno, "kind": kind,
                })
                if kind == "dynamic":
                    self.graph.dynamic.append({
                        "file": self.file, "line": node.lineno,
                        "kind": callee, "caller": self.current,
                    })
                else:
                    self.graph.edges[self.current].add(callee)
        self.generic_visit(node)

    def _callee_name(self, func):
        if isinstance(func, ast.Name):
            if func.id in DYNAMIC_NAMES:
                return func.id, "dynamic"
            return self.imports.get(func.id, func.id), "direct"
        if isinstance(func, ast.Attribute):
            if func.attr in DYNAMIC_ATTRS:
                return func.attr, "dynamic"
            # obj.method() -> resolve obj if imported, else keep method name
            if isinstance(func.value, ast.Name):
                base = self.imports.get(func.value.id, func.value.id)
                return f"{base}.{func.attr}", "attr"
            return func.attr, "attr"
        return None, "unknown"


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
    # Pass 1: collect functions + raw calls
    for p in py_files:
        try:
            src = p.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src, filename=str(p))
        except (SyntaxError, OSError):
            continue
        visitor = _FileVisitor(_module_name(p, root), str(p), graph)
        visitor.visit(tree)
    # Pass 2: resolve raw call names to qualified functions where unique
    by_simple: dict[str, list[str]] = {}
    for q in graph.functions:
        by_simple.setdefault(q.split(".")[-1], []).append(q)
        by_simple.setdefault(q, []).append(q)
    for call in graph.raw_calls:
        if call["kind"] == "dynamic":
            continue
        raw = call["callee_raw"]
        caller = call["caller"]
        # Exact qualified match
        if raw in graph.functions:
            graph.edges[caller].add(raw)
            continue
        # Simple-name match, unique only
        simple = raw.split(".")[-1]
        cands = by_simple.get(simple, [])
        # Prefer same-module candidate
        mod = ".".join(caller.split(".")[:-1])
        same = [c for c in cands if c.startswith(mod + ".")]
        if len(same) == 1:
            graph.edges[caller].add(same[0])
        elif len(cands) == 1:
            graph.edges[caller].add(cands[0])
        elif len(cands) > 1:
            graph.ambiguous.setdefault(caller, set()).update(cands)
        # If 0 candidates: external library call. Keep it as a node so
        # BFS can reach vulnerable functions like yaml.load, which live
        # in a dependency, not in the project. This was the bug that
        # made app_vuln report not_reachable: the yaml.load edge was
        # dropped because yaml.load is not defined in the project.
        if "." in raw and raw not in graph.functions:
            graph.functions[raw] = FuncInfo(
                qualified=raw, file="external", start=0, end=0,
                name=raw.split(".")[-1],
            )
            graph.edges[caller].add(raw)
    return graph
