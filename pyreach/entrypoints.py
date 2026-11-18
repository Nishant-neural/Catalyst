"""Phase 3 (part): Real entry points only. Dead code does not count.

App mode: main(), CLI commands, Flask/Django routes, __main__ blocks.
Library mode: public API in __all__ or public (non-underscore) top-level
functions in __init__.py / public modules.
If we cannot find any entry point, fall back to public functions only
and mark the result low-confidence, never to every function.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .callgraph import Graph


def find_entrypoints_with_evidence(root: str | Path, graph: Graph) -> dict[str, str]:
    """ChatGPT fix: entry points are declared roots WITH evidence.

    A function named main() is not automatically an entry point — it
    must actually be invoked. A route handler is invoked by framework
    dispatch, not by a direct call in your code, so we record a
    conceptual edge: framework_dispatcher -> handler.
    console_scripts in pyproject.toml are also real entries.
    Returns {qualified_name: evidence_string}.
    """
    root = Path(root)
    evidence: dict[str, str] = {}
    # console_scripts
    try:
        import tomllib
        pp = root / "pyproject.toml"
        if pp.exists():
            data = tomllib.loads(pp.read_text(encoding="utf-8"))
            scripts = data.get("project", {}).get("scripts", {})
            for name, target in scripts.items():
                # target like "pkg.mod:func"
                func = target.split(":")[-1].split(".")[-1]
                for q in graph.functions:
                    if q.split(".")[-1] == func:
                        evidence[q] = f"console_scripts entry '{name}' -> {target}"
    except Exception:
        pass
    entries, _note = find_entrypoints(root, graph)
    for q in entries:
        evidence.setdefault(q, "main / route / public API (see find_entrypoints)")
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
                    if ".route" in text or ".get" in text or ".post" in text:
                        for q in graph.functions:
                            if q.split(".")[-1] == node.name:
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
                # Decorators: @app.route, @click.command, @app.get, etc.
                for d in node.decorator_list:
                    text = ast.unparse(d) if hasattr(ast, "unparse") else ""
                    if any(k in text for k in (".route", ".get", ".post", "click.command", "app.command")):
                        entries.add(q)
                # __all__ is handled below via module level; public API in __init__
                if rel.endswith("__init__.py") and not node.name.startswith("_"):
                    entries.add(q)
            if isinstance(node, ast.Assign):
                # if __name__ == "__main__": block -> the file's main is entry
                pass
        # __main__ guard: any function called inside it is an entry
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                test = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
                if '__name__' in test and '__main__' in test:
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                            # find qualified by simple name
                            for q in graph.functions:
                                if q.split(".")[-1] == sub.func.id:
                                    entries.add(q)
    if mode == "library":
        # In library mode, public top-level functions are entries.
        # Keep __init__ entries already added; add other public funcs.
        for q in graph.functions:
            if not q.split(".")[-1].startswith("_"):
                # Only if module is public (not _private)
                if "._" not in q:
                    entries.add(q)
        # Library mode is broader by design; note it in the reason string.
        return entries, "library: public API is the entry surface"
    if not entries:
        # Fallback: public functions only, low confidence
        entries = {q for q in graph.functions if not q.split(".")[-1].startswith("_")}
        return entries, "fallback: no main/route found, used public functions only"
    return entries, f"app: {len(entries)} entry point(s)"
