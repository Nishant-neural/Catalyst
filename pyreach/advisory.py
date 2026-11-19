"""Phase 1: Advisory -> vulnerable functions, from the fix commit.

Rule: the fix commit changes the vulnerable code. Map its changed
lines to functions with AST. Never guess a function name from prose alone.
If we cannot find a clean fix, confidence is LOW and the verdict later
becomes UNCERTAIN, never NOT-REACHABLE.
"""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field

DOTTED_NAME = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+)\b")


@dataclass
class VulnerableFunction:
    qualified: str  # e.g. yaml.loader.Loader.load
    file: str
    confidence: str  # high | medium | low
    evidence: str  # commit SHA / diff hunk


@dataclass
class Advisory:
    id: str  # OSV-2024-xxxx or GHSA-xxxx
    package: str
    vulnerable_versions: str = ""
    fixed_version: str = ""
    fix_commit: str = ""
    references: list[str] = field(default_factory=list)
    summary: str = ""
    vulnerable_functions: list[VulnerableFunction] = field(default_factory=list)


def load_advisories(path: str) -> list[Advisory]:
    """Load advisories from OSV-style JSON.

    Accepts either {"results": [...]} or a plain list, and either
    OSV fields or our simplified fields in examples/advisory-sample.json.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    items = data.get("results", data) if isinstance(data, dict) else data
    out: list[Advisory] = []
    for item in items:
        refs = []
        for r in item.get("references", []) or []:
            refs.append(r.get("url", r) if isinstance(r, dict) else str(r))
        # OSV affected -> package + ranges, simplified here
        pkg = item.get("package", "")
        if not pkg and item.get("affected"):
            pkg = item["affected"][0].get("package", {}).get("name", "")
        funcs = []
        for fn in item.get("vulnerable_functions", []) or []:
            if isinstance(fn, dict):
                funcs.append(VulnerableFunction(
                    qualified=fn.get("qualified", fn.get("name", "")),
                    file=fn.get("file", ""),
                    confidence=fn.get("confidence", "medium"),
                    evidence=fn.get("evidence", "advisory"),
                ))
            else:
                funcs.append(VulnerableFunction(str(fn), "", "medium", "advisory"))
        fc = item.get("fix_commit", "")
        if isinstance(fc, dict):
            fc = fc.get("sha", "") or fc.get("via", "")
        out.append(Advisory(
            id=item.get("id", item.get("vulnerability_id", "UNKNOWN")),
            package=pkg,
            vulnerable_versions=str(item.get("vulnerable_versions", "")),
            fixed_version=str(item.get("fixed_version", "")),
            fix_commit=fc,
            references=refs,
            summary=item.get("summary", item.get("description", "")),
            vulnerable_functions=funcs,
        ))
    return out


def functions_in_source(source: str, module: str) -> list[tuple[str, int, int]]:
    """Return [(qualified_name, start_line, end_line)] for a source file."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    out: list[tuple[str, int, int]] = []

    def visit(node, prefix: str):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}{child.name}" if prefix else child.name
                full = f"{module}.{q}" if module else q
                out.append((full, child.lineno, getattr(child, "end_lineno", child.lineno)))
                visit(child, f"{q}.")
            elif isinstance(child, ast.ClassDef):
                q = f"{prefix}{child.name}" if prefix else child.name
                visit(child, f"{q}.")
            else:
                visit(child, prefix)

    visit(tree, "")
    return out


def parse_unified_diff(diff_text: str) -> dict[str, set[int]]:
    """Parse a unified diff -> {file_path: set(new_file_line_numbers)}.

    Only '+' lines count, '+++' header excluded. Hunk headers @@ -a,b +c,d @@
    give the starting new line number.
    """
    changed: dict[str, set[int]] = {}
    cur_file: str | None = None
    new_line = 0
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            cur_file = line[4:].strip()
            if cur_file.startswith("b/"):
                cur_file = cur_file[2:]
            changed.setdefault(cur_file, set())
            continue
        if line.startswith("@@ "):
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if m:
                new_line = int(m.group(1))
            continue
        if cur_file is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            changed[cur_file].add(new_line)
            new_line += 1
        elif line.startswith("-"):
            pass  # deleted line has no new-file number
        else:
            new_line += 1
    return changed


def parse_unified_diff_both(diff_text: str) -> tuple[dict[str, set[int]], dict[str, set[int]]]:
    """Return (new_changed, old_changed). Deleted lines belong to the
    OLD version — mapping only the fixed file can miss the removed
    function. ChatGPT fix: consider both sides of the diff.
    """
    new_changed: dict[str, set[int]] = {}
    old_changed: dict[str, set[int]] = {}
    cur_file: str | None = None
    new_line = old_line = 0
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            cur_file = line[4:].strip().removeprefix("b/")
            new_changed.setdefault(cur_file, set())
            old_changed.setdefault(cur_file, set())
            continue
        if line.startswith("@@ "):
            m = re.search(r"-(\d+)(?:,(\d+))? \+(\d+)", line)
            if m:
                old_line, new_line = int(m.group(1)), int(m.group(3))
            continue
        if cur_file is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            new_changed[cur_file].add(new_line)
            new_line += 1
        elif line.startswith("-"):
            old_changed[cur_file].add(old_line)
            old_line += 1
        else:
            new_line += 1
            old_line += 1
    return new_changed, old_changed


def _module_from_path(path: str) -> str:
    """Repo path -> importable module name. Repos often keep code under
    src/ (jinja2, werkzeug, anyio, urllib3) or lib/ (PyYAML); the
    installed package has no such prefix, so strip one leading
    src/lib/lib3 segment — otherwise the candidate's first segment
    never matches an imported module and the public/internal
    classification breaks (19 Nov 2026: src.werkzeug.security.safe_join
    was treated as library-internal even though Flask imports werkzeug,
    and propagation could not link src.jinja2.* to jinja2.*)."""
    mod = path.replace("/", ".").removesuffix(".py")
    for prefix in ("src.", "lib.", "lib3."):
        if mod.startswith(prefix):
            mod = mod[len(prefix):]
            break
    # pkg/__init__.py is the module pkg, not pkg.__init__.
    if mod.endswith(".__init__"):
        mod = mod[: -len(".__init__")]
    return mod


def diff_to_functions(diff_text: str, sources: dict[str, str],
                      commit: str = "", old_sources: dict[str, str] | None = None) -> list[VulnerableFunction]:
    """Map a fix-commit diff to vulnerable functions.

    sources: {file_path: source_text_of_fixed_version}
    old_sources: {file_path: source_text_of_vulnerable_version}, optional.
      If given, deleted lines are mapped on the OLD AST too.
    Confidence: 1-2 functions -> high, 3-5 -> medium, >5 or 0 -> low.
    Test files are ignored.

    ChatGPT fix: this is CANDIDATE generation, not definitive mapping.
    A fix can add validation in the caller (process()) without changing
    the vulnerable helper itself, or touch helpers / tests / constants.
    Keep all candidates with evidence + confidence, cross-check the
    advisory text, and let low confidence lead to UNCERTAIN.
    """
    changed = parse_unified_diff(diff_text)
    if old_sources:
        _, old_changed = parse_unified_diff_both(diff_text)
        # Merge old-side hits by mapping them through old_sources below.
        # We reuse `changed` for the new side, and handle old side in the loop.
        pass
    else:
        old_changed = {}
    found: list[VulnerableFunction] = []
    for path, lines in changed.items():
        if "/test" in path or path.startswith("test") or path.endswith("_test.py"):
            continue
        src = sources.get(path) or sources.get(path.split("/")[-1], "")
        if not src:
            continue
        module = _module_from_path(path)
        for qualified, start, end in functions_in_source(src, module):
            hit = [ln for ln in lines if start <= ln <= end]
            if hit:
                found.append(VulnerableFunction(
                    qualified=qualified, file=path,
                    confidence="high",
                    evidence=f"{commit}:{path}:{hit[0]}" if commit else f"{path}:{hit[0]}",
                ))
    # Old side: deleted lines mapped on the vulnerable version's AST.
    if old_sources:
        for path, lines in old_changed.items():
            if "/test" in path or path.startswith("test"):
                continue
            src = old_sources.get(path) or old_sources.get(path.split("/")[-1], "")
            if not src:
                continue
            module = _module_from_path(path)
            for qualified, start, end in functions_in_source(src, module):
                hit = [ln for ln in lines if start <= ln <= end]
                if hit:
                    found.append(VulnerableFunction(
                        qualified=qualified, file=path, confidence="high",
                        evidence=f"{commit}:old:{path}:{hit[0]}" if commit else f"old:{path}:{hit[0]}",
                    ))
    # Deduplicate, keep first evidence
    seen: dict[str, VulnerableFunction] = {}
    for fn in found:
        seen.setdefault(fn.qualified, fn)
    uniq = list(seen.values())
    if len(uniq) == 0:
        return []
    if len(uniq) <= 2:
        conf = "high"
    elif len(uniq) <= 5:
        conf = "medium"
    else:
        conf = "low"
    for fn in uniq:
        fn.confidence = conf
    return uniq


def names_from_text(text: str) -> list[str]:
    """Secondary signal only: dotted names mentioned in advisory text."""
    return sorted(set(DOTTED_NAME.findall(text or "")))
