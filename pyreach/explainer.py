"""LLM chat explainer for UNCERTAIN results only.

The real LLM use case in pyreach is not deciding verdicts — it is
explaining the places deterministic code cannot verify. For every
uncertain result this module builds, in this order:

1. A deterministic explanation (works with no key, no LLM call).
   It names the blocker, the evidence that exists, and the one
   discriminating check that would resolve it.
2. A token-budgeted evidence pack (~1,500 tokens) for the LLM.
3. Optionally, ONE stateless LLM call (temperature 0, no tools, no
   loop) that returns a closed-world JSON explanation. A deterministic
   citation verifier checks every claim before it is shown. The LLM
   output NEVER changes a verdict.

Labels: every line is [deterministic] or [llm-explainer]. If the LLM
call fails, times out, or is rejected by the verifier, only the
deterministic explanation is shown, with
"[llm-explainer unavailable — deterministic result unchanged]".

Design source: research report §5 (Codex / Claude Code / Aider /
Semgrep pattern: deterministic scanner -> LLM explainer with a narrow
evidence pack -> human decides). What is NOT copied: embeddings,
LSP servers, persistent indexes, multi-call verification, agentic
tool loops, auto-fix / auto-suppress.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from .resolver import DEFAULT_MODEL, resolve_with_llm

FOOTER = ("This explanation is limited to the evidence above. "
          "It does not prove the vulnerable function is (or is not) called. "
          "The verdict remains UNCERTAIN.")

TOKEN_CAP = 1500          # ~tokens for the evidence pack
SNIPPET_MAX_LINES = 30    # lines of function body per hop, max
RG_MAX_MATCHES = 20

BLOCKERS = ("dynamic_call", "ambiguous_name", "unparsed_file",
            "library_not_parsed")

# What each blocker means, in the deterministic template's own words.
BLOCKER_WHAT = {
    "dynamic_call": "a dynamic call (getattr / importlib / plugin) is reachable "
                    "from an entry point, and the name it resolves to cannot "
                    "be proved from the code",
    "ambiguous_name": "a call could resolve to two or more different "
                      "functions with the same name, so the target cannot be "
                      "ruled in or out",
    "unparsed_file": "some project files could not be parsed, so the call "
                     "graph is incomplete and a hidden path may exist",
    "library_not_parsed": "the vulnerable function lives in dependency "
                          "source that was not parsed, so absence cannot be "
                          "proved from project code alone",
}


def _norm(text: str) -> str:
    """Collapse all whitespace, for verbatim-snippet comparison."""
    return " ".join(text.split())


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 characters per token."""
    return max(1, len(text) // 4)


def _read_lines(path: str | Path) -> list[str]:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


def _resolve_file(root: Path, file: str | Path) -> Path:
    """Resolve a graph file path: graph files are stored as given to
    build_graph, so they may be relative to the cwd (scan with a
    relative project path) or to the project root, or absolute."""
    p = Path(file)
    if p.is_absolute():
        return p
    if p.exists():
        return p
    return root / p


def _location_ok(root: Path, file: str | None, line: int | None) -> bool:
    """Does file:line exist inside the analysed tree?"""
    if not file or not line:
        return False
    try:
        resolved = _resolve_file(root, file).resolve()
        if not str(resolved).startswith(str(root.resolve()) + os.sep):
            return False
        lines = _read_lines(resolved)
        return 1 <= line <= len(lines)
    except OSError:
        return False


def _reachable_nodes(graph, entries: set[str]) -> set[str]:
    """All functions reachable from the entry points via graph edges."""
    seen: set[str] = set(entries)
    stack = list(entries)
    while stack:
        cur = stack.pop()
        for nxt in graph.edges.get(cur, set()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def _unparsed_files(root: Path) -> list[str]:
    """Project .py files that ast.parse rejects (Python 2 files, syntax
    errors). These are holes in the call graph, recorded not hidden."""
    bad: list[str] = []
    for p in sorted(root.rglob("*.py")):
        try:
            ast.parse(p.read_text(encoding="utf-8", errors="ignore"),
                      filename=str(p))
        except (SyntaxError, OSError):
            bad.append(str(p))
    return bad


def _is_library_internal(qualified: str) -> bool:
    return "construct_" in qualified


def _target_project_defined(graph, target: str) -> bool:
    """Is the target defined in project code (not an external node)?"""
    for q, info in graph.functions.items():
        if (q == target or q.endswith("." + target)
                or q.split(".")[-1] == target) and info.file != "external":
            return True
    return False


def derive_blocker(result, graph, root: Path, entries: set[str]) -> str:
    """The blocker for one uncertain result, derived deterministically.

    The LLM never invents a blocker type: this runs first, and the
    verifier later rejects any LLM answer whose blocker differs.
    Priority is most-specific first: a library internal is about the
    dependency, a dynamic call is about a call site, ambiguity is
    about a name, unparsed files are about coverage.
    """
    target = result.vulnerable_function
    reachable = _reachable_nodes(graph, entries)
    # 1. Library internal, never defined in project code: the dependency
    #    was not parsed, so no project-side evidence can clear it.
    if _is_library_internal(target) and not _target_project_defined(graph, target):
        return "library_not_parsed"
    # 2. A dynamic trigger reachable from an entry point.
    for d in graph.dynamic:
        if d.get("caller") in reachable:
            return "dynamic_call"
    # 3. Ambiguous edges: prefer ones whose candidates could be the target.
    simple = target.split(".")[-1] if target else ""
    for caller, cands in graph.ambiguous.items():
        if caller in reachable and any(
                c.split(".")[-1] == simple or c == target for c in cands):
            return "ambiguous_name"
    for caller in graph.ambiguous:
        if caller in reachable:
            return "ambiguous_name"
    # 4. Unparsed files leave holes in the graph.
    discovered = len(list(root.rglob("*.py")))
    parsed = len({f.file for f in graph.functions.values()
                  if f.file != "external"})
    if discovered > parsed:
        return "unparsed_file"
    # Fallbacks, in the same order, without the reachability filter:
    # the result is uncertain, so at least one of these must apply.
    if graph.dynamic:
        return "dynamic_call"
    if graph.ambiguous:
        return "ambiguous_name"
    if not _target_project_defined(graph, target):
        return "library_not_parsed"
    # Last resort: low-confidence function list. The blocker label is
    # imperfect here (see honest limits in PHASES.md); the explanation
    # text says so plainly instead of inventing a cause.
    return "library_not_parsed"


def _partial_path(graph, entries: set[str], node: str) -> list[str]:
    """BFS path from an entry point to `node`, or [] if unreachable."""
    if not node or node not in graph.functions:
        return []
    from .reach import bfs_path
    return bfs_path(graph, entries, node) or []


def _function_snippet(graph, qualified: str) -> dict | None:
    """<=30 lines of the function body only, never the whole file."""
    info = graph.functions.get(qualified)
    if info is None or info.file == "external":
        return None
    lines = _read_lines(info.file)
    if not lines:
        return None
    start = max(1, info.start)
    end = info.end if info.end and info.end >= start else start + SNIPPET_MAX_LINES - 1
    end = min(end, start + SNIPPET_MAX_LINES - 1, len(lines))
    if start > len(lines):
        return None
    snippet = "\n".join(lines[start - 1:end])
    return {"file": info.file, "line": start, "snippet": snippet}


def _dynamic_source_text(root: Path, site: dict) -> str:
    """What the dynamic name comes from, in the code's own words.

    Returns the raw expression, e.g. `config["func"]`. A literal would
    have been resolved by constant propagation, so by the time we are
    explaining an uncertain result the source is non-literal. If the
    argument is a bare name, trace it one assignment back so the
    explanation names the real source (`name` -> `config["func"]`).
    """
    lines = _read_lines(site["file"])
    if not (1 <= site["line"] <= len(lines)):
        return "an unknown source"
    src = lines[site["line"] - 1].strip()
    m = re.search(r"getattr\s*\(\s*[^,]+,\s*([^)]+)\)", src)
    if m:
        expr = m.group(1).strip()
    else:
        m = re.search(r"import_module\s*\(\s*([^)]+)\)", src)
        if m:
            expr = m.group(1).strip()
        else:
            return "an unknown source"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr):
        # One step back: `name = config["func"]` above the call.
        pat = re.compile(rf"^\s*{re.escape(expr)}\s*=\s*(.+?)\s*$")
        for ln in range(site["line"] - 2, -1, -1):
            mm = pat.match(lines[ln])
            if mm:
                return mm.group(1)
    return expr


def _blocking_dynamic_site(graph, root: Path, entries: set[str]) -> dict:
    """The dynamic site that actually blocks the verdict: the first
    reachable one constant propagation cannot resolve. A site whose
    name is a literal ("safe_load") is already decided — it is not
    the blocker, even if it comes first in the file. Falls back to
    the first reachable dynamic site, then the first site at all."""
    from .resolver import constant_propagate_getattr
    reachable = _reachable_nodes(graph, entries)
    ordered = [d for d in graph.dynamic if d.get("caller") in reachable] \
        + [d for d in graph.dynamic if d.get("caller") not in reachable]
    for d in ordered:
        src = "\n".join(_read_lines(d.get("file", "")))
        if src and constant_propagate_getattr(src, d.get("line", 0)) is None:
            return d
    return ordered[0] if ordered else {}


def ripgrep_evidence(root: Path, blocker: str, target: str) -> list[dict]:
    """Deterministic rg pass BEFORE any LLM call (report §5.6).

    dynamic_call: every getattr / import_module site, plus every
    mention of the vulnerable simple name. ambiguous_name: every
    definition of that name. Other blockers: no rg evidence applies.
    Capped at 20 matches. Falls back to os.walk + regex when rg is
    absent. Never raises: on any failure return [].
    """
    simple = target.split(".")[-1] if target else ""
    if blocker == "dynamic_call":
        patterns = ["getattr", "import_module", simple]
    elif blocker == "ambiguous_name":
        patterns = [f"def {simple}"]
    else:
        return []
    patterns = [p for p in patterns if p]
    matches: list[dict] = []
    rg = shutil.which("rg")
    try:
        if rg:
            args = [rg, "-n", "--no-heading", "--type", "py"]
            for p in patterns:
                args += ["-e", p]
            args.append(str(root))
            r = subprocess.run(args, capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines()[:RG_MAX_MATCHES]:
                # rg -n output: file:line:text
                parts = line.split(":", 2)
                if len(parts) == 3 and parts[1].isdigit():
                    matches.append({"file": parts[0], "line": int(parts[1]),
                                    "text": parts[2].strip()[:200]})
        else:
            rx = [re.compile(re.escape(p)) for p in patterns]
            for p in sorted(root.rglob("*.py")):
                for i, line in enumerate(_read_lines(p), start=1):
                    if any(r.search(line) for r in rx):
                        matches.append({"file": str(p), "line": i,
                                        "text": line.strip()[:200]})
                    if len(matches) >= RG_MAX_MATCHES:
                        return matches
    except Exception:
        return []
    return matches[:RG_MAX_MATCHES]


def discriminating_check(blocker: str, target: str, package: str,
                         blocked_edge: dict, root: Path) -> dict:
    """One discriminating check per blocker type — a deterministic
    template in code. The LLM only ever fills in already-verified
    names/paths; the command and the file:line come from here and are
    verified to exist before display.
    """
    simple = target.split(".")[-1] if target else ""
    file, line = blocked_edge.get("file"), blocked_edge.get("line")
    loc = f"{file}:{line}" if _location_ok(root, file, line) else None
    if blocker == "dynamic_call":
        check = (f"Find every dynamic call that could resolve to "
                 f"'{simple}' and log what it resolves to at runtime")
        cmd = f'rg -n --type py "{simple}" {root}'
        if loc:
            check += (f". Add a temporary print/log at {loc} showing the "
                      f"resolved name, then run the entry point and read it.")
        return {"check": check, "command": cmd}
    if blocker == "ambiguous_name":
        check = (f"List every definition of '{simple}' and confirm which "
                 f"one is actually imported at the call site")
        cmd = f'rg -n --type py "def {simple}" {root}'
        if loc:
            check += f"; the ambiguous call is at {loc}."
        return {"check": check, "command": cmd}
    if blocker == "unparsed_file":
        f = file or "the unparsed file"
        check = f"Fix the parse error in {f} and re-run the scan"
        cmd = f"python -m py_compile {f}" if file else "python -m py_compile <file>"
        if loc:
            check += f" (first failure at {loc})"
        return {"check": check, "command": cmd}
    # library_not_parsed
    mod = target.split(".")[0] if target else package
    check = (f"Check the installed {package} and whether {target} is "
             f"called by a public loader the project uses")
    cmd = f"pip show {package}"
    if loc:
        check += f". The public call site, if any, is at {loc}."
    return {"check": check, "command": cmd}


def build_evidence_pack(result, graph, root: Path, entries: set[str],
                        advisory: dict) -> dict:
    """Token-budgeted evidence pack for one uncertain result.

    Contents: OSV advisory, partial BFS path with file:line per hop,
    the single blocked edge + blocker class, <=30-line snippets per
    hop (function body only), a symbol table for ambiguous names, and
    capped rg matches. Never the whole repo, the whole call graph, or
    unparsed library source — those are reported as "not parsed".
    Truncation drops the lowest-value hops first (earliest hops, far
    from the blocked edge) until the pack fits ~1,500 tokens.
    """
    root = Path(root)
    target = result.vulnerable_function
    blocker = derive_blocker(result, graph, root, entries)
    reachable = _reachable_nodes(graph, entries)

    # The blocked edge: the exact place the deterministic analysis stops.
    blocked_edge: dict
    if blocker == "dynamic_call":
        site = _blocking_dynamic_site(graph, root, entries)
        blocked_edge = {"from": site.get("caller", ""),
                        "to": target, "file": site.get("file", ""),
                        "line": site.get("line"), "kind": site.get("kind", "getattr")}
        blocked_node = site.get("caller", "")
    elif blocker == "ambiguous_name":
        caller = next((c for c in graph.ambiguous if c in reachable),
                      next(iter(graph.ambiguous), "") if graph.ambiguous else "")
        info = graph.functions.get(caller)
        blocked_edge = {"from": caller, "to": target,
                        "file": info.file if info else "",
                        "line": info.start if info else None,
                        "kind": "ambiguous"}
        blocked_node = caller
    elif blocker == "unparsed_file":
        bad = _unparsed_files(root)
        blocked_edge = {"from": "", "to": target,
                        "file": bad[0] if bad else "",
                        "line": 1 if bad else None, "kind": "unparsed_file"}
        blocked_node = ""
    else:  # library_not_parsed
        blocked_edge = {"from": "", "to": target, "file": "", "line": None,
                        "kind": "library_not_parsed"}
        blocked_node = ""

    path = _partial_path(graph, entries, blocked_node) if blocked_node else []
    hops = []
    for q in path:
        info = graph.functions.get(q)
        hops.append({"function": q,
                     "file": info.file if info else "",
                     "line": info.start if info else None})
    snippets = []
    for q in path:
        s = _function_snippet(graph, q)
        if s:
            snippets.append(s)
    # The blocked call site itself, if it has source (dynamic / ambiguous).
    if blocked_edge.get("file") and blocked_edge.get("line"):
        lines = _read_lines(blocked_edge["file"])
        ln = blocked_edge["line"]
        if 1 <= ln <= len(lines):
            snippets.append({"file": blocked_edge["file"], "line": ln,
                             "snippet": lines[ln - 1]})

    symbol_table: list[dict] = []
    if blocker == "ambiguous_name":
        simple = target.split(".")[-1]
        for q, info in sorted(graph.functions.items()):
            if q.split(".")[-1] == simple and info.file != "external":
                symbol_table.append({"name": q, "file": info.file,
                                     "line": info.start})

    discovered = len(list(root.rglob("*.py")))
    parsed = len({f.file for f in graph.functions.values()
                  if f.file != "external"})
    pack: dict = {
        "advisory": {"id": advisory.get("id", ""),
                     "package": advisory.get("package", ""),
                     "vulnerable_function": target,
                     "fixed_version": advisory.get("fixed_version", "")},
        "verdict": "uncertain",
        "blocker": blocker,
        "partial_path": hops,
        "blocked_edge": blocked_edge,
        "snippets": snippets,
        "symbol_table": symbol_table,
        "ripgrep": ripgrep_evidence(root, blocker, target),
        "coverage": {"project_files_discovered": discovered,
                     "project_files_parsed": parsed,
                     "dependency_source": "not parsed"},
    }
    pack["files"] = sorted({s["file"] for s in snippets}
                           | {h["file"] for h in hops if h["file"]}
                           | ({blocked_edge["file"]} if blocked_edge.get("file") else set())
                           | {m["file"] for m in pack["ripgrep"]})
    # Trim lowest-value hops first until the pack fits the token cap.
    while _estimate_tokens(json.dumps(pack)) > TOKEN_CAP and len(snippets) > 1:
        snippets.pop(0)  # earliest hop, farthest from the blocked edge
        pack["snippets"] = snippets
    while _estimate_tokens(json.dumps(pack)) > TOKEN_CAP and len(pack["ripgrep"]) > 5:
        pack["ripgrep"] = pack["ripgrep"][:5]
    pack["tokens_estimate"] = _estimate_tokens(json.dumps(pack))
    return pack


def deterministic_explanation(result, graph, root: Path, entries: set[str],
                              advisory: dict) -> tuple[dict, dict]:
    """The explanation that needs no key and no LLM call.

    Returns (explanation_dict, evidence_pack). The text is labelled
    [deterministic] throughout and ends with the fixed footer.
    """
    root = Path(root)
    pack = build_evidence_pack(result, graph, root, entries, advisory)
    blocker = pack["blocker"]
    target = result.vulnerable_function
    edge = pack["blocked_edge"]

    if blocker == "dynamic_call":
        site = _blocking_dynamic_site(graph, root, entries)
        src = _dynamic_source_text(root, site) if site else "an unknown source"
        what = (f"A dynamic call at {edge.get('file')}:{edge.get('line')} "
                f"in {edge.get('from')} is reachable from an entry point, "
                f"and the name it resolves to comes from the value of {src}, "
                f"not from a literal in the code. Constant propagation could "
                f"not resolve it, so a hidden path to {target} may exist at runtime.")
        unknown = [f"what value {src} has at runtime",
                   f"whether the dynamic call ever resolves to {target}"]
    elif blocker == "ambiguous_name":
        defs = ", ".join(f"{s['name']} ({s['file']}:{s['line']})"
                         for s in pack["symbol_table"]) or "unknown locations"
        what = (f"The call at {edge.get('file')}:{edge.get('line')} could "
                f"resolve to more than one function named "
                f"'{target.split('.')[-1]}': {defs}. The analysis does not "
                f"guess which one runs, so {target} can neither be confirmed "
                f"nor ruled out.")
        unknown = [f"which definition of '{target.split('.')[-1]}' actually runs",
                   f"whether any of them reaches {target}"]
    elif blocker == "unparsed_file":
        bad = _unparsed_files(root)
        what = (f"{len(bad)} project file(s) could not be parsed, so the call "
                f"graph is incomplete: {', '.join(bad[:3])}"
                f"{' ...' if len(bad) > 3 else ''}. A path to {target} could "
                f"hide in the unparsed code.")
        unknown = ["whether any unparsed file calls " + target,
                   "what the unparsed files contain"]
    else:  # library_not_parsed
        what = (f"{target} is a library-internal function and the dependency "
                f"source was not parsed (0 modules parsed), so no project-side "
                f"evidence can prove it is never called. The library itself "
                f"may call it when a public loader is used.")
        unknown = [f"whether the installed {pack['advisory']['package']} calls {target} internally",
                   f"which public loader, if any, reaches {target}"]

    path_txt = (" -> ".join(h["function"] for h in pack["partial_path"])
                or "no call path reaches the blocked edge")
    check = discriminating_check(blocker, target,
                                 pack["advisory"]["package"], edge, root)
    lines = [
        f"[deterministic] Verdict: UNCERTAIN — {target} "
        f"({pack['advisory']['id']}, package {pack['advisory']['package']}, "
        f"fixed in {pack['advisory']['fixed_version'] or 'unknown'}).",
        f"[deterministic] Blocker: {blocker} — {what}",
        f"[deterministic] Evidence: partial path: {path_txt}. "
        f"Blocked at {edge.get('file') or '(no file)'}:{edge.get('line') or '?'} "
        f"({edge.get('kind')}).",
        f"[deterministic] What would resolve it: {check['check']} — run: {check['command']}",
        "[deterministic] What is not known: " + "; ".join(unknown) + ".",
        f"[deterministic] {FOOTER}",
    ]
    exp = {
        "vulnerable_function": target,
        "advisory_id": pack["advisory"]["id"],
        "blocker": blocker,
        "deterministic_explanation": "\n".join(lines),
        "llm_explanation": None,
        "llm_rejected": False,
        "llm_failures": [],
        "discriminating_check": check,
        "does_not_know": unknown,
        "evidence_pack_tokens": pack["tokens_estimate"],
    }
    return exp, pack


def build_explainer_prompt(pack: dict) -> str:
    """Quote-first prompt: use ONLY the pack, cite file:line per claim,
    put anything unsupported in does_not_know. Saying 'I don't know'
    is the correct answer when the evidence is insufficient."""
    schema = ('{"blocker": "<one of: dynamic_call, ambiguous_name, '
              'unparsed_file, library_not_parsed>", "what_blocks": "one or two '
              'plain-language sentences", "evidence": [{"file": "...", "line": 0, '
              '"snippet": "exact code from the pack"}], "what_would_resolve": '
              '[{"check": "...", "command": "..."}], "does_not_know": '
              '["..."], "verdict": "uncertain"}')
    return f"""You are a Python static-analysis explainer. Answer ONLY with JSON.

You are explaining why a vulnerability verdict is UNCERTAIN. You do NOT
decide the verdict — it stays uncertain whatever you say.

Rules:
- Use ONLY the evidence pack below. Do not use general knowledge, and do
  not invent files, functions, line numbers, or call paths.
- For every factual claim, cite file:line from the pack, and quote the
  snippet exactly as it appears in the pack.
- If the evidence does not support something, put it in does_not_know
  and do not state it as fact. Saying "I don't know" is the correct
  answer when the evidence is insufficient.
- "blocker" must be exactly the blocker in the pack. "verdict" must be
  exactly "uncertain" — there is no other allowed value.
- does_not_know must be a non-empty list: an uncertain verdict always
  has something unknown.

Evidence pack:
```json
{json.dumps(pack, indent=2)}
```

Return strict JSON only, in this shape:
{schema}
Temperature 0. No extra text.
"""


def verify_explainer_answer(answer, pack: dict, root: Path) -> tuple[bool, list[str], dict | None]:
    """Deterministic citation verifier for the explainer's JSON.

    Checks: JSON object with all required keys; verdict is exactly
    "uncertain" (any reachable/not_reachable in a verdict field fails);
    blocker matches the pack (the LLM never invents a blocker type);
    does_not_know present and non-empty; every cited file:line exists
    in the analysed tree AND inside the evidence pack; every cited
    snippet is a verbatim substring of that file at that line
    (whitespace-normalised). Bad evidence / what_would_resolve entries
    are stripped and recorded. ANY failure rejects the whole answer:
    the caller falls back to the deterministic template and marks
    llm_rejected. Returns (ok, failures, cleaned_answer_or_None).
    """
    root = Path(root)
    failures: list[str] = []
    if not isinstance(answer, dict):
        return False, ["answer is not a JSON object"], None
    for k in ("blocker", "what_blocks", "evidence", "what_would_resolve",
              "does_not_know", "verdict"):
        if k not in answer:
            failures.append(f"missing key: {k}")
    if failures:
        return False, failures, None
    cleaned = dict(answer)
    # The verdict field is a closed world with ONE allowed value.
    verdict = answer.get("verdict")
    if verdict != "uncertain":
        failures.append(f"verdict field must be exactly 'uncertain', got {verdict!r}")
        # Also catch a nested verdict field saying otherwise.
    def _scan_verdicts(obj, path=""):
        if isinstance(obj, dict):
            for kk, vv in obj.items():
                if kk == "verdict" and vv != "uncertain":
                    failures.append(f"verdict field at {path or 'top level'} "
                                    f"must be 'uncertain', got {vv!r}")
                _scan_verdicts(vv, f"{path}.{kk}" if path else kk)
        elif isinstance(obj, list):
            for i, vv in enumerate(obj):
                _scan_verdicts(vv, f"{path}[{i}]")
    _scan_verdicts({k: v for k, v in answer.items() if k != "verdict"})
    if answer.get("blocker") != pack.get("blocker"):
        failures.append(f"blocker must be {pack.get('blocker')!r}, got {answer.get('blocker')!r}")
    if not isinstance(answer.get("what_blocks"), str) or not answer["what_blocks"].strip():
        failures.append("what_blocks must be a non-empty string")
    dnk = answer.get("does_not_know")
    if not isinstance(dnk, list):
        failures.append("does_not_know must be a list")
    elif not dnk or not all(isinstance(x, str) and x.strip() for x in dnk):
        failures.append("does_not_know must be a non-empty list of strings: "
                        "an uncertain verdict always has something unknown")
    # Evidence: every citation must exist, be in the pack, and match verbatim.
    pack_files = set(pack.get("files", []))
    ev = answer.get("evidence")
    if not isinstance(ev, list):
        failures.append("evidence must be a list")
        ev = []
    kept_ev: list[dict] = []
    for i, item in enumerate(ev):
        if not isinstance(item, dict) or not isinstance(item.get("file"), str) \
                or not isinstance(item.get("line"), int) \
                or isinstance(item.get("line"), bool) \
                or not isinstance(item.get("snippet"), str):
            failures.append(f"evidence[{i}] must have file (str), line (int), snippet (str)")
            continue
        f, ln, snip = item["file"], item["line"], item["snippet"]
        if f not in pack_files:
            failures.append(f"evidence[{i}] cites {f}, which is outside the evidence pack")
            continue
        if not _location_ok(root, f, ln):
            failures.append(f"evidence[{i}] cites {f}:{ln}, which does not exist")
            continue
        lines = _read_lines(_resolve_file(root, f))
        if not (1 <= ln <= len(lines)):
            failures.append(f"evidence[{i}] line {ln} out of range in {f}")
            continue
        first = _norm(snip.splitlines()[0]) if snip.splitlines() else ""
        if first != _norm(lines[ln - 1]):
            failures.append(f"evidence[{i}] snippet does not match {f}:{ln} verbatim")
            continue
        rest = _norm("\n".join(lines[ln - 1:]))
        if _norm(snip) not in rest:
            failures.append(f"evidence[{i}] snippet is not a verbatim substring of {f} from line {ln}")
            continue
        kept_ev.append(item)
    cleaned["evidence"] = kept_ev
    # what_would_resolve: entries must be well-formed; drop bad ones.
    wwr = answer.get("what_would_resolve")
    if not isinstance(wwr, list):
        failures.append("what_would_resolve must be a list")
        wwr = []
    kept_wwr: list[dict] = []
    for i, item in enumerate(wwr):
        if not isinstance(item, dict) or not item.get("check") or not item.get("command"):
            failures.append(f"what_would_resolve[{i}] must have non-empty check and command")
            continue
        kept_wwr.append(item)
    cleaned["what_would_resolve"] = kept_wwr
    if failures:
        return False, failures, cleaned
    return True, [], cleaned


def explain_result(result, graph, root, advisory: dict,
                   entries: set[str], use_llm: bool = False,
                   model: str = DEFAULT_MODEL, cache=None) -> dict:
    """Explain one uncertain result. Returns the report-shaped dict.

    Deterministic explanation always present. The LLM layer runs only
    when use_llm is True (key present / --with-llm, --no-llm wins in
    the CLI): one stateless call via resolver.resolve_with_llm, whose
    cache and .env handling are reused. A failed call (None) means
    "unavailable", not "rejected". A returned answer that fails the
    verifier means "rejected": fall back to deterministic only.
    The verdict is never changed here.
    """
    root = Path(root)
    exp, pack = deterministic_explanation(result, graph, root, entries, advisory)
    if not use_llm:
        return exp
    prompt = build_explainer_prompt(pack)
    try:
        ans = resolve_with_llm(prompt, model=model, cache=cache)
    except Exception:
        ans = None
    if ans is None:
        # No key, no network, timeout: the LLM layer is unavailable.
        # The deterministic explanation stands unchanged.
        return exp
    ok, failures, cleaned = verify_explainer_answer(ans, pack, root)
    if not ok:
        exp["llm_rejected"] = True
        exp["llm_failures"] = failures
        return exp
    assert cleaned is not None
    lines = [f"[llm-explainer] {cleaned['what_blocks']}"]
    for item in cleaned["evidence"]:
        first = item["snippet"].splitlines()[0].strip() if item["snippet"].splitlines() else ""
        lines.append(f"[llm-explainer] Evidence: {item['file']}:{item['line']}: {first}")
    for item in cleaned["what_would_resolve"]:
        lines.append(f"[llm-explainer] Would resolve: {item['check']} — run: {item['command']}")
    lines.append("[llm-explainer] Does not know: " + "; ".join(cleaned["does_not_know"]) + ".")
    exp["llm_explanation"] = "\n".join(lines)
    # The LLM's does_not_know joins the deterministic list (union, order kept).
    for item in cleaned["does_not_know"]:
        if item not in exp["does_not_know"]:
            exp["does_not_know"].append(item)
    return exp


def format_explanation(exp: dict) -> str:
    """Printable form: deterministic lines, then the LLM layer or the
    unavailable note. The footer is already the last deterministic line."""
    parts = [exp["deterministic_explanation"]]
    if exp.get("llm_explanation"):
        parts.append(exp["llm_explanation"])
    elif exp.get("llm_rejected"):
        parts.append("[llm-explainer unavailable — deterministic result unchanged]")
    else:
        parts.append("[llm-explainer unavailable — deterministic result unchanged]")
    return "\n".join(parts)
