"""CLI: pyreach scan <project> --advisory <json> [options]

Phases 1-5 in one command:
  1. advisory -> vulnerable functions
  2. call graph + BFS reachability
  3. real entry points + JSON + OpenVEX + cache
  4. LLM resolver for uncertain dynamic cases (only with a key)
  5. execution proof for reachable cases + PR comment

Exit 0 = scan completed (even if reachable found).
Exit 2 = reachable vulnerability found (useful for CI).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .advisory import load_advisories
from .callgraph import build_graph
from .cache import Cache
from .completeness import Ledger
from .debate import format_pr_comment
from .entrypoints import find_entrypoints, find_entrypoints_with_evidence
from .proof import run_execution_proof
from .reach import analyze
from .resolver import build_prompt, constant_propagate_getattr, extract_string_literals, resolve_with_llm, verify_answer
from .vex import build_openvex, write_openvex


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="pyreach", description="Which vuln alerts actually affect this Python project?")
    p.add_argument("command", choices=["scan"])
    p.add_argument("project", help="Path to the Python project to scan")
    p.add_argument("--advisory", required=True, help="Advisory JSON (OSV-style, see examples/advisory-sample.json)")
    p.add_argument("--out", default="report.json", help="JSON report output")
    p.add_argument("--vex", default="openvex.json", help="OpenVEX output (only for not_reachable)")
    p.add_argument("--with-llm", action="store_true", help="Run LLM resolver on uncertain cases (needs OPENROUTER_API_KEY)")
    p.add_argument("--with-proof", action="store_true", help="Run execution proof for reachable cases")
    p.add_argument("--cache-dir", default=".reachcache")
    args = p.parse_args(argv)

    root = Path(args.project)
    if not root.exists():
        print(f"error: project not found: {root}", file=sys.stderr)
        return 1

    advisories = load_advisories(args.advisory)
    cache = Cache(args.cache_dir)
    graph = build_graph(root)
    entries, entry_note = find_entrypoints(root, graph)
    print(f"entry points ({entry_note}): {sorted(entries)}")
    print(f"functions: {len(graph.functions)}, edges: {sum(len(v) for v in graph.edges.values())}, dynamic triggers: {len(graph.dynamic)}")

    results = analyze(advisories, graph, entries)

    # Completeness ledger — core, not a write-up item (ChatGPT fix)
    ledger = Ledger(
        project_files_discovered=len(list(root.rglob("*.py"))),
        project_files_parsed=len({f.file for f in graph.functions.values() if f.file != "external"}),
        dynamic_unresolved=len(graph.dynamic),
        ambiguous_edges=sum(len(v) for v in graph.ambiguous.values()),
        entry_points_identified=len(entries),
        vulnerable_targets_high=sum(1 for a in advisories for f in a.vulnerable_functions if f.confidence == "high"),
        vulnerable_targets_low=sum(1 for a in advisories for f in a.vulnerable_functions if f.confidence == "low"),
    )
    evidence = find_entrypoints_with_evidence(root, graph)
    print(f"entry evidence: {evidence}")
    print(f"completeness: {ledger.to_dict()}")

    # Phase 4a: deterministic constant propagation BEFORE any LLM (ChatGPT fix)
    # Simple cases like name="load" do not need a model.
    for r in results:
        if r.verdict != "uncertain" or not graph.dynamic:
            continue
        d = graph.dynamic[0]
        try:
            src = Path(d["file"]).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        vals = constant_propagate_getattr(src, d["line"])
        if vals is None:
            continue  # genuinely unknown, leave for LLM / uncertain
        if r.vulnerable_function.split(".")[-1] in vals:
            r.verdict, r.confidence = "reachable", "high"
            r.reason += f" | constant propagation: getattr can be {vals} (line {d['line']})"
        elif vals:
            r.verdict, r.confidence = "not_reachable", "high"
            r.reason += f" | constant propagation: getattr can only be {vals}, none vulnerable"

    # Phase 4b: LLM resolver, uncertain only
    if args.with_llm:
        for r in results:
            if r.verdict != "uncertain":
                continue
            # Find a dynamic call site in the project (first one, base version)
            if not graph.dynamic:
                continue
            d = graph.dynamic[0]
            src_path = Path(d["file"])
            try:
                src = src_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lines = src.splitlines()
            lo, hi = max(0, d["line"] - 25), min(len(lines), d["line"] + 25)
            snippet = "\n".join(f"{i+1}: {lines[i]}" for i in range(lo, hi))
            prompt = build_prompt(snippet, sorted(graph.functions), extract_string_literals(src),
                                  [r.vulnerable_function], d["file"], d["line"])
            ans = resolve_with_llm(prompt)
            if ans is None:
                print("LLM resolver: no key / no answer, staying uncertain")
                continue
            ok, failures = verify_answer(ans, set(graph.functions), src, "uncertain")
            print(f"LLM resolver for {r.advisory_id}: ok={ok} failures={failures} answer={ans}")
            if not ok:
                continue
            if ans["can_reach"] is True:
                r.verdict, r.confidence = "reachable", "medium"
                r.reason += f" | LLM resolver: {ans['reason']} (verified, lines {ans['evidence_lines']})"
            elif ans["can_reach"] is False:
                r.verdict, r.confidence = "not_reachable", "medium"
                r.reason += f" | LLM resolver: {ans['reason']} (verified, lines {ans['evidence_lines']})"

    # Phase 5: execution proof, reachable only
    proofs = {}
    if args.with_proof:
        for r in results:
            if r.verdict != "reachable" or not r.path:
                continue
            entry_q = r.path[0]
            entry_file = str(Path(graph.functions[entry_q].file).resolve()) if entry_q in graph.functions else ""
            entry_func = entry_q.split(".")[-1]
            if not entry_file:
                continue
            proof = run_execution_proof(str(root), entry_file, entry_func, r.vulnerable_function)
            proofs[r.advisory_id] = proof
            print(f"proof {r.advisory_id}: vulnerable_hit={proof['vulnerable_hit']} trace={proof['trace'][:5]}")

    # Ledger is stale after Phase 4 resolution: a dynamic case resolved
    # by constant propagation / verified LLM is no longer unresolved.
    ledger.dynamic_unresolved = sum(1 for r in results if r.verdict == "uncertain")
    ledger.ambiguous_edges = sum(len(v) for v in graph.ambiguous.values())
    total = len(results) or 1
    uncertain_rate = sum(1 for r in results if r.verdict == "uncertain") / total
    print(f"uncertain rate: {uncertain_rate:.0%} ({sum(1 for r in results if r.verdict == 'uncertain')}/{len(results)}) — a tool that labels everything uncertain gets 0 false not-reachable without solving anything, so report this metric.")
    report = {
        "project": str(root),
        "entry_note": entry_note,
        "entry_evidence": evidence,
        "completeness_ledger": ledger.to_dict(),
        "uncertain_rate": uncertain_rate,
        "cache": {"hits": cache.hits, "misses": cache.misses},
        "results": [
            {"advisory_id": r.advisory_id, "package": r.package,
             "vulnerable_function": r.vulnerable_function, "verdict": r.verdict,
             "confidence": r.confidence, "path": r.path, "reason": r.reason}
            for r in results
        ],
        "proofs": proofs,
        "pr_comments": [format_pr_comment(r, entry_note) for r in results],
    }
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    # OpenVEX only if the ledger is complete for not_reachable (ChatGPT fix).
    # Otherwise a not_reachable verdict after a resolved dynamic case would
    # still be written, but an unresolved one must never produce VEX.
    vex_results = results if ledger.is_complete_for_not_reachable() else [
        r for r in results if r.verdict == "not_reachable" and r.confidence == "high"
        and "dynamic" not in r.reason
    ]
    # Simpler and safer: if ledger is not complete, write no VEX statements.
    if not ledger.is_complete_for_not_reachable():
        vex_results = []
    vex = build_openvex(vex_results, root.name)
    write_openvex(args.vex, vex)
    print(f"\nwrote {args.out} and {args.vex}")
    for r in results:
        print(f"  {r.verdict:13} {r.confidence:6} {r.advisory_id} {r.vulnerable_function}  {r.reason[:110]}")
    print(f"OpenVEX statements: {len(vex['statements'])} (not_reachable only)")
    return 2 if any(r.verdict == "reachable" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
