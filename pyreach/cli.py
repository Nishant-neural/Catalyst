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
from .phase1 import analyse_advisory_live, save_advisories
from .callgraph import build_graph
from .cache import Cache
from .completeness import Ledger
from .debate import format_pr_comment
from .entrypoints import find_entrypoints, find_entrypoints_with_evidence
from .proof import run_execution_proof
from .reach import analyze
from .resolver import DEFAULT_MODEL, build_prompt, resolve_getattr_case
from .vex import build_openvex, write_openvex


def main(argv=None) -> int:
    # Phase 1 fetch command: pyreach fetch <package> <version> [--out advisories.json]
    # Lives before the scan parser, so `fetch` does not need a project path.
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "fetch":
        fp = argparse.ArgumentParser(prog="pyreach fetch", description="Phase 1: OSV -> fix commit -> diff -> vulnerable functions")
        fp.add_argument("package")
        fp.add_argument("version")
        fp.add_argument("--out", default="advisories.json")
        fargs = fp.parse_args(argv[1:])
        print(f"fetching OSV for {fargs.package} {fargs.version} ...")
        # Phase 3: diffs are cached by commit sha / sdist sha256, so a
        # second fetch of the same advisory is a cache hit, not a download.
        cache = Cache(".reachcache")
        results = analyse_advisory_live(fargs.package, fargs.version, cache=cache)
        save_advisories(results, fargs.out)
        print(f"advisories: {len(results)}  -> {fargs.out}  (cache: {cache.hits} hits, {cache.misses} misses)")
        for r in results:
            fc = r.get("fix_commit") or {}
            print(f"  {r['id']} fixed={r.get('fixed_version')} commit={fc.get('sha', '')[:12] if fc.get('sha') else fc.get('via', 'none')}")
            for c in r.get("candidates", []):
                print(f"    {c['confidence']:6} {c['qualified'] or '(no candidate)'}  {c['evidence'][:100]}")
        return 0

    p = argparse.ArgumentParser(prog="pyreach", description="Which vuln alerts actually affect this Python project?")
    p.add_argument("command", choices=["scan"])
    p.add_argument("project", help="Path to the Python project to scan")
    p.add_argument("--advisory", help="Advisory JSON (OSV-style, see examples/advisory-sample.json). If omitted, use --package + --version to fetch live (Phase 1).")
    p.add_argument("--package", help="Package to fetch advisories for (with --version), e.g. PyYAML")
    p.add_argument("--version", help="Installed version to fetch advisories for, e.g. 5.3.1")
    p.add_argument("--out", default="report.json", help="JSON report output")
    p.add_argument("--vex", default="openvex.json", help="OpenVEX output (only for not_reachable)")
    p.add_argument("--with-llm", action="store_true", help="Run LLM resolver on uncertain cases (needs OPENROUTER_API_KEY)")
    p.add_argument("--model", default=DEFAULT_MODEL, help="LLM model for the resolver (default: openai/gpt-oss-20b)")
    p.add_argument("--print-prompt", action="store_true", help="Print the grounded LLM prompt for uncertain cases and exit without calling any model (demo without a key)")
    p.add_argument("--with-proof", action="store_true", help="Run execution proof for reachable cases")
    p.add_argument("--proof-timeout", type=int, default=10, help="Seconds per witness run (default 10)")
    p.add_argument("--cache-dir", default=".reachcache")
    args = p.parse_args(argv)

    root = Path(args.project)
    if not root.exists():
        print(f"error: project not found: {root}", file=sys.stderr)
        return 1

    cache = Cache(args.cache_dir)
    if args.advisory:
        advisories = load_advisories(args.advisory)
    elif args.package and args.version:
        print(f"Phase 1: fetching advisories for {args.package} {args.version} ...")
        live = analyse_advisory_live(args.package, args.version, cache=cache)
        # Write the live result next to the report so it is reproducible
        Path("_live_advisories.json").write_text(json.dumps(live, indent=2), encoding="utf-8")
        advisories = load_advisories("_live_advisories.json")
        print(f"Phase 1: {len(advisories)} advisories, "
              f"{sum(len(a.vulnerable_functions) for a in advisories)} candidates")
    else:
        print("error: give --advisory <json> or --package <name> --version <ver>", file=sys.stderr)
        return 1
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

    # Phase 4: deterministic constant propagation FIRST, LLM only for
    # what it cannot resolve. Phase 4 fix over the base: the old code
    # tried only graph.dynamic[0] and passed ALL project functions as
    # "this module's" candidates. Now every uncertain result tries every
    # dynamic site, and the prompt gets same-file functions only.
    # --print-prompt shows the grounded prompt without calling any model,
    # so the resolver is demoable with no API key at all.
    for r in results:
        if r.verdict != "uncertain" or not graph.dynamic:
            continue
        for d in graph.dynamic:
            try:
                src = Path(d["file"]).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if args.print_prompt:
                lines = src.splitlines()
                lo, hi = max(0, d["line"] - 25), min(len(lines), d["line"] + 25)
                snippet = "\n".join(f"{i+1}: {lines[i]}" for i in range(lo, hi))
                same_file = sorted(q for q in graph.functions
                                   if graph.functions[q].file == d["file"])
                from .resolver import extract_string_literals
                print(build_prompt(snippet, same_file, extract_string_literals(src),
                                   [r.vulnerable_function], d["file"], d["line"]))
                continue
            if not args.with_llm:
                # Constants only, no network, no LLM — even if a key is
                # set in the environment. The user did not ask for the LLM.
                from .resolver import constant_propagate_getattr as _cp
                vals = _cp(src, d["line"])
                if vals is None:
                    continue
                vuln = r.vulnerable_function.split(".")[-1]
                if vals and vuln in vals:
                    r.verdict, r.confidence = "reachable", "high"
                    r.reason += f" | constant propagation: dynamic name can be {vals}, including vulnerable {vuln} (line {d['line']})"
                elif vals:
                    r.verdict, r.confidence = "not_reachable", "high"
                    r.reason += f" | constant propagation: dynamic name can only be {vals}, none vulnerable (line {d['line']})"
                break
            outcome = resolve_getattr_case(
                src, d["line"], [r.vulnerable_function], set(graph.functions),
                cache=cache, model=args.model)
            if outcome is None:
                continue
            if outcome.get("_verification_failed"):
                print(f"LLM resolver for {r.advisory_id}: {outcome['reason']}")
                continue
            r.verdict, r.confidence = outcome["verdict"], outcome["confidence"]
            r.reason += f" | {outcome['reason']}"
            print(f"Phase 4 {r.advisory_id} {r.vulnerable_function}: {r.verdict} ({r.confidence}) — {outcome['reason'][:100]}")
            break  # one resolved site is enough for this result

    # Phase 5: execution witness, reachable only. Never changes a verdict:
    # a failed run keeps the static verdict. Entry functions are passed
    # as dotted paths relative to their module (mod.Class.method works,
    # <module> means import-only).
    proofs = {}
    if args.with_proof:
        for r in results:
            if r.verdict != "reachable" or not r.path:
                continue
            entry_q = r.path[0]
            if entry_q not in graph.functions:
                continue
            entry_file = str(Path(graph.functions[entry_q].file).resolve())
            # Strip the module prefix: app.Loader.load_config -> Loader.load_config
            mod = entry_q.rsplit(".", 1)[0] if "." in entry_q else ""
            entry_func = entry_q[len(mod) + 1:] if mod and entry_q.startswith(mod + ".") else entry_q.split(".")[-1]
            proof = run_execution_proof(str(root), entry_file, entry_func,
                                        r.vulnerable_function, timeout=args.proof_timeout)
            proofs[r.advisory_id] = proof
            print(f"proof {r.advisory_id}: vulnerable_hit={proof['vulnerable_hit']} trace={proof['trace'][:5]} error={proof['error']}")

    # Ledger is stale after Phase 4 resolution: a dynamic case resolved
    # by constant propagation / verified LLM is no longer unresolved.
    ledger.dynamic_unresolved = sum(1 for r in results if r.verdict == "uncertain")
    ledger.ambiguous_edges = sum(len(v) for v in graph.ambiguous.values())
    total = len(results) or 1
    uncertain_rate = sum(1 for r in results if r.verdict == "uncertain") / total
    print(f"uncertain rate: {uncertain_rate:.0%} ({sum(1 for r in results if r.verdict == 'uncertain')}/{len(results)}) — a tool that labels everything uncertain gets 0 false not-reachable without solving anything, so report this metric.")
    report = {
        "project": str(root),
        # Phase 3: provenance — which advisory, which fix commit, how many
        # candidates, so a judge can reproduce the run from the report alone.
        "advisories": [
            {"id": a.id, "package": a.package, "fixed_version": a.fixed_version,
             "fix_commit": a.fix_commit if isinstance(a.fix_commit, str) else "",
             "candidates": len(a.vulnerable_functions)}
            for a in advisories
        ],
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
    # OpenVEX, per result, not per run (Phase 1 fix).
    # The old rule blocked ALL VEX if any result was uncertain — one
    # uncertain library-internal candidate (e.g. construct_python_object_new,
    # dependency not parsed) then blocked VEX for yaml.full_load, which IS
    # provably not_reachable from project source alone. That was wrong.
    # Correct gate, per result: the verdict itself is not_reachable with
    # high/medium confidence, AND the graph is clean (no dynamic trigger,
    # no ambiguous edge, project fully parsed), so no hidden path could
    # exist for that target. Uncertain results never produce VEX.
    graph_clean = (not graph.dynamic and not graph.ambiguous
                   and ledger.project_files_discovered == ledger.project_files_parsed)
    vex_results = [
        r for r in results
        if r.verdict == "not_reachable" and r.confidence in ("high", "medium")
    ] if graph_clean else []
    vex = build_openvex(vex_results, root.name)
    write_openvex(args.vex, vex)
    print(f"\nwrote {args.out} and {args.vex}")
    for r in results:
        print(f"  {r.verdict:13} {r.confidence:6} {r.advisory_id} {r.vulnerable_function}  {r.reason[:110]}")
    print(f"OpenVEX statements: {len(vex['statements'])} (not_reachable only)")
    return 2 if any(r.verdict == "reachable" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
