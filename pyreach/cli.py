"""CLI: pyreach scan <project> --advisory <json> [options]

Phases 1-5 in one command:
  1. advisory -> vulnerable functions
  2. call graph + BFS reachability
  3. real entry points + JSON + OpenVEX + cache
  4. LLM resolver for uncertain dynamic cases (auto-enabled when a key
     is in .env / the environment, --no-llm to skip it)
  5. execution proof for reachable cases + PR comment

Exit 0 = scan completed (even if reachable found).
Exit 2 = reachable vulnerability found (useful for CI).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from .advisory import load_advisories
from .deps import advisory_file_for, normalize_name, resolve_dependencies
from .dotenv import load_dotenv_file
from .phase1 import analyse_advisory_live, save_advisories
from .callgraph import build_graph
from .cache import Cache
from .completeness import Ledger
from .debate import format_pr_comment
from .entrypoints import (find_entrypoints, find_entrypoints_with_evidence,
                          find_unsupported_entrypoints)
from .explainer import explain_result, format_explanation
from .html_report import blocked_location, html_path_for, render_report_file, write_html_report
from .proof import run_execution_proof
from .reach import Result, analyze, reachable_functions, reachable_modules, site_can_run
from .resolver import (DEFAULT_MODEL, LLM_TEST_PROMPT, build_prompt,
                       resolve_getattr_case, resolve_with_llm_status)
from .vex import build_openvex, write_openvex


def _report_dotenv(summary: dict) -> None:
    """One line about .env loading. Never prints a value — only the file
    path, how many keys were loaded, and how many were already set in
    the real environment (those win and are left untouched). Silent
    when there is no .env file at all: that is the normal no-key case."""
    if not summary.get("path"):
        return
    if summary.get("error"):
        print(f".env: {summary['error']} (continuing with environment variables)")
        return
    loaded, skipped = summary["loaded"], summary["skipped"]
    if loaded:
        print(f".env: loaded {len(loaded)} key(s) from {summary['path']} ({', '.join(loaded)})")
    if skipped:
        print(f".env: {len(skipped)} key(s) already set in the environment, kept as-is ({', '.join(skipped)})")


def llm_key_present() -> bool:
    """Is there an LLM key to use — from .env (already loaded by now)
    or from a real environment variable? Checks the value's presence
    only, never the value itself."""
    return bool(os.environ.get("OPENROUTER_API_KEY")
                or os.environ.get("GROQ_API_KEY"))


def llm_explainer_summary(explanations: list[dict]) -> str:
    """One summary line for the LLM explainer layer, e.g.
    "LLM explainer: 3 called, 0 accepted, 0 rejected, 3 unavailable (timeout)".

    "called" counts every explanation where the layer actually ran
    (llm_status != "not_called"); "accepted" is llm_status "ok";
    "rejected" is verifier-rejected; the rest are unavailable, with
    the distinct failure kinds in parentheses, most common first.
    """
    from collections import Counter
    called = accepted = rejected = 0
    unavailable: Counter = Counter()
    for e in explanations:
        status = e.get("llm_status", "not_called")
        if status == "not_called":
            continue
        called += 1
        if e.get("llm_explanation"):
            accepted += 1
        elif e.get("llm_rejected"):
            rejected += 1
        else:
            unavailable[status] += 1
    unav = sum(unavailable.values())
    line = (f"LLM explainer: {called} called, {accepted} accepted, "
            f"{rejected} rejected, {unav} unavailable")
    if unavailable:
        kinds = ", ".join(k for k, _ in unavailable.most_common())
        line += f" ({kinds})"
    return line


def _print_llm_debug(explanations: list[dict]) -> None:
    """Per-result LLM status + safe detail, for --llm-debug only."""
    for e in explanations:
        status = e.get("llm_status", "not_called")
        detail = e.get("llm_error")
        line = f"LLM debug {e.get('vulnerable_function', '?')}: {status}"
        if detail:
            line += f" — {detail}"
        print(line)


def should_use_llm(with_llm: bool, no_llm: bool, key_present: bool) -> bool:
    """Decide whether the Phase 4 LLM resolver may run.

    --no-llm always wins (explicit opt-out). Otherwise the resolver is
    on when the user asked for it (--with-llm) OR when a key is present
    — that is the .env case: putting a key in .env is itself asking for
    the LLM, so a plain `scan` must use it with no extra flag. With no
    key at all the resolver stays off and verdicts stay uncertain.
    """
    if no_llm:
        return False
    return bool(with_llm or key_present)


def resolve_model_choice(explicit_model: str | None) -> tuple[str, bool]:
    """Turn a --model flag into (model, allow_fallback).

    The --model arguments default to None so "not given" can be told
    apart from "given": no --model means the default model WITH the
    free-model fallback chain (a delisted default 404 falls back);
    an explicit --model means exactly that model, no fallback — the
    user's explicit choice is not ours to override.
    """
    if explicit_model is None:
        return DEFAULT_MODEL, True
    return explicit_model, False


def _dependency_coverage(advisories, graph) -> tuple[int, int]:
    """Modules discovered vs parsed for the vulnerable dependencies
    (ChatGPT §5, 19 Nov 2026). Discovered: .py files under the installed
    package, found via the import names the advisories' candidates use
    (yaml.load -> yaml). Parsed: 0 — pyreach does not parse dependency
    source yet, and the ledger must say so honestly instead of 0/0. The
    internal-target rule in reach.py is what keeps those candidates
    uncertain until dependency source is parsed."""
    discovered = 0
    seen: set[str] = set()
    for adv in advisories:
        for vf in adv.vulnerable_functions:
            first = vf.qualified.split(".")[0] if vf.qualified else ""
            if not first or first in seen:
                continue
            seen.add(first)
            try:
                import importlib.util
                spec = importlib.util.find_spec(first)
            except Exception:
                spec = None
            if spec is None or not spec.origin:
                continue
            p = Path(spec.origin)
            try:
                if p.name == "__init__.py":
                    discovered += len(list(p.parent.rglob("*.py")))
                elif p.suffix == ".py":
                    discovered += 1
            except OSError:
                pass
    return discovered, 0


def _run_scan(root, advisories, cache, use_llm, model, allow_fallback,
              args, packages=None):
    """Phases 2-5 + explainer + report for one advisory list.

    Shared by `scan` (one package) and `scan-all` (all advisories from
    every pinned dependency, one combined list). The call graph is built
    once per call; scan-all therefore builds it once for all packages,
    not once per package. `args` is the scan argument namespace
    (out/vex/with_proof/explain/verbose/no_html/llm_debug/proof_timeout/
    print_prompt). `packages`, when given, is the scan-all package table
    (filled with per-package result counts here, before the report is
    written). Returns (report_dict, exit_code).
    """
    graph = build_graph(root)
    entries, entry_note = find_entrypoints(root, graph)
    # Quiet by default: the terminal is a summary, not a dump. A full
    # entry-point list on a real project is 1,194 names on one line
    # (MkDocs, 19 Nov 2026) — it belongs in report.json, not stdout.
    if args.verbose:
        print(f"entry points ({entry_note}): {sorted(entries)}")
    else:
        print(f"entry points ({entry_note}): {len(entries)}")
    print(f"functions: {len(graph.functions)}, edges: {sum(len(v) for v in graph.edges.values())}, dynamic triggers: {len(graph.dynamic)}")

    results = analyze(advisories, graph, entries)

    # Completeness ledger — core, not a write-up item (ChatGPT fix)
    dep_discovered, dep_parsed = _dependency_coverage(advisories, graph)
    ledger = Ledger(
        project_files_discovered=len(list(root.rglob("*.py"))),
        project_files_parsed=len({f.file for f in graph.functions.values() if f.file != "external"}),
        dependency_modules_discovered=dep_discovered,
        dependency_modules_parsed=dep_parsed,
        unresolved_imports=list(graph.unresolved_imports),
        entry_points_unsupported=find_unsupported_entrypoints(root, graph),
        dynamic_unresolved=len(graph.dynamic),
        ambiguous_edges=sum(len(v) for v in graph.ambiguous.values()),
        unresolved_attribute_calls=len(graph.unresolved_attrs),
        entry_points_identified=len(entries),
        vulnerable_targets_high=sum(1 for a in advisories for f in a.vulnerable_functions if f.confidence == "high"),
        vulnerable_targets_low=sum(1 for a in advisories for f in a.vulnerable_functions if f.confidence == "low"),
    )
    evidence = find_entrypoints_with_evidence(root, graph)
    # Same rule: the whole evidence dict (1,194 entries on MkDocs) is
    # in report.json as entry_evidence; the terminal gets a count.
    if args.verbose:
        print(f"entry evidence: {evidence}")
    else:
        print(f"entry evidence: {len(evidence)} entries (see report.json)")
    print(f"completeness: {ledger.to_dict()}")

    # Phase 4: deterministic constant propagation FIRST, LLM only for
    # what it cannot resolve. Aggregation rule (19 Nov 2026 fix — the
    # real PyYAML 5.3.1 sdist caught this): ONE dynamic site's answer
    # decides ONE site, never the whole result. The old code took the
    # first site that resolved to a literal list and let it decide:
    # a single getattr with name "encoding" marked all 7 PyYAML
    # candidates not_reachable, including yaml.load, which the test
    # suite genuinely calls. Correct rule:
    #   - any site resolving to the vulnerable name -> reachable
    #   - ALL sites resolved safe, none unknown -> not_reachable
    #   - otherwise -> stay uncertain, and say how many sites resolved
    # --print-prompt shows the grounded prompt without calling any model,
    # so the resolver is demoable with no API key at all.
    # Only dynamic sites in code that can execute are tried (see
    # reach.site_can_run): a site in dead code can neither call anything
    # nor hide a path, and (19 Nov 2026, ChatGPT review) a dead-code site
    # must not flip a verdict to reachable either. But a site inside a
    # dunder method of a reachable module (e.g. __getattr__) DOES run —
    # BFS alone misses it, and the old BFS-only filter silently dropped
    # MkDocs' config_options.py:549 site that way.
    reached = reachable_functions(graph, entries)
    modules = reachable_modules(graph, entries)
    reachable_sites = [d for d in graph.dynamic
                       if site_can_run(graph, entries, reached, modules, d)]
    unresolved_sites: set[tuple[str, int]] = set()
    for r in results:
        if r.verdict != "uncertain" or not reachable_sites:
            continue
        sites = reachable_sites
        resolved_safe = 0
        unresolved = 0
        llm_used = False
        hit_reason = ""
        hit_conf = "high"
        for d in sites:
            try:
                src = Path(d["file"]).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                unresolved += 1
                unresolved_sites.add((d["file"], d["line"]))
                continue
            if args.print_prompt:
                # Demo: first site only, not all 51 of them.
                if d is sites[0]:
                    lines = src.splitlines()
                    lo, hi = max(0, d["line"] - 25), min(len(lines), d["line"] + 25)
                    snippet = "\n".join(f"{i+1}: {lines[i]}" for i in range(lo, hi))
                    same_file = sorted(q for q in graph.functions
                                       if graph.functions[q].file == d["file"])
                    from .resolver import extract_string_literals
                    print(build_prompt(snippet, same_file, extract_string_literals(src),
                                       [r.vulnerable_function], d["file"], d["line"]))
                    print(f"# ... and {len(sites) - 1} more dynamic sites "
                          f"(a key in .env enables the resolver for them all)")
                continue
            outcome = resolve_getattr_case(
                src, d["line"], [r.vulnerable_function], set(graph.functions),
                cache=cache, model=model, allow_llm=use_llm,
                allow_fallback=allow_fallback)
            if outcome is None:
                unresolved += 1
                unresolved_sites.add((d["file"], d["line"]))
                continue
            if outcome.get("_verification_failed"):
                print(f"LLM resolver for {r.advisory_id}: {outcome['reason']}")
                unresolved += 1
                unresolved_sites.add((d["file"], d["line"]))
                continue
            if "LLM resolver" in outcome["reason"]:
                llm_used = True
            if outcome["verdict"] == "reachable":
                hit_reason = outcome["reason"]
                hit_conf = outcome["confidence"]
                break
            resolved_safe += 1
        if hit_reason:
            r.verdict, r.confidence = "reachable", hit_conf
            r.reason += f" | {hit_reason}"
            print(f"Phase 4 {r.advisory_id} {r.vulnerable_function}: reachable — {hit_reason[:100]}")
        elif unresolved == 0 and resolved_safe == len(sites):
            # Every dynamic site resolved, none can hit the target.
            conf = "medium" if llm_used else "high"
            r.verdict, r.confidence = "not_reachable", conf
            r.reason = (f"No static path. Phase 4 resolved all {len(sites)} "
                        f"dynamic call site(s); none can reach {r.vulnerable_function}.")
            print(f"Phase 4 {r.advisory_id} {r.vulnerable_function}: not_reachable "
                  f"({conf}, all {len(sites)} dynamic sites resolved safe)")
        else:
            r.reason += (f" | Phase 4: resolved {resolved_safe}/{len(sites)} dynamic "
                         f"sites safe, {unresolved} still unknown — staying uncertain")

    # Phase 5: execution witness, reachable only. Never changes a verdict:
    # a failed run keeps the static verdict. Entry functions are passed
    # as dotted paths relative to their module (mod.Class.method works,
    # <module> means import-only).
    proofs = {}
    if args.with_proof:
        # The witness runs project code in a subprocess with the current
        # interpreter. That is not a sandbox (ChatGPT review, 19 Nov 2026):
        # use --with-proof only on projects you trust.
        print("proof: runs project code in a subprocess — not a sandbox; use only on trusted projects")
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
    # dynamic_unresolved now means what it says — dynamic sites still
    # unknown after Phase 4 (19 Nov 2026 fix: it used to be overwritten
    # with the count of uncertain results, which made
    # is_complete_for_not_reachable() false whenever anything was
    # uncertain, even for unrelated reasons).
    ledger.dynamic_unresolved = len(unresolved_sites)
    ledger.ambiguous_edges = sum(len(v) for v in graph.ambiguous.values())
    # Completeness gate (ChatGPT §5, 19 Nov 2026): a not_reachable verdict
    # stands only if the analysis actually covered what it claims.
    # analyze() already enforces the per-target conditions (dynamic,
    # ambiguous, unresolved attrs, references, internals); this gate
    # catches the ledger-level holes it cannot see — files that failed
    # to parse, imports that did not resolve, entry points we could not
    # model. A result flipped here was never proven safe, only unexamined.
    if (ledger.project_files_discovered != ledger.project_files_parsed
            or ledger.unresolved_imports or ledger.entry_points_unsupported):
        for r in results:
            if r.verdict == "not_reachable":
                r.verdict, r.confidence = "uncertain", "low"
                r.reason += (" | Completeness gate: not_reachable requires full "
                             "coverage (unparsed files / unresolved imports / "
                             "unsupported entry points).")
    total = len(results) or 1
    uncertain_rate = sum(1 for r in results if r.verdict == "uncertain") / total
    print(f"uncertain rate: {uncertain_rate:.0%} ({sum(1 for r in results if r.verdict == 'uncertain')}/{len(results)}) — a tool that labels everything uncertain gets 0 false not-reachable without solving anything, so report this metric.")

    # Explainer: deterministic first, LLM layer only if enabled. Runs
    # AFTER Phase 4 resolution, so explanations describe final verdicts.
    # Never changes a verdict; the LLM output is verified before display.
    explanations = []
    if args.explain:
        uncertain_results = [r for r in results if r.verdict == "uncertain"]
        if not uncertain_results:
            print("explain: no uncertain results to explain.")
        for r in uncertain_results:
            adv = next((a for a in advisories if a.id == r.advisory_id), None)
            exp = explain_result(
                r, graph, root,
                {"id": r.advisory_id, "package": r.package,
                 "fixed_version": adv.fixed_version if adv else ""},
                entries, use_llm=use_llm, model=model, cache=cache,
                allow_fallback=allow_fallback)
            explanations.append({
                "vulnerable_function": exp["vulnerable_function"],
                "advisory_id": exp["advisory_id"],
                "blocker": exp["blocker"],
                "deterministic_explanation": exp["deterministic_explanation"],
                "llm_explanation": exp["llm_explanation"],
                "llm_rejected": exp["llm_rejected"],
                # The diagnostic: what the LLM layer actually did for
                # this result (ok / rejected / no_key / timeout /
                # rate_limited / ... / not_called). llm_enabled only
                # proves a key was found, never that a call succeeded.
                "llm_status": exp.get("llm_status", "not_called"),
                "llm_error": exp.get("llm_error"),
                # Which model produced (or was last tried for) this
                # explanation — not always the default, when the
                # fallback chain switched models on a delisted 404.
                "llm_model": exp.get("llm_model"),
                "discriminating_check": exp["discriminating_check"],
                "does_not_know": exp["does_not_know"],
                "evidence_pack_tokens": exp["evidence_pack_tokens"],
            })
            # Quiet by default: ONE line per uncertain result. The full
            # explanation text (deterministic + LLM layer) is in
            # report.json and in the HTML report — printing it all made
            # a MkDocs scan ~240KB of terminal output. --verbose
            # restores the old full dump for debugging.
            if args.verbose:
                print()
                print(format_explanation(exp))
            else:
                loc = blocked_location(exp["deterministic_explanation"])
                print(f"explain [uncertain] {exp['vulnerable_function']} — "
                      f"blocker {exp['blocker']}"
                      + (f", blocked at {loc}" if loc else "")
                      + f" (full explanation in {html_path_for(args.out).name})")
        # One line saying what the LLM layer actually did. Before this
        # fix, llm_explanation null + llm_rejected false looked like
        # "rejected" or "not tried" — it was neither: the call itself
        # had failed silently (no key / timeout / 429 / bad JSON).
        if explanations:
            print(llm_explainer_summary(explanations))
            if args.llm_debug:
                _print_llm_debug(explanations)
    html_name = None if args.no_html else html_path_for(args.out).name
    report = {
        "project": str(root),
        "html_report": html_name,
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
        "llm_enabled": use_llm,
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
        "explanations": explanations,
        "pr_comments": [format_pr_comment(r, entry_note) for r in results],
    }
    # Phase 7 (scan-all): fill per-package result counts from the
    # aggregated results, and tag the report mode. Single-package scans
    # keep their old shape: no "packages" key, mode "scan".
    if packages is not None:
        for pkg in packages:
            if pkg.get("status") in ("scanned", "no-advisories"):
                prs = [r for r in results
                       if normalize_name(r.package) == normalize_name(pkg["name"])]
                pkg["results"] = {
                    v: sum(1 for r in prs if r.verdict == v)
                    for v in ("reachable", "not_reachable", "uncertain")}
                pkg["total_results"] = len(prs)
        report["mode"] = "scan-all"
        report["packages"] = packages
    else:
        report["mode"] = "scan"
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    # Readable HTML interface, written next to the JSON report unless
    # --no-html was given. It renders report.json data only, so it can
    # be regenerated later with `pyreach report --report <report.json>`.
    html_out = None
    if not args.no_html:
        html_out = write_html_report(report, args.out)
    # OpenVEX is aggregated at the advisory level inside build_openvex
    # (ChatGPT Critical 2, 19 Nov 2026): a not_affected statement fires
    # only when EVERY candidate for the advisory is not_reachable. The
    # old per-result rule emitted not_affected for FullLoader while the
    # same report said yaml.load was reachable. The gate is the ledger:
    # fully parsed, no dynamic site still unresolved after Phase 4, no
    # ambiguous edge, no low-confidence target, no unresolved import.
    # (Note the asymmetry is deliberate: the verdict gate above is
    # per-target, but VEX goes to downstream tooling, so it uses the
    # stricter whole-run ledger.)
    vex = build_openvex(results, root.name,
                        graph_clean=ledger.is_complete_for_not_reachable())
    write_openvex(args.vex, vex)
    print(f"\nwrote {args.out} and {args.vex}")
    if html_out is not None:
        print(f"readable report: {html_out} (open it in a browser)")
    for r in results:
        print(f"  {r.verdict:13} {r.confidence:6} {r.advisory_id} {r.vulnerable_function}  {r.reason[:110]}")
    print(f"OpenVEX statements: {len(vex['statements'])} (not_reachable only)")
    return report, (2 if any(r.verdict == "reachable" for r in results) else 0)




def _cmd_scan_all(sargs) -> int:
    """`pyreach scan-all <project>`: check EVERY dependency, not one package.

    1. Resolve dependencies to exact versions (deps.py — never guessed).
    2. Per pinned package, get advisories: from --advisory-dir files when
       given (offline, reproducible), else live via analyse_advisory_live
       (OSV -> fix commit -> diff -> candidates, cached in .reachcache).
       A fetch failure marks that package "fetch-failed" and the scan
       continues with the rest — the failure stays visible in the report,
       it is never a silent skip.
    3. Run the same _run_scan as `scan` over the combined advisory list,
       with the graph built once, and print a per-package table.
    Exit 2 if any package has a reachable vulnerability, else 0.
    """
    root = Path(sargs.project)
    if not root.exists():
        print(f"error: project not found: {root}", file=sys.stderr)
        return 1
    dotenv_summary = load_dotenv_file(path=sargs.env_file, project=root)
    _report_dotenv(dotenv_summary)
    use_llm = should_use_llm(sargs.with_llm, sargs.no_llm, llm_key_present())
    model, allow_fallback = resolve_model_choice(sargs.model)
    if use_llm and not sargs.with_llm:
        via = ".env" if any(k in dotenv_summary.get("loaded", [])
                            for k in ("OPENROUTER_API_KEY", "GROQ_API_KEY")) else "the environment"
        print(f"LLM: key found via {via}, resolver on (use --no-llm to skip it)")
    elif sargs.with_llm and not llm_key_present():
        print("LLM: --with-llm passed but no key found — put it in .env "
              "(OPENROUTER_API_KEY=...) and re-run; staying uncertain for now")
    cache = Cache(sargs.cache_dir)

    deps, notes = resolve_dependencies(root, requirements=sargs.requirements,
                                       include_dev=sargs.include_dev)
    for n in notes:
        print(f"scan-all: {n}")
    only = {normalize_name(x) for x in (sargs.only.split(",") if sargs.only else []) if x.strip()}
    skip = {normalize_name(x) for x in (sargs.skip.split(",") if sargs.skip else []) if x.strip()}
    if only:
        deps = [d for d in deps if d.key in only]
    if skip:
        deps = [d for d in deps if d.key not in skip]

    packages: list[dict] = []
    all_advisories = []
    with tempfile.TemporaryDirectory(prefix="pyreach-scanall-") as tmp:
        for i, dep in enumerate(deps, 1):
            if dep.status == "skipped":
                print(f"scan-all [{i}/{len(deps)}] {dep.name}: SKIP — {dep.reason}")
                packages.append({"name": dep.name, "spec": dep.spec,
                                 "version": None, "version_source": None,
                                 "status": "skipped", "reason": dep.reason,
                                 "advisories": 0, "candidates": 0})
                continue
            print(f"scan-all [{i}/{len(deps)}] {dep.name} {dep.version} "
                  f"({dep.version_source}) ...")
            entry: dict = {"name": dep.name, "spec": dep.spec,
                           "version": dep.version,
                           "version_source": dep.version_source,
                           "advisories": 0, "candidates": 0}
            try:
                if sargs.advisory_dir:
                    f = advisory_file_for(dep.name, sargs.advisory_dir)
                    if f is None:
                        entry.update(status="not-checked",
                                     reason=f"no advisory file for {dep.name} in {sargs.advisory_dir} — "
                                            "not checked, not assumed clean")
                        packages.append(entry)
                        continue
                    advs = load_advisories(str(f))
                else:
                    print(f"  Phase 1: fetching advisories for {dep.name} {dep.version} ...")
                    dicts = analyse_advisory_live(dep.name, dep.version, cache=cache)
                    tmp_file = str(Path(tmp) / f"{dep.key}.json")
                    save_advisories(dicts, tmp_file)
                    advs = load_advisories(tmp_file)
            except Exception as e:
                entry.update(status="fetch-failed",
                             reason=f"could not fetch advisories: {e}")
                packages.append(entry)
                print(f"  fetch failed for {dep.name}: {e} (continuing with the rest)")
                continue
            entry["status"] = "scanned" if advs else "no-advisories"
            entry["advisories"] = len(advs)
            entry["candidates"] = sum(len(a.vulnerable_functions) for a in advs)
            print(f"  {dep.name}: {len(advs)} advisories, "
                  f"{entry['candidates']} candidates")
            all_advisories.extend(advs)
            packages.append(entry)
        if not all_advisories:
            print("scan-all: no advisories for any dependency — nothing to "
                  "check. The report still lists every package and skip, "
                  "so 'nothing found' is checkable, not assumed.")
        scan_args = argparse.Namespace(
            out=sargs.out, vex=sargs.vex, with_proof=sargs.with_proof,
            explain=sargs.explain, verbose=sargs.verbose,
            no_html=sargs.no_html, llm_debug=sargs.llm_debug,
            proof_timeout=sargs.proof_timeout, print_prompt=False)
        report, code = _run_scan(root, all_advisories, cache, use_llm, model,
                                 allow_fallback, scan_args, packages=packages)
    print("\nscan-all packages:")
    for pkg in report.get("packages", []):
        res = pkg.get("results", {})
        line = (f"  {pkg['name']} {pkg.get('version') or ''} "
                f"({pkg.get('version_source') or pkg.get('status', '')}): "
                f"{pkg.get('advisories', 0)} advisories")
        if res:
            line += (f" — {res.get('reachable', 0)} reachable, "
                     f"{res.get('uncertain', 0)} uncertain, "
                     f"{res.get('not_reachable', 0)} not_reachable")
        if pkg.get("reason"):
            line += f" — {pkg['reason']}"
        print(line)
    return code


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
        fp.add_argument("--env-file", default=None,
                        help=".env file to load the API key from (default: ./.env if present)")
        fargs = fp.parse_args(argv[1:])
        _report_dotenv(load_dotenv_file(path=fargs.env_file))
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

    # Explainer command: pyreach explain --report report.json --project <path>
    # [--target yaml.load] [--no-llm]
    # Explains uncertain results from an existing report WITHOUT re-running
    # the whole scan. The graph is rebuilt from the project path (in the
    # report, or --project) so evidence packs are grounded in current code.
    # No uncertain results -> print that plainly, exit 0.
    if argv and argv[0] == "explain":
        ep = argparse.ArgumentParser(
            prog="pyreach explain",
            description="Explain uncertain results from an existing report")
        ep.add_argument("--report", required=True, help="report.json from a scan")
        ep.add_argument("--project", default=None,
                        help="Project path (default: the path stored in the report)")
        ep.add_argument("--target", default=None,
                        help="Only explain this vulnerable function, e.g. yaml.load")
        ep.add_argument("--with-llm", action="store_true",
                        help="Also run the LLM explainer layer (auto-enabled when a key is in .env)")
        ep.add_argument("--no-llm", action="store_true",
                        help="Deterministic explanations only, even with a key present")
        ep.add_argument("--model", default=None,
                        help="LLM model (default: cohere/north-mini-code:free; "
                             "explicit --model is used exactly, with no fallback)")
        ep.add_argument("--env-file", default=None)
        ep.add_argument("--llm-debug", action="store_true",
                        help="Also print the per-result LLM status and safe detail")
        eargs = ep.parse_args(argv[1:])
        _report_dotenv(load_dotenv_file(path=eargs.env_file))
        try:
            report = json.loads(Path(eargs.report).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"error: cannot read report {eargs.report}: {e}", file=sys.stderr)
            return 1
        root = Path(eargs.project) if eargs.project else Path(report.get("project", ""))
        if not root.exists():
            print(f"error: project not found: {root} "
                  f"(pass --project <path>)", file=sys.stderr)
            return 1
        if eargs.project and report.get("project") \
                and Path(report["project"]) != Path(eargs.project):
            print(f"warning: this report was for {report['project']}, "
                  f"but you passed --project {eargs.project} — the "
                  f"explanations are grounded in the project you passed, "
                  f"not the one the report was scanned from")
        use_llm = should_use_llm(eargs.with_llm, eargs.no_llm, llm_key_present())
        model, allow_fallback = resolve_model_choice(eargs.model)
        if use_llm and not eargs.with_llm:
            print("LLM: key found, explainer layer on (use --no-llm to skip it)")
        cache = Cache(".reachcache")
        graph = build_graph(root)
        entries, _entry_note = find_entrypoints(root, graph)
        adv_by_id = {a.get("id"): a for a in report.get("advisories", [])}
        rows = [r for r in report.get("results", []) if r.get("verdict") == "uncertain"]
        if eargs.target:
            t = eargs.target
            rows = [r for r in rows if r.get("vulnerable_function") in (t, )
                    or r.get("vulnerable_function", "").endswith("." + t)
                    or r.get("vulnerable_function", "").split(".")[-1] == t]
        if not rows:
            print("no uncertain results to explain.")
            return 0
        exps = []
        for r in rows:
            adv = adv_by_id.get(r.get("advisory_id"), {}) or {}
            res = Result(advisory_id=r.get("advisory_id", ""),
                         package=r.get("package", ""),
                         vulnerable_function=r.get("vulnerable_function", ""),
                         verdict="uncertain",
                         confidence=r.get("confidence", "low"),
                         path=r.get("path") or [],
                         reason=r.get("reason", ""))
            exp = explain_result(
                res, graph, root,
                {"id": r.get("advisory_id", ""), "package": r.get("package", ""),
                 "fixed_version": adv.get("fixed_version", "")},
                entries, use_llm=use_llm, model=model, cache=cache,
                allow_fallback=allow_fallback)
            exps.append(exp)
            print(format_explanation(exp))
            print()
        print(llm_explainer_summary(exps))
        if eargs.llm_debug:
            _print_llm_debug(exps)
        return 0

    # Report command: pyreach report --report report.json [--out report.html]
    # Renders the readable HTML interface from an existing report.json
    # without re-scanning — e.g. for a report produced before the HTML
    # output existed. Exit 0 on success, clean error otherwise.
    if argv and argv[0] == "report":
        rp = argparse.ArgumentParser(
            prog="pyreach report",
            description="Render an existing report.json as readable HTML")
        rp.add_argument("--report", required=True, help="report.json from a scan")
        rp.add_argument("--out", default=None,
                        help="HTML output (default: <report>.html, same directory)")
        rargs = rp.parse_args(argv[1:])
        try:
            out = render_report_file(rargs.report, rargs.out)
        except FileNotFoundError:
            print(f"error: report not found: {rargs.report}", file=sys.stderr)
            return 1
        except (OSError, json.JSONDecodeError) as e:
            print(f"error: cannot read report {rargs.report}: {e}", file=sys.stderr)
            return 1
        print(f"wrote {out} (open it in a browser)")
        return 0

    # LLM diagnosis: pyreach llm-test [--model <model>]
    # One minimal call, no scan. Run this FIRST when the LLM layer
    # looks dead: it tells you whether the key, the endpoint, or the
    # model is the problem, instead of a full MkDocs scan telling you
    # nothing. Prints key presence only, never the value. Exit 0 on
    # ok, 1 otherwise. No cache: a cached ok would hide a dead endpoint.
    if argv and argv[0] == "llm-test":
        tp = argparse.ArgumentParser(
            prog="pyreach llm-test",
            description="One-call LLM diagnosis: key, endpoint and model, no scan")
        tp.add_argument("--model", default=None,
                        help="LLM model (default: cohere/north-mini-code:free; "
                             "explicit --model is used exactly, with no fallback)")
        tp.add_argument("--env-file", default=None)
        targs = tp.parse_args(argv[1:])
        _report_dotenv(load_dotenv_file(path=targs.env_file))
        print(f"LLM key: {'present' if llm_key_present() else 'missing (set OPENROUTER_API_KEY in .env or the environment)'}")
        model, allow_fallback = resolve_model_choice(targs.model)
        import time
        t0 = time.monotonic()
        ans, status = resolve_with_llm_status(LLM_TEST_PROMPT,
                                              model=model, cache=None,
                                              allow_fallback=allow_fallback)
        dt = time.monotonic() - t0
        used = status.get("model") or model
        if ans is not None and isinstance(ans, dict) and ans.get("ok") is True:
            print(f"LLM test: ok in {dt:.2f}s (model {used})")
            return 0
        if ans is not None:
            kind, detail = "bad_json", 'model replied but not the expected {"ok": true} JSON'
        else:
            kind = status.get("kind", "network_error")
            detail = status.get("detail") or ""
        print(f"LLM test: {kind}" + (f" — {detail}" if detail else "")
              + f" (model {used})")
        return 1

    # Phase 7: pyreach scan-all <project> — every dependency, not one package.
    if argv and argv[0] == "scan-all":
        sp = argparse.ArgumentParser(
            prog="pyreach scan-all",
            description="Scan every dependency of a project for known vulnerabilities")
        sp.add_argument("project", help="Path to the Python project to scan")
        sp.add_argument("--out", default="report.json", help="JSON report output")
        sp.add_argument("--vex", default="openvex.json", help="OpenVEX output (only for not_reachable)")
        sp.add_argument("--requirements", default=None,
                        help="requirements.txt to read pins from (default: <project>/requirements.txt)")
        sp.add_argument("--advisory-dir", default=None,
                        help="Directory of per-package advisory JSON files (<name>.json) — offline mode, no OSV fetch")
        sp.add_argument("--include-dev", action="store_true",
                        help="Also scan dev/test dependencies")
        sp.add_argument("--only", default=None,
                        help="Comma-separated dependency names to scan (default: all pinned)")
        sp.add_argument("--skip", default=None,
                        help="Comma-separated dependency names to skip")
        sp.add_argument("--with-llm", action="store_true")
        sp.add_argument("--no-llm", action="store_true")
        sp.add_argument("--model", default=None)
        sp.add_argument("--with-proof", action="store_true", help="Run execution proof for reachable cases")
        sp.add_argument("--explain", action="store_true")
        sp.add_argument("--verbose", action="store_true")
        sp.add_argument("--no-html", action="store_true")
        sp.add_argument("--llm-debug", action="store_true")
        sp.add_argument("--proof-timeout", type=int, default=10)
        sp.add_argument("--cache-dir", default=".reachcache")
        sp.add_argument("--env-file", default=None)
        sargs = sp.parse_args(argv[1:])
        return _cmd_scan_all(sargs)

    p = argparse.ArgumentParser(prog="pyreach", description="Which vuln alerts actually affect this Python project?")
    p.add_argument("command", choices=["scan"])
    p.add_argument("project", help="Path to the Python project to scan")
    p.add_argument("--advisory", help="Advisory JSON (OSV-style, see examples/advisory-sample.json). If omitted, use --package + --version to fetch live (Phase 1).")
    p.add_argument("--package", help="Package to fetch advisories for (with --version), e.g. PyYAML")
    p.add_argument("--version", help="Installed version to fetch advisories for, e.g. 5.3.1")
    p.add_argument("--out", default="report.json", help="JSON report output")
    p.add_argument("--vex", default="openvex.json", help="OpenVEX output (only for not_reachable)")
    p.add_argument("--with-llm", action="store_true", help="Run LLM resolver on uncertain cases (also auto-enabled when a key is in .env / the environment)")
    p.add_argument("--no-llm", action="store_true", help="Never run the LLM resolver, even if a key is in .env / the environment")
    p.add_argument("--model", default=None, help="LLM model for the resolver (default: cohere/north-mini-code:free; explicit --model is used exactly, with no fallback)")
    p.add_argument("--print-prompt", action="store_true", help="Print the grounded LLM prompt for uncertain cases and exit without calling any model (demo without a key)")
    p.add_argument("--with-proof", action="store_true", help="Run execution proof for reachable cases")
    p.add_argument("--explain", action="store_true",
                   help="Explain every uncertain result (deterministic first; LLM layer only if a key is present and --no-llm is not given)")
    p.add_argument("--verbose", action="store_true",
                   help="Print the full terminal dump (full entry-point list, full entry evidence, full explanation text). Default is a short summary only.")
    p.add_argument("--no-html", action="store_true",
                   help="Do not write the readable HTML report next to report.json")
    p.add_argument("--llm-debug", action="store_true",
                   help="Also print the per-result LLM status and safe detail (with --explain)")
    p.add_argument("--proof-timeout", type=int, default=10, help="Seconds per witness run (default 10)")
    p.add_argument("--cache-dir", default=".reachcache")
    p.add_argument("--env-file", default=None,
                   help=".env file to load the API key from (default: ./.env in the current dir or the scanned project)")
    args = p.parse_args(argv)

    root = Path(args.project)
    if not root.exists():
        print(f"error: project not found: {root}", file=sys.stderr)
        return 1

    # .env first, before anything reads OPENROUTER_API_KEY / GROQ_API_KEY.
    # A real env var always wins; a missing .env is silent and normal.
    dotenv_summary = load_dotenv_file(path=args.env_file, project=root)
    _report_dotenv(dotenv_summary)

    # The .env case: a key in .env IS the request to use the LLM, so a
    # plain `scan` (no --with-llm) uses it. --no-llm always wins.
    use_llm = should_use_llm(args.with_llm, args.no_llm, llm_key_present())
    # No --model: default model WITH the free-model fallback chain.
    # Explicit --model: exactly that model, no fallback.
    model, allow_fallback = resolve_model_choice(args.model)
    if use_llm and not args.with_llm:
        via = ".env" if any(k in dotenv_summary.get("loaded", [])
                            for k in ("OPENROUTER_API_KEY", "GROQ_API_KEY")) else "the environment"
        print(f"LLM: key found via {via}, resolver on (use --no-llm to skip it)")
    elif args.with_llm and not llm_key_present():
        print("LLM: --with-llm passed but no key found — put it in .env "
              "(OPENROUTER_API_KEY=...) and re-run; staying uncertain for now")

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
    return _run_scan(root, advisories, cache, use_llm, model,
                     allow_fallback, args)[1]


if __name__ == "__main__":
    raise SystemExit(main())
