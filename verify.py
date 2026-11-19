#!/usr/bin/env python3
"""One-command verification for pyreach, Phases 1-5 + explainer + HTML report.

Usage, from the project root:
    python3 verify.py            # offline: pytest + 38 fixture scans + prompt + witness + explain + quiet/HTML + scan-all + VEX
    python3 verify.py --live     # also: real OSV fetch for PyYAML 5.3.1 (needs network)

Every check prints PASS or FAIL with what it expected and what it got.
Exit code 0 only if every check passes. No API key needed for any check.

What it proves, in order:
  A. the unit suite (189 tests) — the deterministic core + explainer + HTML report + LLM status
  B. all 35 fixtures give the expected verdict AND exit code
     (exit 2 = reachable, exit 0 = not_reachable / uncertain)
  C. --print-prompt works with no key (Phase 4 demo)
  D. --with-proof witnesses a real path, keeps a wrapper's middle,
     and never downgrades when the entry needs args (Phase 5)
  E. --explain explains uncertain results deterministically, with the
     footer, and `explain` replays them from an existing report
  F. quiet terminal (no line over ~500 chars, no evidence dump) and
     the readable HTML report next to the JSON, regenerable with
     `pyreach report`
  H. `pyreach llm-test` with no key reports kind no_key, exit 1, and
     prints no key value (the MkDocs diagnostic: a silent LLM failure
     must name itself, not look like "not tried")
  I. Phase 7 `pyreach scan-all` (offline, --advisory-dir): every
     dependency resolved, PyYAML scanned and reachable, a package with
     no advisory file marked not-checked, a range-only dependency
     skipped and listed — never guessed, never silently dropped
  J. Phase 8 OpenVEX aggregation: a reachable finding blocks the
     not_affected statement for its advisory; an all-clear advisory
     still gets exactly one statement
  G. (--live) the real OSV -> fix-commit -> candidates pipeline
     for PyYAML 5.3.1, the case Phase 1 was built on (runs last)
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ADV = str(ROOT / "examples" / "advisory-sample.json")

# fixture -> (expected verdict of the first result, expected exit code)
EXPECTED = {
    "app_vuln": ("reachable", 2),
    "app_safe": ("not_reachable", 0),
    "app_dead": ("not_reachable", 0),
    "app_getattr": ("not_reachable", 0),
    "app_wrapper": ("reachable", 2),
    "app_route": ("reachable", 2),
    "app_top": ("reachable", 2),
    "app_nested": ("reachable", 2),
    "app_method": ("reachable", 2),
    "app_star": ("reachable", 2),
    "app_alias": ("reachable", 2),
    "app_console": ("reachable", 2),
    "app_django": ("reachable", 2),
    "app_library": ("reachable", 2),
    "app_click": ("reachable", 2),
    "app_getattr_load": ("reachable", 2),
    "app_getattr_loop": ("not_reachable", 0),
    "app_getattr_config": ("uncertain", 0),
    "app_getattr_branch": ("reachable", 2),
    "app_getattr_reassign": ("not_reachable", 0),
    "app_getattr_concat": ("not_reachable", 0),
    "app_importlib": ("reachable", 2),
    "app_witness_wrapper": ("reachable", 2),
    "app_proof_args": ("reachable", 2),
    "app_getattr_mixed": ("uncertain", 0),
    "app_load_collision": ("reachable", 2),
    # Phase 8 (ChatGPT review fixes, 19 Nov 2026)
    "app_unresolved_attr": ("uncertain", 0),   # Critical 1: .load() via variable
    "app_never_imported": ("not_reachable", 0),  # Critical 4: dead module
    "app_vex_full": ("reachable", 2),          # Critical 2: yaml.load reachable
    "app_unparsed": ("uncertain", 0),          # Critical 5: completeness gate
    "app_mockpatch": ("not_reachable", 0),     # Critical 4: @mock.patch phantom
    "app_dunder": ("uncertain", 0),            # dunder __getattr__ site runs
    # Evaluation fixes (19 Nov 2026)
    "app_console_ambig": ("reachable", 2),  # console script pkg.cli:run
    "app_console_reexport": ("reachable", 2),  # console script via re-export
    "app_library_all": ("reachable", 2),  # __all__ + console script both entries
    # Demo fixes (19 Nov 2026): app_same_name is unit-test-only (its
    # verdict depends on the advisory, not the sample one); app_init_call
    # does not import yaml, so yaml.load is uncertain (internal rule).
    "app_init_call": ("uncertain", 0),  # Retry.__init__ reachable (unit test)
    "app_rel_import": ("uncertain", 0),  # relative import + ctor chain (unit test)
    "app_all_class": ("uncertain", 0),  # class in __all__ -> __init__ entry (unit test)
}

passed = failed = 0


def check(name: str, ok: bool, detail: str = ""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


def run(args, **kw):
    return subprocess.run([sys.executable, *args], cwd=ROOT,
                          capture_output=True, text=True, timeout=120, **kw)


def _have(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except ImportError:
        return False


def _read_report(path: Path):
    """Report JSON or None if the scan never wrote one (crash)."""
    try:
        # Reports are written UTF-8; on Windows read_text() defaults
        # to cp1252 and crashes on the em-dashes in reasons (19 Nov 2026).
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def main() -> int:
    live = "--live" in sys.argv
    tmp = Path(tempfile.mkdtemp(prefix="pyreach-verify-"))
    # Dependency precheck, so a missing package shows up as one clear
    # line instead of 24 identical failures. On Windows, make sure you
    # run this with the venv Python (`python verify.py`, NOT `python3`,
    # which can be a different, system Python with nothing installed).
    has_yaml = _have("yaml")
    has_requests = _have("requests")
    print(f"dependencies: yaml={'yes' if has_yaml else 'MISSING (pip install pyyaml)'}  "
          f"requests={'yes' if has_requests else 'MISSING (pip install requests)'}")
    if not has_yaml:
        print("  NOTE: the fixtures import yaml, so the witness checks (D) "
              "will fail until you install it. The static scans (B) do not need it.")
    if live and not has_requests:
        print("  NOTE: --live needs requests; skipping the live fetch.")
        live = False

    print("A. unit tests")
    # pytest if present, else stdlib unittest (the tests are unittest
    # TestCases, so both run the same 145 tests). pytest is not part of
    # a default Python install, and a fresh VM may not have it.
    r = run(["-m", "pytest", "tests", "-q"])
    if "No module named pytest" in r.stderr:
        r = run(["-m", "unittest", "discover", "-s", "tests", "-q"])
        detail = (r.stderr.strip().splitlines() or [""])[-1]
        check("unittest suite (189 tests, pytest not installed)", r.returncode == 0, detail)
    else:
        check("pytest suite (189 tests)", r.returncode == 0,
              r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-300:])

    print("B. fixture scans (sample advisory, no network)")
    for name, (verdict, code) in EXPECTED.items():
        out = tmp / f"{name}.json"
        r = run(["-m", "pyreach.cli", "scan", f"fixtures/{name}",
                 "--advisory", ADV, "--out", str(out),
                 "--cache-dir", str(tmp / "cache")])
        rep = _read_report(out)
        if rep is None:
            # The scan crashed before writing a report. Show the CLI's
            # own error instead of a bare "no such file" — that is what
            # the old verify.py did, and it hid the real cause.
            err = (r.stderr.strip() or r.stdout.strip()).splitlines()
            got = f"<scan crashed, exit={r.returncode}: {err[-1] if err else 'no output'}>"
        else:
            got = rep["results"][0]["verdict"]
        check(f"{name}: {verdict}, exit {code}",
              got == verdict and r.returncode == code,
              f"got verdict={got} exit={r.returncode}")

    print("C. Phase 4 --print-prompt (no key needed)")
    r = run(["-m", "pyreach.cli", "scan", "fixtures/app_getattr_config",
             "--advisory", ADV, "--print-prompt",
             "--out", str(tmp / "p.json"), "--cache-dir", str(tmp / "cache")])
    check("prompt printed, same-file candidates only",
          "Functions that actually exist in this module" in r.stdout
          and "app.load_config" in r.stdout and r.returncode == 0,
          r.stdout[-200:] + r.stderr[-200:])

    print("D. Phase 5 --with-proof witness")
    r = run(["-m", "pyreach.cli", "scan", "fixtures/app_witness_wrapper",
             "--advisory", ADV, "--with-proof",
             "--out", str(tmp / "w.json"), "--cache-dir", str(tmp / "cache")])
    rep = _read_report(tmp / "w.json")
    proof = (rep or {}).get("proofs", {}).get("OSV-2020-1234", {}) if rep else {}
    check("wrapper middle kept in trace",
          proof.get("vulnerable_hit") is True
          and any("parse_config" in t for t in proof.get("trace", [])),
          f"trace={proof.get('trace')} stderr={r.stderr.strip()[-200:] if r.stderr.strip() else ''}")
    r = run(["-m", "pyreach.cli", "scan", "fixtures/app_proof_args",
             "--advisory", ADV, "--with-proof",
             "--out", str(tmp / "a.json"), "--cache-dir", str(tmp / "cache")])
    rep = _read_report(tmp / "a.json")
    proof = (rep or {}).get("proofs", {}).get("OSV-2020-1234", {}) if rep else {}
    verdict = rep["results"][0]["verdict"] if rep else "<no report>"
    check("failed witness never downgrades (still reachable)",
          verdict == "reachable"
          and proof.get("vulnerable_hit") is False
          and "TypeError" in str(proof.get("error")),
          f"verdict={verdict} proof={proof}")

    print("E. explainer --explain (deterministic only, no key needed)")
    r = run(["-m", "pyreach.cli", "scan", "fixtures/app_getattr_config",
             "--advisory", ADV, "--explain", "--no-llm",
             "--out", str(tmp / "e.json"), "--cache-dir", str(tmp / "cache")])
    rep = _read_report(tmp / "e.json")
    exps = (rep or {}).get("explanations", []) if rep else []
    check("scan --explain: 1 explanation, dynamic_call, footer, no LLM",
          len(exps) == 1 and exps[0]["blocker"] == "dynamic_call"
          and "verdict remains UNCERTAIN" in exps[0]["deterministic_explanation"]
          and 'config["func"]' in exps[0]["deterministic_explanation"]
          and exps[0]["llm_explanation"] is None
          and exps[0]["llm_rejected"] is False
          # The diagnostic: with --no-llm the layer never ran, and the
          # explanation must SAY so (llm_status "not_called"), not leave
          # a bare null that looks like a silent failure.
          and exps[0].get("llm_status") == "not_called"
          and exps[0].get("llm_error") is None
          and exps[0]["does_not_know"]
          and exps[0]["evidence_pack_tokens"] <= 1500
          and r.returncode == 0,
          f"explanations={exps} exit={r.returncode}")
    r = run(["-m", "pyreach.cli", "explain", "--report", str(tmp / "e.json"),
             "--project", "fixtures/app_getattr_config", "--no-llm"])
    check("explain replays from the report without re-scanning",
          "Blocker: dynamic_call" in r.stdout and r.returncode == 0,
          r.stdout[-200:] + r.stderr[-200:])
    r = run(["-m", "pyreach.cli", "scan", "fixtures/app_vuln",
             "--advisory", ADV, "--explain", "--no-llm",
             "--out", str(tmp / "e2.json"), "--cache-dir", str(tmp / "cache")])
    rep = _read_report(tmp / "e2.json")
    check("scan --explain with no uncertain results: empty list, exit 2",
          (rep or {}).get("explanations") == [] and r.returncode == 2,
          f"explanations={(rep or {}).get('explanations')} exit={r.returncode}")

    print("F. quiet terminal + readable HTML report (19 Nov 2026 fix)")
    r = run(["-m", "pyreach.cli", "scan", "fixtures/app_getattr_config",
             "--advisory", ADV, "--explain", "--no-llm",
             "--out", str(tmp / "f.json"), "--cache-dir", str(tmp / "cache")])
    longest = max((len(ln) for ln in r.stdout.splitlines()), default=0)
    html_path = tmp / "f.html"
    page = html_path.read_text(encoding="utf-8") if html_path.exists() else ""
    rep = _read_report(tmp / "f.json")
    check("quiet scan: no line over 500 chars, no evidence dump, HTML written",
          longest < 500 and "entry evidence: {" not in r.stdout
          and "explain [uncertain] yaml.load" in r.stdout
          and html_path.exists() and "yaml.load" in page
          and "The verdict remains UNCERTAIN" in page
          and (rep or {}).get("html_report") == "f.html"
          and r.returncode == 0,
          f"longest={longest} html_exists={html_path.exists()} exit={r.returncode}")
    r = run(["-m", "pyreach.cli", "report", "--report", str(tmp / "f.json"),
             "--out", str(tmp / "f-regen.html")])
    regen = (tmp / "f-regen.html").read_text(encoding="utf-8") if (tmp / "f-regen.html").exists() else ""
    check("pyreach report regenerates HTML from an existing report.json",
          r.returncode == 0 and "yaml.load" in regen,
          r.stdout[-200:] + r.stderr[-200:])

    print("H. llm-test diagnosis with no key (no network call)")
    # Run in the temp dir (no .env there) with any key stripped from
    # the environment, so this check is offline and cannot leak a key:
    # a real key in the parent environment must not make this test
    # attempt a live call, and must not appear in the output.
    import os as _os
    clean_env = {k: v for k, v in _os.environ.items()
                 if k not in ("OPENROUTER_API_KEY", "GROQ_API_KEY", "LLM_BASE_URL")}
    # cwd=tmp so no .env is found by the walk-up; PYTHONPATH=ROOT so
    # `python -m pyreach.cli` still resolves from the temp dir.
    clean_env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run([sys.executable, "-m", "pyreach.cli", "llm-test"],
                       cwd=tmp, capture_output=True, text=True,
                       timeout=60, env=clean_env)
    check("llm-test with no key: kind no_key, exit 1, no key printed",
          r.returncode == 1 and "no_key" in r.stdout
          and "sk-" not in r.stdout and "sk-" not in r.stderr,
          f"exit={r.returncode} stdout={r.stdout[-200:]!r} stderr={r.stderr[-200:]!r}")

    print("I. Phase 7 scan-all (offline, --advisory-dir)")
    r = run(["-m", "pyreach.cli", "scan-all", "fixtures/app_scanall",
             "--advisory-dir", "fixtures/app_scanall_advisories",
             "--no-llm", "--no-html",
             "--out", str(tmp / "s.json"), "--vex", str(tmp / "s-vex.json"),
             "--cache-dir", str(tmp / "cache")])
    rep = _read_report(tmp / "s.json")
    pkgs = {p["name"]: p for p in (rep or {}).get("packages", [])}
    yaml_load = [x for x in (rep or {}).get("results", [])
                 if x.get("vulnerable_function") == "yaml.load"]
    check("scan-all: PyYAML scanned+reachable, requests not-checked, range-only skipped",
          (rep or {}).get("mode") == "scan-all"
          and pkgs.get("PyYAML", {}).get("status") == "scanned"
          and pkgs.get("PyYAML", {}).get("version") == "5.3.1"
          and pkgs.get("PyYAML", {}).get("results", {}).get("reachable") == 1
          and pkgs.get("requests", {}).get("status") == "not-checked"
          and pkgs.get("pyreach-skip-demo", {}).get("status") == "skipped"
          and len(yaml_load) == 1 and yaml_load[0]["verdict"] == "reachable"
          and "scan-all packages:" in r.stdout
          and r.returncode == 2,
          f"packages={pkgs} exit={r.returncode}")
    r = run(["-m", "pyreach.cli", "scan-all", "fixtures/app_scanall",
             "--advisory-dir", "fixtures/app_scanall_advisories",
             "--only", "pyyaml",
             "--no-llm", "--no-html",
             "--out", str(tmp / "s2.json"), "--vex", str(tmp / "s2-vex.json"),
             "--cache-dir", str(tmp / "cache")])
    rep2 = _read_report(tmp / "s2.json")
    check("scan-all --only pyyaml scans just that package",
          [p["name"] for p in (rep2 or {}).get("packages", [])] == ["PyYAML"]
          and r.returncode == 2,
          f"packages={(rep2 or {}).get('packages')} exit={r.returncode}")

    print("J. Phase 8 OpenVEX aggregation (ChatGPT Critical 2, 19 Nov 2026)")
    # app_vex_full against the REAL PyYAML advisory: yaml.load is
    # reachable, so the advisory gets NO not_affected statement even
    # though two candidates are not_reachable.
    REAL = str(ROOT / "examples" / "advisory-real-pyyaml.json")
    r = run(["-m", "pyreach.cli", "scan", "fixtures/app_vex_full",
             "--advisory", REAL, "--no-llm", "--no-html",
             "--out", str(tmp / "j1.json"), "--vex", str(tmp / "j1-vex.json"),
             "--cache-dir", str(tmp / "cache")])
    vex1 = _read_report(tmp / "j1-vex.json") or {}
    check("app_vex_full + real advisory: reachable present, 0 VEX statements",
          len(vex1.get("statements", [])) == 0 and r.returncode == 2,
          f"statements={vex1.get('statements')} exit={r.returncode}")
    # app_safe: the one candidate is genuinely not_reachable and the
    # ledger is complete, so exactly one statement is emitted.
    r = run(["-m", "pyreach.cli", "scan", "fixtures/app_safe",
             "--advisory", ADV, "--no-llm", "--no-html",
             "--out", str(tmp / "j2.json"), "--vex", str(tmp / "j2-vex.json"),
             "--cache-dir", str(tmp / "cache")])
    vex2 = _read_report(tmp / "j2-vex.json") or {}
    check("app_safe: 1 VEX statement for the all-clear advisory",
          len(vex2.get("statements", [])) == 1
          and vex2["statements"][0]["status"] == "not_affected"
          and r.returncode == 0,
          f"statements={vex2.get('statements')} exit={r.returncode}")
    # app_never_imported: dead module, same all-clear result.
    r = run(["-m", "pyreach.cli", "scan", "fixtures/app_never_imported",
             "--advisory", ADV, "--no-llm", "--no-html",
             "--out", str(tmp / "j3.json"), "--vex", str(tmp / "j3-vex.json"),
             "--cache-dir", str(tmp / "cache")])
    vex3 = _read_report(tmp / "j3-vex.json") or {}
    check("app_never_imported: 1 VEX statement, dead module not an entry",
          len(vex3.get("statements", [])) == 1 and r.returncode == 0,
          f"statements={vex3.get('statements')} exit={r.returncode}")

    if live:
        print("G. live OSV fetch (network)")
        out = tmp / "live-advisories.json"
        r = run(["-m", "pyreach.cli", "fetch", "PyYAML", "5.3.1",
                 "--out", str(out)])
        rep = _read_report(out)
        try:
            advs = rep if isinstance(rep, list) else json.loads(out.read_text(encoding="utf-8"))
            ids = [a.get("id") for a in advs]
            cands = sum(len(a.get("vulnerable_functions", [])) for a in advs)
        except Exception as e:
            ids, cands = [], f"<no output: {e}; stderr={r.stderr.strip()[-200:]}>"
        check("PyYAML 5.3.1 -> GHSA-8q59-q68h-6hv4, >=1 candidate",
              "GHSA-8q59-q68h-6hv4" in ids and isinstance(cands, int) and cands >= 1,
              f"ids={ids} candidates={cands}")

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
