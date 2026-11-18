#!/usr/bin/env python3
"""One-command verification for pyreach, Phases 1-5.

Usage, from the project root:
    python3 verify.py            # offline: pytest + 25 fixture scans + prompt + witness
    python3 verify.py --live     # also: real OSV fetch for PyYAML 5.3.1 (needs network)

Every check prints PASS or FAIL with what it expected and what it got.
Exit code 0 only if every check passes. No API key needed for any check.

What it proves, in order:
  A. the unit suite (48 tests) — the deterministic core
  B. all 24 fixtures give the expected verdict AND exit code
     (exit 2 = reachable, exit 0 = not_reachable / uncertain)
  C. --print-prompt works with no key (Phase 4 demo)
  D. --with-proof witnesses a real path, keeps a wrapper's middle,
     and never downgrades when the entry needs args (Phase 5)
  E. (--live) the real OSV -> fix-commit -> candidates pipeline
     for PyYAML 5.3.1, the case Phase 1 was built on
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
        return json.loads(path.read_text())
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
    # TestCases, so both run the same 48 tests). pytest is not part of
    # a default Python install, and a fresh VM may not have it.
    r = run(["-m", "pytest", "tests", "-q"])
    if "No module named pytest" in r.stderr:
        r = run(["-m", "unittest", "discover", "-s", "tests", "-q"])
        detail = (r.stderr.strip().splitlines() or [""])[-1]
        check("unittest suite (48 tests, pytest not installed)", r.returncode == 0, detail)
    else:
        check("pytest suite (48 tests)", r.returncode == 0,
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

    if live:
        print("E. live OSV fetch (network)")
        out = tmp / "live-advisories.json"
        r = run(["-m", "pyreach.cli", "fetch", "PyYAML", "5.3.1",
                 "--out", str(out)])
        rep = _read_report(out)
        try:
            advs = rep if isinstance(rep, list) else json.loads(out.read_text())
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
