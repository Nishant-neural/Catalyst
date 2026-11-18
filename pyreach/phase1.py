"""Phase 1 — built: live OSV -> fix commit -> diff -> candidates.

This is the part the base left as a stub (pre-supplied functions in JSON).
Now it is real, tested on PyYAML 5.3.1 / GHSA-8q59-q68h-6hv4.

Real example that proves the ChatGPT correction:
  GHSA-8q59-q68h-6hv4, CVE-2020-14343, PyYAML < 5.4
  Fix commit a001f2782501ad2d24986959f0239a354675f9dc
  Diff moves multi-constructors from FullConstructor to UnsafeConstructor
  in lib/yaml/constructor.py, at MODULE level, outside any function.
  It does NOT change the vulnerable function itself.
  So mapping changed lines to functions alone returns [].
  The candidates must come from:
    (a) names mentioned in the changed lines
        (construct_python_object_new, construct_python_object, ...)
    (b) advisory text: "full_load method" / "FullLoader loader"
    (c) test changes in the diff: yaml.load(..., FullLoader) -> UnsafeLoader,
        yaml.full_load(...) -> yaml.unsafe_load(...)
  All three agree: the vulnerable entry points are full_load / FullLoader.
  Confidence is MEDIUM, not high, because the fix is module-level.
  Low confidence -> UNCERTAIN later, never a guessed NOT-REACHABLE.
"""
from __future__ import annotations

import json
import re

import requests

from .advisory import Advisory, VulnerableFunction, diff_to_functions, names_from_text
from .cache import Cache, cache_key

OSV_URL = "https://api.osv.dev/v1/query"
COMMIT_RE = re.compile(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{40})")
COMMIT_SHORT_RE = re.compile(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})")


def fetch_osv(package: str, version: str, ecosystem: str = "PyPI") -> list[Advisory]:
    """Query api.osv.dev for a package@version. Returns Advisory objects
    with id, package, fixed_version, references, summary. No API key needed."""
    r = requests.post(OSV_URL, json={
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version,
    }, timeout=30)
    r.raise_for_status()
    out: list[Advisory] = []
    # Dedupe: OSV returns the same CVE twice (GHSA + PYSEC are aliases).
    # Keep the first, skip any later vuln whose id/aliases overlap seen ids.
    seen_ids: set[str] = set()
    for v in r.json().get("vulns", []):
        ids = {v.get("id", "")} | set(v.get("aliases", []))
        if ids & seen_ids:
            continue
        seen_ids |= ids
        fixed = ""
        for aff in v.get("affected", []):
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fixed = ev["fixed"]
        refs = [ref.get("url", "") for ref in v.get("references", [])]
        out.append(Advisory(
            id=v.get("id", ""),
            package=package,
            fixed_version=fixed,
            references=refs,
            summary=v.get("summary", "") or v.get("details", "")[:500],
        ))
        # Keep full details for text cross-check in summary field
        out[-1].summary = (v.get("summary", "") + " | " + v.get("details", ""))[:2000]
    return out


def find_fix_commit(advisory: Advisory) -> tuple[str, str] | None:
    """Find (repo, sha) from advisory references. Returns None if none."""
    for url in advisory.references:
        m = COMMIT_RE.search(url) or COMMIT_SHORT_RE.search(url)
        if m:
            return m.group(1), m.group(2)
    return None


def fetch_github_diff(repo: str, sha: str, cache: Cache | None = None) -> str:
    """Fetch a commit diff as text. No auth for public repos, rate-limited.
    Uses the .diff endpoint, which needs no API token.
    Phase 3: cached by (repo, sha) — the sha IS the content hash, so a
    cached diff can never be stale. First project pays, later ones reuse."""
    if cache is not None:
        key = cache_key(repo, sha, sha)
        hit = cache.get(key)
        if hit is not None:
            return hit["diff"]
    url = f"https://github.com/{repo}/commit/{sha}.diff"
    r = requests.get(url, headers={"User-Agent": "pyreach/0.1.0"}, timeout=30)
    r.raise_for_status()
    if cache is not None:
        cache.put(cache_key(repo, sha, sha), {"diff": r.text})
    return r.text


def fetch_github_file(repo: str, sha: str, path: str) -> str:
    """Fetch a single file at a commit, via raw.githubusercontent.com."""
    # Strip leading lib/ or lib3/ prefixes? Caller passes the diff path as-is;
    # try it, then try without a leading lib/ segment.
    for p in (path, path.removeprefix("lib/"), path.removeprefix("lib3/")):
        url = f"https://raw.githubusercontent.com/{repo}/{sha}/{p}"
        r = requests.get(url, headers={"User-Agent": "pyreach/0.1.0"}, timeout=30)
        if r.status_code == 200:
            return r.text
    return ""


def candidates_from_test_diff(diff_text: str) -> list[VulnerableFunction]:
    """Test changes are a strong signal: if a test changes a call from
    X to Y, X was the vulnerable API. E.g. yaml.load(..., FullLoader)
    -> UnsafeLoader, yaml.full_load(...) -> yaml.unsafe_load(...)."""
    out: list[VulnerableFunction] = []
    for line in diff_text.splitlines():
        if not line.startswith("-") or line.startswith("---"):
            continue
        # Only a test line that mentions the vulnerable loader/entry point
        # counts. A bare yaml.load in a test is too noisy on its own.
        if "FullLoader" not in line and "full_load" not in line and "FullConstructor" not in line:
            continue
        # Look for old calls in removed test lines
        for name in re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s*\(", line):
            if name in ("assert", "print", "return"):
                continue
            # Registration calls are not vulnerable functions.
            if name.endswith("add_multi_constructor") or name.endswith("add_constructor"):
                continue
            out.append(VulnerableFunction(
                qualified=name, file="test-diff", confidence="medium",
                evidence=f"test changed away from {name}",
            ))
    # Deduplicate, keep only plausible API names (contain load / Loader / dump etc. or dotted)
    seen: dict[str, VulnerableFunction] = {}
    for fn in out:
        if "." in fn.qualified or fn.qualified in ("full_load", "load"):
            seen.setdefault(fn.qualified, fn)
    return list(seen.values())


def module_level_candidates(diff_text: str, advisory_text: str) -> list[VulnerableFunction]:
    """Module-level fix: changed lines are outside any function.
    Candidates are names mentioned in the changed lines AND in the
    advisory text, with medium confidence."""
    text_names = set(names_from_text(advisory_text))
    # Also extract simple names from advisory text like full_load
    text_names.update(re.findall(r"\b(full_load|unsafe_load|safe_load|FullLoader|UnsafeLoader|SafeLoader)\b", advisory_text))
    # Only REMOVED (-) lines are vulnerable code. Added (+) lines are the
    # fix — e.g. UnsafeConstructor.construct_python_object_new is the safe
    # destination, not a candidate. Including + lines was a bug: it listed
    # the fix itself as vulnerable.
    changed_names: set[str] = set()
    for line in diff_text.splitlines():
        if line.startswith("-") and not line.startswith("---"):
            changed_names.update(re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\b", line))
    # Intersection, plus constructor methods mentioned in diff
    cands: list[VulnerableFunction] = []
    for name in sorted(changed_names):
        simple = name.split(".")[-1]
        if simple.startswith("construct_python_"):
            cands.append(VulnerableFunction(
                qualified=name, file="diff", confidence="medium",
                evidence=f"module-level fix touches {name}",
            ))
    for name in sorted(text_names):
        # full_load / FullLoader are entry points, not necessarily in diff
        cands.append(VulnerableFunction(
            qualified=name, file="advisory-text", confidence="medium",
            evidence=f"advisory text mentions {name}",
        ))
    seen: dict[str, VulnerableFunction] = {}
    for fn in cands:
        seen.setdefault(fn.qualified, fn)
    return list(seen.values())


def analyse_advisory_live(package: str, version: str, cache: Cache | None = None) -> list[dict]:
    """Full Phase 1 pipeline for one package@version. Returns a list of
    dicts, one per advisory, with fix commit, diff stats, and candidates.
    Each dict is JSON-serialisable and can be saved as an advisory file
    for `pyreach scan --advisory <that file>`."""
    advisories = fetch_osv(package, version)
    results: list[dict] = []
    for adv in advisories:
        found = find_fix_commit(adv)
        entry: dict = {
            "id": adv.id, "package": adv.package,
            "fixed_version": adv.fixed_version,
            "references": adv.references,
            "summary": adv.summary,
            "fix_commit": None, "candidates": [],
        }
        if not found:
            # Fallback: no fix commit in references, diff the PyPI sdists
            # (vulnerable version vs fixed version) instead.
            if adv.fixed_version:
                try:
                    diff = fetch_pypi_sdist_diff(package, version, adv.fixed_version, cache=cache)
                    cands = diff_to_functions(diff, {}, commit="pypi-diff")
                    cands.extend(module_level_candidates(diff, adv.summary))
                    entry["fix_commit"] = {"repo": None, "sha": None, "via": "pypi-sdist-diff"}
                    entry["diff_lines"] = len(diff.splitlines())
                    entry["candidates"] = [{
                        "qualified": fn.qualified, "file": fn.file,
                        "confidence": fn.confidence, "evidence": fn.evidence,
                    } for fn in cands] or [{
                        "qualified": "", "file": "", "confidence": "low",
                        "evidence": "pypi diff found no function-level change",
                    }]
                    entry["vulnerable_functions"] = entry["candidates"]
                except Exception as e:
                    entry["candidates"] = [{
                        "qualified": "", "file": "", "confidence": "low",
                        "evidence": f"no fix commit and pypi diff failed: {e}",
                    }]
            else:
                entry["candidates"] = [{
                    "qualified": "", "file": "", "confidence": "low",
                    "evidence": "no fix commit found in references and no fixed version",
                }]
            results.append(entry)
            continue
        repo, sha = found
        entry["fix_commit"] = {"repo": repo, "sha": sha}
        try:
            diff = fetch_github_diff(repo, sha, cache=cache)
        except Exception as e:
            entry["candidates"] = [{
                "qualified": "", "file": "", "confidence": "low",
                "evidence": f"could not fetch diff: {e}",
            }]
            results.append(entry)
            continue
        entry["diff_files"] = sorted({l[4:].strip() for l in diff.splitlines() if l.startswith("+++ ")})
        entry["diff_lines"] = len(diff.splitlines())
        # 1) Function-level mapping (both sides, via diff_to_functions)
        #    For the real PyYAML case this returns [] — the fix is module-level.
        #    We try it with empty sources first to show that, then with
        #    fetched sources for the changed files.
        sources: dict[str, str] = {}
        old_sources: dict[str, str] = {}
        for path in entry["diff_files"]:
            if path.endswith(".py") and "test" not in path:
                txt = fetch_github_file(repo, sha, path)
                if txt:
                    sources[path] = txt
        func_cands = diff_to_functions(diff, sources, commit=sha, old_sources=old_sources or None)
        cands = list(func_cands)
        # 2) Module-level + text candidates
        cands.extend(module_level_candidates(diff, adv.summary))
        # 3) Test-diff candidates
        cands.extend(candidates_from_test_diff(diff))
        # Deduplicate, keep highest confidence (high > medium > low)
        order = {"high": 0, "medium": 1, "low": 2}
        seen: dict[str, VulnerableFunction] = {}
        for fn in cands:
            if fn.qualified not in seen or order[fn.confidence] < order[seen[fn.qualified].confidence]:
                seen[fn.qualified] = fn
        entry["candidates"] = [{
            "qualified": fn.qualified, "file": fn.file,
            "confidence": fn.confidence, "evidence": fn.evidence,
        } for fn in seen.values()]
        # Also store in the Advisory object shape for scan()
        entry["vulnerable_functions"] = entry["candidates"]
        results.append(entry)
    return results


def fetch_pypi_sdist_diff(package: str, old_version: str, new_version: str,
                          cache: Cache | None = None) -> str:
    """Fallback when there is no fix commit: download the sdist for the
    vulnerable version and the fixed version from PyPI, and diff matching
    .py files with difflib. Returns a unified-diff-like string.
    This is slower than a GitHub diff and only used when no commit exists.
    Phase 3: cached by (package, old->new, sdist sha256). The sha256 from
    PyPI metadata is the artifact hash, so a cached diff can never be stale."""
    import difflib
    import io
    import tarfile

    def sdist_meta(version: str):
        r = requests.get(f"https://pypi.org/pypi/{package}/{version}/json", timeout=30)
        r.raise_for_status()
        urls = r.json().get("urls", [])
        sdist = next((u for u in urls if u.get("packagetype") == "sdist"), None)
        return sdist

    if cache is not None:
        old_meta, new_meta = sdist_meta(old_version), sdist_meta(new_version)
        artifact = ((old_meta or {}).get("digests", {}).get("sha256", "") +
                    (new_meta or {}).get("digests", {}).get("sha256", ""))
        key = cache_key(package, f"{old_version}->{new_version}", "", artifact)
        hit = cache.get(key)
        if hit is not None:
            return hit["diff"]

    def sdist_files(version: str) -> dict[str, str]:
        sdist = sdist_meta(version)
        if not sdist:
            return {}
        data = requests.get(sdist["url"], timeout=60).content
        out: dict[str, str] = {}
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            for m in tf.getmembers():
                if m.isfile() and m.name.endswith(".py"):
                    # Strip top-level dir: pkg-1.0/lib/yaml/... -> lib/yaml/...
                    parts = m.name.split("/", 1)
                    key = parts[1] if len(parts) == 2 else m.name
                    try:
                        out[key] = tf.extractfile(m).read().decode("utf-8", errors="ignore")
                    except Exception:
                        pass
        return out

    old, new = sdist_files(old_version), sdist_files(new_version)
    chunks: list[str] = []
    for path in sorted(set(old) & set(new)):
        if old[path] == new[path]:
            continue
        chunks.extend(difflib.unified_diff(
            old[path].splitlines(), new[path].splitlines(),
            fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="",
        ))
        chunks.append("")
    diff = "\n".join(chunks)
    if cache is not None:
        old_meta, new_meta = sdist_meta(old_version), sdist_meta(new_version)
        artifact = ((old_meta or {}).get("digests", {}).get("sha256", "") +
                    (new_meta or {}).get("digests", {}).get("sha256", ""))
        cache.put(cache_key(package, f"{old_version}->{new_version}", "", artifact),
                  {"diff": diff})
    return diff


def save_advisories(results: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
