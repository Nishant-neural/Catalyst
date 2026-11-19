# Problem 1 — Solution Plan, Phases 1-5

> **Revised 18 Nov 2026 after ChatGPT review — see CHATGPT-REVIEW.md.**
> Main corrections adopted: fix-commit mapping is candidate generation
> (both sides of the diff), constant propagation runs BEFORE any LLM,
> completeness ledger is CORE not write-up only, execution "proof" is
> renamed dynamic execution WITNESS and is optional, entry points carry
> evidence, cache key includes artifact hash + parser version, and the
> schedule now prioritises core + completeness over the witness.
> Taint stays Phase 6, for later only.

## Core rule

Deterministic first, LLM second, fail-closed.

- A verdict must trace to evidence: a call path, a diff line, or a trace.
- Never mark a reachable vulnerability as not-reachable. That is the
  worst error in this problem, and the judges penalise it hardest.
- If you are unsure, say uncertain. Do not guess, do not drop the alert.
- The LLM never decides a verdict alone. It proposes, code verifies.

## What winning looks like

For each alert: reachable / not_reachable / uncertain, with the exact
call path as proof. For not_reachable, a valid OpenVEX file.
Most fixture verdicts right, 0 false not-reachable, honest uncertain
labels. A demo a maintainer can check by hand in 2 minutes.

## Inputs and outputs

Inputs: project folder, pinned `requirements.txt` / lockfile, alerts
from OSV / `pip-audit` JSON. Each alert has package, version range,
fixed version, references.

Outputs: `report.json` (one result per alert, with path, confidence,
reason), `openvex.json` (not_reachable only), terminal table,
PR comment text (see `debate.py`).

Exit codes: 0 = scan completed, no reachable found. 2 = reachable found.
Useful for CI.

---

## Phase 1 — Advisory to vulnerable functions (from the fix commit) ✅ BUILT

**Goal:** turn an alert into a list of vulnerable functions, with confidence.
**Files:** `pyreach/phase1.py` (live fetch), `pyreach/advisory.py` (diff mapping)
**Time:** hours 2-6 in the 24h plan.
**Status: built and tested live, 18 Nov.** Commands:
`python3 -m pyreach.cli fetch PyYAML 5.3.1 --out examples/advisory-real-pyyaml.json`
`python3 -m pyreach.cli scan fixtures/app_vuln --package PyYAML --version 5.3.1`
Real result: GHSA-8q59-q68h-6hv4 (CVE-2020-14343), fixed 5.4, commit
`a001f2782501`, 7 candidates, all medium confidence.

### What live testing proved (and fixed)

1. **The fix commit does NOT change the vulnerable function.** The PyYAML
   fix moves multi-constructors from `FullConstructor` to `UnsafeConstructor`
   at module level, outside any function. Mapping changed lines to functions
   alone returns []. Candidates must also come from names in the removed
   lines (`construct_python_object_new`, …), advisory text (`full_load`,
   `FullLoader`), and test changes (`yaml.load(..., FullLoader)` →
   `UnsafeLoader`, `yaml.full_load` → `yaml.unsafe_load`). Only REMOVED
   lines are vulnerable code — added lines are the fix, so `UnsafeConstructor.*`
   was wrongly listed as vulnerable in the first run and is now excluded.
2. **Library internals must never be a false not_reachable** (`pyreach/reach.py`).
   `FullConstructor.construct_python_object_new` is never called by project
   code — the library calls it internally when you call `yaml.load`. So a
   no-path BFS must not say not_reachable. It says uncertain, and
   `propagate_library_internals()` upgrades it to reachable when `yaml.load`
   is reachable. Test: `tests/test_reach_internal.py` (2 tests). On
   `app_safe` the internals stay uncertain (honest: dependency source not
   parsed), while `yaml.load` / `yaml.full_load` are still not_reachable.
3. **OSV dedupes by alias.** GHSA-8q59-q68h-6hv4 and PYSEC-2021-142 are the
   same CVE; `fetch_osv()` keeps the first and skips the alias.
4. **PyPI sdist fallback works.** PYSEC had no fix commit in its references,
   so `fetch_pypi_sdist_diff()` diffed PyYAML 5.3.1 vs 5.4 sdists and got the
   same candidates. Used only when no commit exists.
5. **OpenVEX is per result, not per run** (`pyreach/cli.py`). The old rule
   blocked all VEX if any result was uncertain, so 3 uncertain internals
   blocked VEX for `yaml.full_load`, which is provably not_reachable. Now
   VEX is written per not_reachable result when the graph is clean (no
   dynamic trigger, no ambiguous edge, project fully parsed). Uncertain
   results never produce VEX.

### Steps

1. Load advisories with `load_advisories()`. Accept OSV-style JSON
   (`{"results": [...]}` or a plain list). Keep id, package, fixed
   version, references, summary, and any pre-supplied
   `vulnerable_functions` (the sample file uses this for fixtures).
2. Find the fix commit. Look in OSV references for a commit URL.
   About 1,948 of 7,866 PyPA advisories link one directly.
   If no direct link, fall back to diffing the vulnerable version and
   the fixed version from PyPI (same method, bigger diff).
3. Get the diff. GitHub API or a shallow `git clone`, fetch only that
   commit. Ignore test files, docs, and version bumps.
4. Parse the diff with `parse_unified_diff()`. It returns
   `{file: set(new_file_line_numbers)}`. Only `+` lines count.
   Hunk headers `@@ -a,b +c,d @@` give the starting new line.
5. Map changed lines to functions with `diff_to_functions()`.
   Parse the fixed file with AST, get each function's start/end line,
   find which function contains each changed line.
6. Assign confidence:
   - **High:** 1-2 functions changed, change is inside the body.
     Example: fix for `yaml.load` only changes `load()` in `loader.py`.
   - **Medium:** 3-5 functions, or a helper used by the vulnerable function.
   - **Low:** more than 5 functions, only a constant changed, or no
     fix commit found at all.
7. Second signal only: `names_from_text()` extracts dotted names like
   `yaml.load` from the advisory text with a regex. If text and diff
   agree, raise confidence. If they disagree, keep the diff and lower
   confidence. Text alone never creates a vulnerable function.

### Design Question 1 — answer

How do you get from a fix commit to a list of vulnerable functions,
and how sure can you be?

You do it by diff, not by guessing. A fix commit by definition changes
the vulnerable code to fix it, so the functions its diff touches are
the candidates. You are sure when the diff is small and focused
(1-2 functions, high). You are less sure when the diff is a refactor
(many functions, low). When confidence is low, you do not guess —
the verdict later becomes uncertain, not not-reachable. That protects
you from the worst error.

### What to test

- Unit test in `tests/test_advisory.py`: a 2-line diff maps to `load()`.
- On fixtures: the sample advisory already lists `yaml.load` as high
  confidence, so Phase 1 is exercised end-to-end by the CLI.

### Cut if short on time

Keep the pre-supplied `vulnerable_functions` path in the advisory JSON.
That lets you demo Phases 2-5 even if live fix-commit fetching is not
finished. Do not fake a fix commit.

---

## Phase 2 — Call graph + reachability (deterministic) ✅ BUILT

**Goal:** build a call graph with AST only, then BFS from entry points.
**Files:** `pyreach/callgraph.py`, `pyreach/reach.py`
**Time:** hours 6-11.
**Status: built and hardened, 18 Nov. 15 tests pass (was 8).**
All 11 fixtures give the expected verdict via the CLI.

### What Phase 2 hardening fixed (8 changes in `callgraph.py`)

1. **Nested functions:** the old visitor set `current=None` after a nested
   def, so calls in the outer function *after* the nested def were dropped.
   Now `current` is a stack (save/restore). Fixture: `app_nested`.
2. **Top-level module code** is a pseudo-node `module.<module>`, and it is
   a real entry point (import runs it). A project calling `yaml.load` at
   import time with no `main()` was previously missed entirely.
   Fixture: `app_top`, path `app.<module> -> yaml.load`.
3. **`self.` / `cls.`** resolve to the enclosing class, even when another
   class has a same-named method (old: ambiguous -> uncertain).
   Fixture: `app_method`, path through `app.Loader.load_config ->
   app.Loader.helper`, not `SafeLoader`.
4. **Constructor receivers:** `Loader().load_config()` resolves to
   `module.Loader.load_config` (old: ambiguous on `load_config`).
5. **Dotted chains:** `a.b.load()` is reconstructed as a full dotted name
   with the base resolved through imports (old: returned just `load`).
6. **`import a.b.c`** binds `a`, not `a.b.c` (old map was wrong).
7. **Assignment aliases:** `load = yaml.load` then `load(f)` is a real call
   to `yaml.load`. Fixture: `app_alias`. Old code missed it — a false
   not-reachable, the worst failure.
8. **Star imports:** `from helpers import *` prefers the star-imported
   module when a simple name is ambiguous project-wide.
   Fixture: `app_star` (helpers vs legacy both define `parse_config`).
   Pass 2 also rebuilds edges from `raw_calls` only: the old code kept raw
   unqualified edges alongside resolved ones, and created external nodes
   for ANY dotted call — including `self.helper` and `config.load` (a local
   variable) — which polluted the graph and could false-match a target by
   simple name. External nodes are now created only when the base is a
   known import. Two bugs found while testing: the empty-module-node
   cleanup ran before pass 2 (when edge sets are still empty) and deleted
   live `<module>` nodes — it now runs after pass 2.

### What is still NOT handled (honest limits)

- `x = Loader(); x.load_config()` — variable type inference. Only direct
  `Loader().load_config()` and `self.` are resolved. An unknown-object
  method call is dropped, never guessed.
- Calls inside a lambda are attributed to the enclosing function (fine),
  but the lambda itself is not a node.
- Decorator calls are not graph edges; route handlers are entry points
  via Phase 3, not via the graph.

### Call graph — `callgraph.py`

1. Walk every `.py` file under the project root, `ast.parse()` only.
   Never import or execute code. This is also your safety story.
2. For each file, collect with `_FileVisitor`:
   - Function definitions: qualified name `module.Class.method` or
     `module.func`, with start/end line. Stored in `Graph.functions`.
   - Imports: `import yaml as y` maps `y -> yaml`, `from yaml import load`
     maps `load -> yaml.load`. Stored per file.
   - Calls: `Name` calls and `Attribute` calls (`obj.method()`).
     Resolve the base name through the import map where possible.
   - Dynamic triggers: `getattr`, `setattr`, `eval`, `exec`,
     `__import__`, `globals`, `locals`, `importlib.import_module`.
     Recorded in `Graph.dynamic` with file, line, caller. Not resolved here.
3. Pass 2, resolve raw call names to qualified functions:
   - Exact qualified match wins.
   - Simple-name match wins only if unique, preferring same-module.
   - If 2+ candidates, record in `Graph.ambiguous`, do not pick one.
   - If 0 candidates, it is an external library call; keep it only if
     it is a known import target, otherwise ignore it for BFS.
   - After resolution, drop edges that are not real functions in the graph.
     This keeps BFS honest.

Data structures: `Graph.functions: dict[qualified, FuncInfo]`,
`Graph.edges: dict[caller, set[callee]]`,
`Graph.ambiguous: dict[caller, set[candidates]]`,
`Graph.dynamic: list[{file, line, kind, caller}]`.

### Reachability — `reach.py`

`bfs_path(graph, starts, target)` returns the shortest path, or None.
Target matching is by qualified name, or by simple name suffix, so
`yaml.load` matches `yaml.load` and `yaml.loader.load` is not confused
with it unless the simple name is unique.

`analyze(advisories, graph, entrypoints)`:

- If a path exists -> **reachable**, confidence high if function
  confidence is high, else medium. Path is the evidence.
- If no path:
  - Function confidence low -> **uncertain**, low. Cannot prove absence.
  - A dynamic trigger is reachable from entry points -> **uncertain**, low.
    A hidden path may exist.
  - Ambiguous edges exist -> **uncertain**, medium.
  - Otherwise -> **not_reachable**, high/medium. BFS searched everything,
    no path, no dynamic trigger, no ambiguous edge.

This is the fail-closed rule in code. It is the same rule as Crater:
zero proof means unavailable, not validated.

### Why this works on the fixtures

The organisers give small apps pinned to known versions. Small apps
mean small graphs, direct imports, few dynamic tricks. BFS will find
true reachable cases, and will correctly say not-reachable when the
project only uses the safe function, e.g. `safe_load` vs `load`.

### What to test

- `fixtures/app_vuln` -> reachable, path `app.main -> app.load_config -> yaml.load`
- `fixtures/app_safe` -> not_reachable
- `fixtures/app_dead` -> not_reachable (see Phase 3, entry points)
- `fixtures/app_getattr` -> uncertain (see Phase 4)

Run: `python -m pytest tests/ -q`

---

## Phase 3 — Real entry points, output, cache ✅ BUILT

**Goal:** only real starts count, then write JSON + OpenVEX, and cache
dependency parsing.
**Files:** `pyreach/entrypoints.py`, `pyreach/vex.py`, `pyreach/cache.py`, `pyreach/cli.py`
**Time:** hours 11-14. **BUILD NOW: this phase contains differentiator 3.**
**Status: built, 18 Nov. 23 tests pass (was 15). All 15 fixtures correct.**

### What Phase 3 hardening fixed

1. **console_scripts now feed BFS roots**, not just evidence. A CLI tool
   whose only entry is `pyproject [project.scripts]` fell back to "all
   public functions", so `dead()` became an entry. Fixture: `app_console`
   (only entry `app.run`, path never through `app.dead`).
2. **Django urlpatterns:** `path("upload/", views.upload)` resolves the
   view, preferring the views module. Fixture: `app_django`. Class-based
   views (`MyView.as_view()`) are unsupported, not guessed.
3. **Decorators:** `.put/.delete/.patch`, `click.group`, `.command(` added.
   Fixture: `app_click` (regression, old code already handled click.command).
4. **Library mode prefers `__all__`** in `__init__.py`, resolved to
   qualified functions. Old code took all public functions, so an
   unexported-but-public helper was an entry. Fixture: `app_library`
   (only entry `pkg.lib.load_config`).
5. **__main__ guard** prefers the same-module function; **__init__.py
   public functions are entries only in library mode** (old code added
   them in app mode too).
6. **Cache is actually wired now** (`phase1.py` + `cli.py`). GitHub diffs
   cache by `(repo, sha)` — the sha IS the content hash, so it can never
   be stale. PyPI sdist diffs cache by `(package, old->new, sdist sha256)`.
   Verified live: second `fetch PyYAML 5.3.1` is a cache hit, output
   byte-identical; a later scan reports `{'hits': 1, 'misses': 0}`.
   The cache key already included artifact hash + parser version
   (ChatGPT fix); what was missing was any caller.
7. **Report provenance:** `report.json` now has an `advisories` list
   (id, package, fixed_version, fix commit sha, candidate count), so a
   judge can reproduce the run from the report alone. Bug found: live
   advisory `fix_commit` is a dict, `load_advisories()` now extracts
   its sha.

### Honest limits

- `urls.<module>` shows up as an entry in the Django fixture (top-level
  `path()` calls run on import). Correct, just noisy; the verdict and
  the path are unaffected.
- Class-based Django views are not resolved. `x = Loader(); x.method()`
  is still unresolved (Phase 2 limit).

### 3a. Real entry points — `entrypoints.py` — BUILD NOW

A naive tool starts BFS from every function. Then dead code that calls
the vuln looks reachable. That is a false positive a maintainer judge
will spot immediately.

`find_entrypoints(root, graph)` returns `(entries, note)`:

- **App mode:** `main()`, functions decorated with `@app.route`,
  `@app.get`, `@app.post`, `@click.command`, and functions called
  inside an `if __name__ == "__main__":` block.
- **Library mode:** if there is a `pyproject.toml` and no `main.py` /
  `cli.py` / `app.py`, the public API is the entry surface: public
  (non-underscore) functions, especially in `__init__.py`.
- **Fallback:** if no entry is found at all, use public functions only
  and mark the note as fallback, low confidence. Never use every
  function silently.

Example: `fixtures/app_dead` has `dead()` calling `yaml.load()`, but
nothing calls `dead()`. Entry points are only `main()`, so BFS never
reaches `dead()`, verdict is not_reachable. That is the demo for this
differentiator, and it is a 1-fixture proof other teams will miss.

### 3b. Output — `vex.py`, `cli.py`

`report.json`: project, entry note, cache hits/misses, one result per
alert with advisory id, package, vulnerable function, verdict,
confidence, path, reason, plus proofs and PR comments.

`openvex.json`: built by `build_openvex()`. Only for not_reachable.
Each statement has vulnerability `@id`, product, status
`not_affected`, justification `vulnerable_code_not_in_execute_path`,
and status notes with the reason. If completeness is not 100% (see
Phase 5 ledger), do not write OpenVEX, write uncertain instead.

CLI: `pyreach scan <project> --advisory <json> --out report.json --vex openvex.json [--with-llm] [--with-proof]`
Exit 0 = scan completed, no reachable. Exit 2 = reachable found, for CI.

### 3c. Cache — `cache.py` — Design Question 3 answer

How do you cache analysis of popular packages so it is not repeated
for every project?

Key = `package@version-sha256(source)`, stored as JSON in `.reachcache/`.
`Cache.get(key)` / `Cache.put(key, data)` with hit/miss counters.

Rules: never cache project code, only dependencies. Invalidate on
hash change. If a version is not pinned, do not cache it as if it were.

Why it works: `requests`, `urllib3`, `yaml`, `jinja2` appear in almost
every project. First project pays the parse cost, every later project
reuses it. Show the hit rate in the report, e.g. "4 of 5 packages
from cache, 0.2s vs 3.1s fresh".

In this base, the CLI creates a `Cache` and reports hits/misses.
Wiring the dependency download + parse through the cache is the
next step in the hackathon: download the sdist for the pinned version,
parse it, save to cache, then load from cache on the next run.

### Design Question 3 — answer in one line

Cache by exact package identity and content hash, reuse across projects,
invalidate on any change, and never cache unpinned versions.

---


## Phase 4 — LLM resolver for dynamic / uncertain cases only ✅ BUILT

**Goal:** resolve getattr / importlib / plugin cases that deterministic
code must leave uncertain, without letting the LLM hallucinate a verdict.
**Files:** `pyreach/resolver.py`
**Time:** hours 14-18.

### When it runs

Only for results already marked uncertain in Phase 2, and only when a
dynamic trigger exists. It never runs on reachable or not_reachable,
and it never downgrades a deterministic reachable verdict.

### Prompt — `build_prompt()` — copy-pasteable

- Model: small open-weight, gpt-oss 20B or Llama 3.1 8B, via a free
  provider (OpenRouter / Groq). Temperature 0.
- Input, one call site at a time: 30-50 lines around the call, the list
  of functions that actually exist in that module from AST (pick ONLY
  from this list), string literals in the file, and the vulnerable
  functions for this advisory.
- Ask one question in strict JSON:
  `{"can_reach": true|false|"unknown", "possible_values": [...], "vulnerable_hit": "... or null", "reason": "...", "evidence_lines": [...], "confidence": 0.0}`
- Rules in the prompt: trace where the name / module string comes from.
  Literal? Loop over literals? Config / user input / env? If it comes
  from config, user input, or env, answer "unknown".

Worked examples:

- `name = "load"; func = getattr(yaml, name)` -> possible values
  `["load"]`, vulnerable hit `yaml.load`, reachable.
- `for name in ["safe_load", "dump"]: getattr(yaml, name)` -> possible
  values are safe, no hit, not_reachable.
- `name = config["func"]; func = getattr(yaml, name)` -> unknown,
  stay uncertain.

The full prompt is in `problem-1-getattr-resolver-prompt-and-verifier.md`
§4 if you have that file. Copy it, do not rewrite it from memory.

### Verifier — `verify_answer()` — 10 rules, deterministic

The LLM proposes, code decides. Verification checks:

1. Answer is a dict with all required keys.
2. `can_reach` is true, false, or "unknown".
3. `vulnerable_hit`, if set, is in the AST symbol table.
4. `possible_values` are strings, and any function name in them is in
   the symbol table.
5. `evidence_lines` are ints inside the source file.
6. Every cited line, when read from the source, actually contains a
   string or name from `possible_values` (byte-match check).
7. Confidence is 0-1, and >= 0.8 to upgrade from uncertain.
   0.8 is a starting value, tune it on the organisers' fixtures.
8. Never downgrade a deterministic reachable verdict.
9. If `can_reach` is true, `vulnerable_hit` must be non-null.
10. If `can_reach` is false, `possible_values` must be non-empty and
    none of them may be a vulnerable function.

If any rule fails, discard the LLM answer and stay uncertain.
If no API key is set (`OPENROUTER_API_KEY` / `GROQ_API_KEY`), the
resolver is skipped entirely and verdicts stay uncertain. That is safe.

### .env — where the key lives (19 Nov 2026)

`pyreach/dotenv.py` (stdlib only, no python-dotenv dependency) loads
the key from a `.env` file: `Copy-Item .env.example .env`, then one
line `OPENROUTER_API_KEY=sk-or-v1-...`. The CLI loads it at the start
of every `scan` and `fetch` (also `--env-file <path>`; the resolver
loads it as a fallback for library callers), looking in the current
directory (walking up), then the scanned project's directory.
Only `OPENROUTER_API_KEY`, `GROQ_API_KEY` and `LLM_BASE_URL` are ever
read — any other line is ignored, so a stray line cannot inject an
unrelated env var. A real environment variable always wins over
`.env`; a missing `.env` is silent and normal. The loader prints
only the file path and how many keys were loaded, never a value, and
`.env` is in `.gitignore` (`.env.example` is the template, no real
key in it). Verified 19 Nov 2026: 10 new tests in
`tests/test_dotenv.py` (59 tests total), plus an end-to-end scan with
a fake key in `.env` — the `.env:` line printed, the scan stayed
uncertain on app_getattr_config as it should, and the fake key
appeared nowhere in stdout, report.json or openvex.json.

**Auto-enable, 19 Nov 2026:** a key in `.env` IS the request to use
the LLM, so a plain `scan` (no `--with-llm`) now turns the resolver
on — `cli.should_use_llm()`: `--no-llm` always wins, otherwise
`--with-llm` or a present key enables it. The scan prints
`LLM: key found via .env, resolver on (use --no-llm to skip it)` and
records `"llm_enabled": true/false` in report.json, so you can check
afterwards whether the LLM was actually on. `--with-llm` still works;
with no key anywhere the resolver stays off. Verified with a fake
key: plain scan -> `llm_enabled: true`, `--no-llm` -> false, no `.env`
-> false. 63 tests total (4 new in `tests/test_llm_auto.py`).

### ✅ What Phase 4 actually built (23 Nov 2026, live-verified)

- `constant_propagate_getattr()` rewritten: source order (ast.walk is
  breadth-first, so reassignment resolved randomly), branch union
  (if/else `name = "load"` / `"safe_load"` -> both, fail-closed),
  sequential reassignment last-wins, string concat (`"safe_" + "load"`),
  var-to-var, and `importlib.import_module("yaml")` as the dynamic arg.
- `verify_answer()` fixes: rule 10's second half is now checked
  (can_reach false with possible_values ["load"] used to PASS);
  `can_reach: 1` no longer passes as true (1 == True in Python);
  a true/false verdict needs at least one evidence line.
- `resolve_getattr_case()` — one helper, constants first, LLM second,
  verifier decides. CLI tries EVERY uncertain result x EVERY dynamic
  site (base tried only dynamic[0]) and the prompt gets same-file
  functions only (base passed all project functions as "this module's").
- LLM answers cached by (model, sha256(prompt)) in `.reachcache`, so a
  re-scan does not re-spend a call. `--model` picks the model,
  `--print-prompt` prints the grounded prompt with no key at all.
- `import_module` alias in the call graph: `mod =
  importlib.import_module("yaml")` then `mod.load(f)` is yaml.load.
  Old code dropped it as attr-unresolved — a missed reachable.
- Live CLI results: app_getattr_load reachable, app_getattr_loop /
  reassign / concat not_reachable, app_getattr_branch reachable
  (branch union), app_getattr_config honestly uncertain,
  app_importlib reachable with full path. No key was needed for any
  of these — constants decided, LLM never called.

- **Aggregation fix, 19 Nov 2026 (found by the real PyYAML sdist scan):**
  one dynamic site's answer decided the whole result. A single
  `getattr(..., "encoding")` marked all 7 PyYAML candidates
  not_reachable, including yaml.load, which the test suite genuinely
  calls (via the test runner's dynamic dispatch, so no static path).
  Now: any site resolving to the vulnerable name -> reachable; ALL
  sites resolved safe -> not_reachable; otherwise uncertain, with the
  count in the reason ("resolved 9/51 dynamic sites safe, 42 still
  unknown"). Regression fixture app_getattr_mixed + test.
  The sdist scan now honestly reports 7 uncertain, 0 not_reachable.
- Default model is now `openai/gpt-oss-20b:free` — the :free suffix
  matters, without it OpenRouter bills the paid variant.
- Honest limits: no variable type inference (unchanged), no LLM run
  yet — the resolver needs OPENROUTER_API_KEY / GROQ_API_KEY and the
  0.8 threshold is still untested against organisers' fixtures.
- **Real-project tests, 19 Nov 2026 (see REAL_PROJECTS.md):**
  MkDocs (65 py) 4 reachable / 3 uncertain, exit 2, path
  `mkdocs.utils.meta.get_data -> yaml.load`; Cookiecutter (90 py)
  and pre-commit (134 py) 7/7 uncertain, exit 0. Two bugs found and
  fixed: (1) `yaml.load` mis-resolved to a test fake's `.load` by
  simple-name fallback — dotted library calls now resolve before
  that fallback (`fixtures/app_load_collision`); (2) external
  library functions were library-mode entry points, giving a bogus
  path `["yaml.load"]` — entries are project code only now.
  65 tests, verify.py offline 30/30. Still open: no real project
  reaches not_reachable (library internals 0/0 parsed + ambiguous
  edges block it), `functools.partial` wrappers are invisible, and
  the Loader argument is not distinguished.

### Design Question 2 — answer

How do you handle Python's dynamic features, such as getattr and
plugins loaded at runtime, without pretending to be certain?

First, detect them in AST and mark the alert uncertain. Then, and
only then, use a small LLM to trace where the dynamic string comes
from, with grounded context and a strict verifier. If the string is a
literal or a loop over literals, you can resolve it. If it comes from
config, user input, or env, you stay uncertain. You never pretend a
dynamic call is safe just because you cannot see the target.

### What to test

- `fixtures/app_getattr` with `name = "safe_load"` -> LLM should
  resolve to not_reachable, verified.
- Change `name` to `"load"` -> reachable.
- Change `name` to `config["func"]` -> stays uncertain, even with LLM.

---

## Phase 5 — Execution proof + PR debate ✅ BUILT

**Goal:** prove reachable claims by running them, and make the PR
debate trustworthy.
**Files:** `pyreach/proof.py`, `pyreach/debate.py`
**Time:** hours 18-21. **BUILD NOW: this phase contains differentiator 1.**

### 5a. Execution proof — `proof.py` — BUILD NOW

Static analysis says reachable. Proof runs the path and records a trace.

1. Build a tiny harness that imports the entry module, calls the entry
   function, and records every function call with `sys.settrace`.
2. Run it in a subprocess in a temp dir, no network, 10 second timeout,
   `PYTHONPATH` set to the project root, `PYTHONNOUSERSITE=1`.
   Never import project code in your own process.
3. If the vulnerable function name appears in the trace, the reachable
   verdict is PROVEN. Record the trace in `report.json` under `proofs`.
4. If the harness crashes, needs arguments, or times out, keep the
   static verdict. Do not upgrade or downgrade it on a failed proof.

This is the Crater idea applied here: prove, do not just claim.
Most teams will stay static only and will say "we run in Docker" as
a checkbox for isolated execution. You make isolation the proof.
That is Extra Marks 1, used as evidence, not as a checkbox.

In this base, `run_execution_proof()` is implemented with a harness
template. Wire it in the CLI with `--with-proof`. It is intentionally
simple: entry functions with no arguments work first. Functions that
need arguments are a stretch, record the trace you do get and keep
the static verdict.

### ✅ What Phase 5 actually built (23 Nov 2026, live-verified)

- Witness trace filter fixed: the harness records the filename of every
  call and keeps calls whose file is under the project root, plus the
  vulnerable call. app_witness_wrapper trace is now
  `entry_mod.main -> helpers.parse_config -> yaml.load` — the old filter
  dropped the wrapper middle.
- Dotted entries: `mod.Class.method` is resolved by walking attributes;
  `<module>` entries are witnessed by importing only (app_top: hit).
- SystemExit no longer kills the harness before it prints (only
  Exception was caught). Entry needing args (app_proof_args): witness
  misses with TypeError recorded, static verdict stays reachable —
  a failed witness never downgrades.
- Resource limits in the harness (RLIMIT_CPU 10s, RLIMIT_AS 512MB,
  POSIX), plus the 10s subprocess timeout as the outer bound.
- `answer_challenge()` now checks the cited line: it must contain a
  support token (vulnerable name / caller on the path) and must be a
  NEW line. An unrelated line, a repeated line, or no citation flips
  the verdict to UNCERTAIN. The base version recorded any in-range
  citation and kept the verdict — it never checked anything.
- Honest limits: a witness is one run with one input, it corroborates
  a static path, it never proves unreachability; no sandbox (venv is
  not isolation), multi-threaded code is not traced.

### 5b. PR debate agent — `debate.py` — WRITE-UP ONLY (rule 4)

`format_pr_comment()` posts: advisory id, verdict, package, vulnerable
function, confidence, call path, reason, and an invitation to challenge.

**Concede-or-cite rule:** if a maintainer challenges the verdict, the
agent must either cite a NEW line from the code that supports its
verdict, or flip to UNCERTAIN. It may never defend itself without a
citation. `answer_challenge()` implements the flip: no citation, or
a citation outside the file, -> uncertain.

Mention this rule in your architecture write-up even if the live bot
in the hackathon is simple. A maintainer judge will notice the honesty.
Most teams will build a bot that always defends itself. Yours concedes.

**Completeness ledger (for not_reachable):** before you are allowed
to say not_reachable and write OpenVEX, list: did we parse all files
in this package, did we miss any dynamic call, did we cover all entry
points? If completeness is not 100%, you cannot say not_reachable,
only uncertain. Keep this ledger in the report, even as a simple
list in Phase 5. It is what makes OpenVEX trustworthy.

---

## Explainer — LLM chat explainer for UNCERTAIN results ✅ BUILT

**Goal:** the real LLM use case is explaining the places deterministic
code cannot verify — not deciding verdicts. For every uncertain result,
pyreach first writes a deterministic explanation (works with no key),
then optionally asks the LLM once, in a closed world, to explain the
same evidence in plain language. The LLM output NEVER changes a verdict.
**Files:** `pyreach/explainer.py`, CLI `--explain` / `explain` in `pyreach/cli.py`
**Status: built and tested, 19 Nov 2026. 120 tests (was 65), verify.py offline 36/36.**
**LLM status diagnosis (19 Nov 2026):** the first real MkDocs run with a
key exposed that a failed LLM call was indistinguishable from "not
tried" (`llm_explanation: null`, `llm_rejected: false`, `llm_enabled:
true`). Fixed: `resolver.resolve_with_llm_status()` reports the kind
(ok / no_key / no_requests / timeout / http_error / rate_limited /
bad_json / network_error) with a safe detail (key redacted, ~120 chars);
`explain_result` records `llm_status` / `llm_error` on every
explanation ("rejected" on verifier failure, "not_called" with
`--no-llm`); scans print `LLM explainer: N called, ... unavailable
(<kind>)`; `pyreach llm-test` diagnoses the layer with one call, no
scan (exit 0 ok, 1 otherwise). `resolve_with_llm` is unchanged for
existing callers. See README "LLM not working?" and TESTS.md.
**Free-model delisting + fallback chain (19 Nov 2026):** the day the
diagnosis landed, a real `pyreach llm-test` on the user's machine got
HTTP 404 "This model is unavailable for free. The paid version is
available now - use this slug instead: openai/gpt-oss-20b" — the old
default `openai/gpt-oss-20b:free` had been delisted, and the live
OpenRouter catalog (GET /api/v1/models) listed no gpt-oss `:free`
slug at all. Default is now `cohere/north-mini-code:free` (code-focused,
answered all 3 passes in a 3 Nov 2026 free-model probe, in the live
0/0-pricing catalog on 19 Nov 2026). `FREE_MODEL_FALLBACKS` in
`pyreach/resolver.py` is [cohere/north-mini-code:free,
google/gemma-4-31b-it:free, nvidia/nemotron-3.5-lightning:free]: on a
404 whose body says "unavailable for free", the call tries the next
model — no other failure switches models, and an explicit `--model`
never falls back. The status dict and every explanation record
`llm_model` (the model that answered, or the last tried); the cache
key includes the model, so a fallback hit never poisons the default's
entry, and the cache is checked across the whole chain before any
network call. Free slugs churn every few weeks — re-check the default
against the live catalog. Verified by mocked tests only in this VM
(no live key here); the user must run `pyreach llm-test` and report
the model it prints.

Design source: research report §5 (Codex / Claude Code / Aider / Semgrep
pattern: deterministic scanner -> LLM explainer with a narrow evidence
pack -> human decides). Copied: closed-world JSON + deterministic
citation verifier, ~1,500-token evidence pack, quote-first prompt with a
mandatory `does_not_know` field, one discriminating check per blocker
type, `[deterministic]` / `[llm-explainer]` labelling, rg evidence pass,
conservative footer, single stateless temp-0 call. NOT copied: embeddings,
LSP servers, persistent indexes, multi-call verification, agentic tool
loops, auto-fix / auto-suppress.

### What it does

- **Blocker taxonomy, derived deterministically** (`derive_blocker()`):
  `dynamic_call` (getattr/importlib/plugin reachable from an entry
  point), `ambiguous_name` (same-name candidates), `unparsed_file`
  (files ast.parse rejects), `library_not_parsed` (dependency source
  0/0 parsed, e.g. library-internal `construct_*`). The LLM never
  invents a blocker type — the verifier rejects any answer whose
  blocker differs from the pack. For `dynamic_call` the blocked edge
  is the first reachable site constant propagation cannot resolve,
  not the first site in the file (app_getattr_mixed: line 19 config,
  not line 15 safe literal).
- **Deterministic explanation first, for every uncertain result:**
  what blocks a verdict, the partial BFS path + blocked edge, what
  would resolve it, what is not known. Labelled `[deterministic]`,
  ends with the fixed footer: "This explanation is limited to the
  evidence above. It does not prove the vulnerable function is (or is
  not) called. The verdict remains UNCERTAIN."
- **Evidence pack** (~1,500-token cap, truncate lowest-value hops
  first): OSV advisory id/package/function/fixed version, partial BFS
  path with file:line per hop, the single blocked edge + blocker,
  <=30 lines of snippet per hop (function body only), a symbol table
  for ambiguous names, capped rg matches. Never the whole repo, whole
  call graph, or unparsed library source — those are "not parsed".
- **Ripgrep pass before any LLM call** (`ripgrep_evidence()`): `rg -n`
  over the analysed tree, top 20 matches, with a Python os.walk +
  regex fallback when rg is absent.
- **Closed-world JSON schema:** `{blocker, what_blocks, evidence:
  [{file, line, snippet}], what_would_resolve: [{check, command}],
  does_not_know: [...], verdict: "uncertain"}` — the verdict enum has
  ONE allowed value. **Deterministic citation verifier**
  (`verify_explainer_answer()`): JSON parses; verdict exactly
  "uncertain" (reachable/not_reachable in any verdict field fails);
  blocker matches the pack; does_not_know present and non-empty;
  every cited file:line exists in the analysed tree AND inside the
  pack; every snippet is a verbatim substring of that file at that
  line (whitespace-normalised). Any failure rejects the whole answer:
  fall back to deterministic only, `llm_rejected: true`.
- **One discriminating check per blocker type** (deterministic template
  in code, LLM fills in nothing): dynamic_call -> `rg` for the literal
  name + log at file:line and run the entry point; ambiguous_name ->
  `rg "def <name>"` + confirm the import; unparsed_file -> `python -m
  py_compile <file>` + fix and re-run; library_not_parsed -> `pip show
  <pkg>` + check the installed source. The file:line is verified to
  exist before display.
- **One stateless call, temp 0, no tools, no loop**, via the existing
  `resolver.resolve_with_llm` (same cache, same .env/key handling).
  No key / timeout / rejected answer -> print the deterministic
  explanation alone with "[llm-explainer unavailable — deterministic
  result unchanged]". `--no-llm` gives deterministic only.

### Commands

```bash
pyreach scan fixtures/app_getattr_config --advisory examples/advisory-sample.json --explain --no-llm
# report.json gains "explanations": [{vulnerable_function, blocker,
# deterministic_explanation, llm_explanation or null, llm_rejected,
# discriminating_check, does_not_know, evidence_pack_tokens}]
pyreach explain --report report.json --project fixtures/app_getattr_config --no-llm
# same explanations from an existing report, without re-scanning.
# No uncertain results -> "no uncertain results to explain.", exit 0.
# --project different from the report's project prints a warning.
```

Live output on app_getattr_config (deterministic only): blocker
`dynamic_call` at app.py:10, name comes from `config["func"]`,
does_not_know lists what `config["func"]` is at runtime. On
app_getattr_mixed the blocked edge is line 19 (config), not line 15
(safe literal).

### Honest limits

- The LLM layer has never run with a real key in this repo (same as
  Phase 4): the prompt, schema, and verifier are tested with stubbed
  answers only. A real run may still be rejected by the verifier —
  that is the safe outcome, not a failure.
- The fallback blocker label is imperfect for the low-confidence
  case: if a result is uncertain only because the function list is
  low confidence (no dynamic / ambiguous / unparsed / internal
  cause), it is labelled `library_not_parsed`. The explanation text
  says so plainly instead of inventing a cause.
- `explain` trusts the report's verdicts and rebuilds the graph from
  the project you pass; a mismatched project prints a warning but
  still explains (grounded in the wrong graph — check the warning).
- `--explain` has not yet been run on the three real projects
  (MkDocs / Cookiecutter / pre-commit); their uncertain results are
  mostly ambiguous/library blockers, which the templates cover, but
  the token cap has only been exercised on fixtures so far.

## Phase 6 (stretch) — Taint priority — KEEP FOR LATER

**Do not build this in Phases 1-5. Come back only if time is left.**

Goal: reachable is not enough, is it reachable from attacker input?

Track where data comes from: `sys.argv`, `input()`, file upload,
`request.args`, `request.form`, env vars. If the vulnerable function
is reachable AND the data flowing into it comes from one of those
sources, mark it critical. If it is reachable only with a hardcoded
safe argument, mark it low.

Implementation sketch, 2-3 hours: in `callgraph.py`, add a source list
for those functions. In `reach.py`, when you find a path, check if any
call on the path passes a tainted variable (simple name tracking, not
full dataflow). Add `priority: critical | high | low` to the result.
Do not build full taint tracking in 24 hours, the simple version is
enough to turn a list into a priority list.

If you run out of time, drop Phase 6 first. It is a nice-to-have,
not a core verdict.

---

## Testing

### Fixtures (included)

- `app_vuln` — reachable. `main -> load_config -> yaml.load`
- `app_safe` — not_reachable. Only `safe_load`.
- `app_dead` — not_reachable. `dead()` calls `yaml.load`, nothing calls `dead()`.
- `app_getattr` — uncertain, then LLM-resolvable. `name = "safe_load"`.

### Your own adversarial suite (write in hour 1-2)

Add 4-6 more tiny apps: transitive call through another dependency,
re-export via `__init__.py`, getattr with config, plugin load,
importlib with literal. This is your oracle, like Crater's test rows.
It proves you thought about edge cases, not just the organisers' fixtures.

### Metrics to show

- Fixtures correct: target most fixtures right.
- False not_reachable: target 0. This is the headline number.
- Uncertain resolved by LLM vs left uncertain: show both counts.
- Cache hits/misses, proof traces hit/miss.

Run tests: `python -m pytest tests/ -q`

---

## 24-hour timeline

- **Hours 0-2:** setup, repo, CLI skeleton, get OSV JSON for 2 test
  advisories, write 3 synthetic fixtures.
- **Hours 2-6:** Phase 1, advisory to functions, fix-commit diff to AST.
- **Hours 6-11:** Phase 2, call graph + BFS, entry points (start early).
- **Hours 11-14:** Phase 3, JSON, OpenVEX, cache, CLI output.
- **Hours 14-18:** Phase 4, LLM resolver + verifier, PR comment format.
- **Hours 18-21:** Phase 5, execution proof, debate rule, dead-code test.
- **Hours 21-24:** run all fixtures, record demo, write README with
  architecture trade-offs, practice the 2-minute demo.

Cuts, in order: drop Phase 6 taint first, then drop execution proof,
keep core + LLM resolver. Never cut the verifier or the fail-closed rule.

## 2-minute demo script

1. (30s) Reachable: run on `app_vuln`, show call path and execution
   trace hitting `yaml.load`.
2. (30s) Not-reachable: run on `app_safe`, show OpenVEX file, explain
   why you are allowed to write it.
3. (30s) Uncertain resolved: run on `app_getattr` with `--with-llm`,
   show before (uncertain) and after (not_reachable, verified lines).
4. (30s) Dead code: run on `app_dead`, show a naive tool would say
   reachable, yours says not_reachable because `dead()` is never called.
   End with the scoreboard: fixtures passed, false not_reachable 0,
   cache hits.

## Phase 7 — Full package scanner (`scan-all`) ✅ BUILT (19 Nov 2026)

Until now `scan` only checked the one package given with
`--package/--version`. A judge scanning a real project wants the whole
dependency list checked. `scan-all` does that, in three steps:

1. **Resolve dependencies** (`pyreach/deps.py`, stdlib only): read
   `pyproject.toml` (`[project]` dependencies, poetry dependencies,
   dev groups only with `--include-dev`), `requirements.txt` (+ files
   under `requirements/`, `-r` includes followed), and lockfiles
   (`poetry.lock`, `Pipfile.lock`, `uv.lock`). Exact version priority:
   requirements `==` pin, then pyproject `==` pin, then lockfile, then
   the installed environment (`importlib.metadata`). A dependency with
   no exact version anywhere is SKIPPED, listed in the report with its
   spec and where a pin would come from — never scanned against a
   guessed version, never silently dropped.
2. **Per package, get advisories**: live via `analyse_advisory_live`
   (OSV → fix commit → diff → candidates, cached in `.reachcache`),
   or offline from `--advisory-dir` (`<normalized-name>.json` per
   package — reproducible, and what `verify.py` section I uses). A
   fetch failure marks that package `fetch-failed` and the scan
   continues with the rest; the failure stays visible in the report.
3. **One combined run**: the same `_run_scan` as `scan` over all
   advisories, the call graph built once. The report gains `mode:
   "scan-all"` and a `packages` table (name, version, version_source,
   advisories, candidates, per-verdict counts, status, reason);
   OpenVEX, HTML and `--explain` all work over the aggregated results.
   Exit 2 if any package has a reachable vulnerability, else 0.
   `--only` / `--skip` limit the packages; `--with-proof` and
   `--explain` behave as in `scan`.

Live proof (19 Nov 2026, this VM, real MkDocs clone, PyYAML pinned
`==5.3.1` via a requirements file): 14 dependencies, 2 scanned
(PyYAML 5.3.1 → 1 advisory, 7 candidates, 4 reachable / 3 uncertain —
identical verdicts to the single-package scan; packaging 24.0 →
0 advisories), 12 skipped as range-only with the reason printed.
`verify.py` section I checks the offline path on
`fixtures/app_scanall`.

### Windows cache bug, found by scan-all's prerequisite run (19 Nov 2026)

The MkDocs LLM run before this phase (`mkdocs-llm-2.json`, re-uploaded
as `mkdocs-llm-3.json` — the two files are identical in every field
that matters) showed all 3 explanations `network_error` with
`OSError: [Errno 22] Invalid argument:
'.reachcache\llm:cohere_north-mini-code:free:<hash>.json'`. That is
NOT a network failure: `:` is illegal in a Windows filename, and the
LLM cache key is `llm:<model>:<sha16>`. `Cache._path` only sanitised
`/` and `@`; Linux allows `:` so the VM's tests never caught it. The
failure happens when SAVING the model's answer, after a successful
POST — so the key, the model and OpenRouter were most likely fine all
along and the answer was thrown away at the cache write. Fixed in
`cache.py` (all Windows-illegal filename characters become `_`,
get/put are best-effort and never raise into the caller) and in
`resolver.py` (the cache write sits in its own try/except, and a cache
failure can no longer be classified as `network_error`). Tests:
`tests/test_cache.py` pins the filename rule and proves a failing
cache still returns the model's answer with kind `ok`. Note
`llm-test` never hit this bug — it uses `cache=None` — which is why
it is the right first diagnostic: if `llm-test` says ok, the endpoint,
key and model work and a scan failure is local.

## Phase 8 — ChatGPT review fixes: the three invariants ✅ BUILT (19 Nov 2026)

A ChatGPT rating of the project (5/10 core verdict reliability) was
verified against the code, not taken on trust. Both critical findings
reproduced exactly as described, plus four more. The build stops
adding features and makes three invariants demonstrably correct:

1. a reachable vulnerability always produces a real inspectable call path;
2. an incomplete/unresolved path never becomes NOT_REACHABLE;
3. OpenVEX never claims not affected when another finding says the
   same vulnerability is reachable.

**Critical 1 — an unresolved call became NOT_REACHABLE.** `parser =
get_parser(); parser.load(...)` was dropped silently (callgraph.py:
"attr-unresolved ... drop") and the app got `not_reachable high` + an
OpenVEX `not_affected` statement, while really calling yaml.load.
Fixed: attr-unresolved calls are recorded in
`graph.unresolved_attrs` ({file, line, caller, attr}); a site whose
attribute equals the candidate's simple name makes that candidate
uncertain, with the reason naming the exact site. Fixture
`app_unresolved_attr`, expected uncertain, 0 VEX.

**Critical 2 — OpenVEX contradicted reachability.** `build_openvex`
emitted a `not_affected` statement per not_reachable result, so an app
calling `yaml.load(..., Loader=yaml.FullLoader)` got three
`not_affected` statements for the same GHSA while the same report said
yaml.load was reachable. Fixed: aggregation at the advisory level —
one statement per advisory, only when EVERY candidate for it is
not_reachable with high/medium confidence, gated on the ledger
(`is_complete_for_not_reachable()`). The old per-result
`graph_clean` gate in cli.py is replaced by that call. Fixture
`app_vex_full` (real advisory): yaml.load + 3 internals reachable,
FullLoader uncertain, 2 not_reachable, **0 VEX statements**;
`verify.py` section J pins this, plus the all-clear cases
(app_safe, app_never_imported → exactly 1 statement each).

**Critical 3 — dependency source never parsed.** The `construct_`
heuristic was a PyYAML special case. Replaced by a general public-API
rule (`reach._is_library_internal`): a candidate is library-internal
iff it is not a project function AND has a dot AND its first segment
is not a module the project imports; bare names are public. Internal
+ dependency unparsed → uncertain, never not_reachable. The ledger now
reports dependency coverage honestly (`dependency_modules_discovered`
via `importlib.util.find_spec`, parsed stays 0 — the dependency source
is still not parsed; the rule makes the absence explicit instead of
guessing). The related FullLoader case is a **reference rule**: a
candidate referenced without being called (`Loader=yaml.FullLoader`,
`functools.partial(yaml.load, ...)` in pre-commit) → uncertain.

**Critical 4 — entry points over-broad.** Every function named `main`
was an entry, and every `<module>` with edges was one, so a
never-imported module's top-level `yaml.load()` counted as reachable.
Fixed: program modules are file stems {main, app, cli, __main__} or
modules with a `__main__` guard or console-script targets or the
project's only module or (library mode) `__init__`; `<module>` entries
only for program modules ∪ modules they transitively import (over
`graph.file_imports`). The blanket `main` rule is deleted. The
`@mock.patch` phantom is fixed too (`_is_route_decorator` rejects
`mock.patch`): MkDocs entries fell 1,217 → 1,092. Fixtures
`app_never_imported` (not_reachable, 1 VEX) and `app_mockpatch`.

**Critical 5 — the completeness ledger was never consulted.**
`is_complete_for_not_reachable()`, `unresolved_imports` and
`entry_points_unsupported` had zero callers/writers outside
completeness.py. Fixed: the ledger is now populated in `_run_scan`
(unresolved imports from the import analysis, unsupported entry
points — class-based Django views and unresolvable console-script
targets — from `find_unsupported_entrypoints`, dependency coverage,
`unresolved_attribute_calls`), `dynamic_unresolved` now means what
it says (dynamic sites still unknown after Phase 4, not a count of
uncertain results), and a **verdict gate** flips not_reachable →
uncertain/low when files are unparsed or imports/entry points are
unresolved. Dynamic/ambiguous stay per-target (analyze + Phase 4
already handle them); VEX uses the stricter whole-run ledger.
Fixture `app_unparsed` (1/2 parsed → gate flips to uncertain).

**Critical 6 — phase1 mapping bugs.** `diff_files` kept the `b/`
prefix from `+++ b/...` headers and `fetch_github_file` never
stripped it, so changed-file fetches 404'd; `old_sources` was
initialised `{}` and never filled, so the both-sides mapping in
`diff_to_functions` never ran. Fixed: `b/` (and `a/`) stripped at
extraction and in `fetch_github_file`; new `fetch_github_parent_sha`
(GitHub API, cached, best-effort) fetches each changed file at the
parent commit into `old_sources`. File fetches are wrapped so a
missing `requests` install (diff came from cache) cannot crash the
live fetch. Tests mock the fetch functions and pin both behaviours.

**Target-specific dynamic/ambiguous blocking (was: global).** Any
reachable dynamic trigger or ambiguous edge anywhere used to block
not_reachable for every unrelated candidate. Now only edges/sites
that can reach the target block it, decided by `site_can_run`:
caller BFS-reachable, or module top-level code of a reachable module,
or an implicitly-invoked dunder method of a reachable module.
The dunder case was found by the MkDocs re-run in this same phase:
the BFS-only filter dropped the `config_options.py:549` getattr
inside `Optional.__getattr__`, so Phase 4 claimed "all 5 sites
resolved" while 2 real sites were never examined. With the fix
MkDocs tries 10 sites, resolves 8, 2 still unknown — the honest
story from before the phase, with exact counts. Fixture `app_dunder`
pins the dunder rule. Phase 4 tries only sites that can run, by the
same predicate.

**Scan-all (§4):** lockfile-only packages are now added as pinned
transitive entries (version_source "lockfile"); direct-URL and
editable requirements produce SKIPPED entries with a reason instead
of being silently dropped (same for poetry git/path/url deps).
The witness prints a not-a-sandbox warning when `--with-proof` runs.

Re-runs 19 Nov 2026 (fresh clones, same commits as the Phase 7
verification: MkDocs 2862536, Cookiecutter c88fbe9, pre-commit
ba5c420): verdict splits unchanged — MkDocs 4 reachable / 3
uncertain, Cookiecutter 7/7 uncertain, pre-commit 7/7 uncertain —
with better reasons and an honest ledger. MkDocs: entries 1,092,
dynamic_unresolved 2, ambiguous 1,980, unparsed 11/65. Cookiecutter:
entries 456, gate blocks 4 candidates on 13 unparsed files.
Pre-commit: entries 33, yaml.load uncertain via the reference rule
(the `functools.partial` wrapper). Full numbers in REAL_PROJECTS.md.
`verify.py` offline: **47 passed, 0 failed** (was 38); unit suite
**173 tests** (was 149); 32 fixtures.

## Risks and trade-offs

- Fix commit may be a big refactor: confidence drops, verdict becomes
  uncertain. That is correct, not a failure.
- Python dynamic code, frameworks that call by string name: you will
  label uncertain. That is correct, but means fewer clean not-reachable
  verdicts.
- Small LLM may hallucinate: verifier + 0.8 threshold + stay-uncertain
  fallback protect you. If the free API is slow, skip Phase 4 in the
  demo and show the deterministic core.
- Execution proof needs arguments: entry functions with no arguments
  work first. Do not spend more than 1 hour on argument handling.

## Tech stack

Python 3.11+, stdlib `ast`, `pathlib`, `json`, `requests` for OSV/GitHub.
Small open-weight model only, temp 0 — current default
`cohere/north-mini-code:free` with a free-model fallback chain
(`resolver.py`: `FREE_MODEL_FALLBACKS`); free slugs get delisted, so
re-check the live OpenRouter catalog before pinning a new default.
No paid LLM, no GPU, CPU laptop is enough.
