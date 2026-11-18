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

## Phase 1 — Advisory to vulnerable functions (from the fix commit)

**Goal:** turn an alert into a list of vulnerable functions, with confidence.
**Files:** `pyreach/advisory.py`
**Time:** hours 2-6 in the 24h plan.

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

## Phase 2 — Call graph + reachability (deterministic)

**Goal:** build a call graph with AST only, then BFS from entry points.
**Files:** `pyreach/callgraph.py`, `pyreach/reach.py`
**Time:** hours 6-11.

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

## Phase 3 — Real entry points, output, cache

**Goal:** only real starts count, then write JSON + OpenVEX, and cache
dependency parsing.
**Files:** `pyreach/entrypoints.py`, `pyreach/vex.py`, `pyreach/cache.py`, `pyreach/cli.py`
**Time:** hours 11-14. **BUILD NOW: this phase contains differentiator 3.**

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


## Phase 4 — LLM resolver for dynamic / uncertain cases only

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

## Phase 5 — Execution proof + PR debate

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
Small open-weight model only, gpt-oss 20B or Llama 3.1 8B, via a free
provider, temp 0. No paid LLM, no GPU, CPU laptop is enough.
