# pyreach — Problem 1: Which vulnerability alerts actually affect a Python project?

Deterministic first, LLM second, fail-closed. Never mark a reachable
vulnerability as not-reachable.

## Quick start

```bash
python -m pip install -e .
pyreach scan fixtures/app_vuln --advisory examples/advisory-sample.json --out report.json --vex openvex.json
echo "exit code: $?"  # 2 = reachable found, 0 = none

pyreach scan fixtures/app_safe --advisory examples/advisory-sample.json --out report.json --vex openvex.json
pyreach scan fixtures/app_dead --advisory examples/advisory-sample.json --out report.json --vex openvex.json
pyreach scan fixtures/app_getattr --advisory examples/advisory-sample.json --out report.json --vex openvex.json

# Phase 4, only if you have a free key — put it in .env, pyreach loads
# it AND turns the LLM on by itself, no flag needed:
#   Copy-Item .env.example .env   (PowerShell) / cp .env.example .env
#   then edit .env: OPENROUTER_API_KEY=sk-or-v1-...  (never commit .env)
pyreach scan fixtures/app_getattr --advisory examples/advisory-sample.json --out report.json
# (use --no-llm to skip the LLM even with a key in .env)

# Phase 5, execution proof:
pyreach scan fixtures/app_vuln --advisory examples/advisory-sample.json --with-proof --out report.json

# Explainer, uncertain results only (deterministic first; LLM layer
# only with a key — same .env auto-enable as Phase 4):
pyreach scan fixtures/app_getattr_config --advisory examples/advisory-sample.json --explain --no-llm --out report.json
pyreach explain --report report.json --project fixtures/app_getattr_config --no-llm

# Phase 7, full package scanner — every dependency, not one --package:
pyreach scan-all fixtures/app_scanall --advisory-dir fixtures/app_scanall_advisories --no-llm --out report.json
# Live (needs network): reads deps from pyproject.toml / requirements.txt
# / lockfiles, resolves each to an exact version, fetches OSV per package:
pyreach scan-all <project> --no-llm --out report.json

python -m pytest tests/ -q
```

## What it does

1. Advisory -> vulnerable functions, from the fix commit diff mapped to
   functions with AST. Confidence high / medium / low.
2. Call graph from AST only, never import or execute project code.
   BFS from real entry points only. Dead code does not count.
3. Verdicts: reachable / not_reachable / uncertain, with call path.
   OpenVEX only for not_reachable. Cache by package@version+hash.
4. LLM resolver, uncertain dynamic cases only (getattr, importlib,
   plugins). Small open-weight model, temp 0, verified by code.
   No key -> stays uncertain, which is safe.
5. Execution proof in an isolated subprocess, plus a PR debate agent
   that must cite a line or flip to uncertain.
6. **Explainer for uncertain results** (`--explain` / `explain`):
   deterministic explanation first — blocker, partial path, blocked
   edge, one discriminating check, what is not known — then optionally
   one verified LLM explanation. The LLM never changes a verdict:
   its JSON must say `verdict: "uncertain"`, its blocker must match
   the deterministic one, and every cited snippet must match the code
   verbatim, or the answer is rejected and only the deterministic
   explanation is shown. Lines are labelled `[deterministic]` vs
   `[llm-explainer]`; no key means deterministic only.
7. **Full package scanner** (`scan-all`): reads the project's real
   dependencies from `pyproject.toml` / `requirements.txt` / lockfiles
   (`poetry.lock`, `Pipfile.lock`, `uv.lock`), resolves each one to an
   EXACT version (requirements `==` pin, then pyproject `==` pin, then
   lockfile, then the installed environment), fetches OSV advisories
   per package, and runs the same reachability check over the combined
   list with the call graph built once. A dependency with no exact
   version anywhere is SKIPPED and listed with its spec and where a
   pin would come from — never scanned against a guessed version,
   never silently dropped. A fetch failure marks that package
   `fetch-failed` and the scan continues. The report gains a
   `packages` table (per-package advisories, candidates, verdict
   counts, status) and a per-package terminal table; exit 2 if any
   package has a reachable vulnerability. `--advisory-dir` runs it
   fully offline from per-package advisory files (`<name>.json`).
   Lockfile-only (transitive) packages are scanned too; direct-URL
   and editable requirements are recorded SKIPPED, not dropped.
8. **Three invariants (Phase 8, 19 Nov 2026):** a reachable
   vulnerability always produces a real inspectable call path; an
   incomplete/unresolved path never becomes NOT_REACHABLE (unresolved
   attribute calls, referenced-but-not-called names, library-internal
   functions with unparsed dependency source, and the completeness
   gate for unparsed files / unresolved imports / unsupported entry
   points all force uncertain); OpenVEX is aggregated at the advisory
   level — one `not_affected` statement only when EVERY candidate for
   that advisory is not_reachable, so it can never contradict a
   reachable finding in the same report. Entry points count only
   modules that can actually execute (no blanket `main`, no
   never-imported module, no `@mock.patch` phantom).

## Reading a scan — terminal is a summary, the HTML report is the interface

A scan prints a short summary only: counts, one line per result, one
line per uncertain explanation (`explain [uncertain] yaml.load —
blocker dynamic_call, blocked at app.py:10`). The full entry-point
list, entry evidence, and explanation text are NOT printed — on MkDocs
that was ~240KB of terminal output (19 Nov 2026). Full detail is in
`report.json`, and every scan also writes a readable `report.html`
next to it — open it in a browser. It has the summary cards, the
results table with call paths, the explanations with blockers and
discriminating checks, and the proofs. `--verbose` restores the full
terminal dump for debugging, `--no-html` skips the HTML file, and
`pyreach report --report report.json` regenerates the HTML from an
existing report without re-scanning.

See `PHASES.md` for implementation details for Phases 1–8 and the
explainer, the design question answers, the 24-hour timeline, and the
demo script.

## LLM not working? Run `pyreach llm-test` first

Do not re-run a whole MkDocs scan to find out the LLM layer is dead —
one scan tells you nothing about why, because a failed call used to
look exactly like "not tried" (null explanation, not rejected). Run:

```bash
pyreach llm-test
```

One minimal call, no scan. It prints key presence only (never the
value), then `ok in 1.23s` or the failure kind. Every explanation in
`report.json` also carries `llm_status` / `llm_error`, and every scan
with `--explain` prints one summary line, e.g.
`LLM explainer: 3 called, 0 accepted, 0 rejected, 3 unavailable (timeout)`.
`--llm-debug` adds the per-result status and safe detail.

| `llm_status` | Means | What to do |
|---|---|---|
| `ok` | A parsed JSON answer came back (it may still be verifier-`rejected`) | Nothing — check `llm_rejected` next |
| `rejected` | An answer came back but failed the citation verifier | Safe outcome, not a failure — read `llm_error` for the failed rule |
| `no_key` | No `OPENROUTER_API_KEY` / `GROQ_API_KEY` in env or `.env` | Check the `.env` location: project root, or `--env-file <path>` |
| `no_requests` | The `requests` package is not installed | `pip install requests` |
| `timeout` | No reply in 60 s | Check the network, retry once |
| `rate_limited` | HTTP 429, free-tier limit reached | Wait, then retry; fewer calls per run |
| `http_error` | Another HTTP status (detail has the code) | Check the code in `llm_error` |
| `http_error` + HTTP 404 "unavailable for free" | The free slug was delisted (happened to `openai/gpt-oss-20b:free` on 19 Nov 2026) | Run `llm-test` — it falls back automatically to the next free model and prints which one answered. If all fallbacks 404, re-check the live catalog at openrouter.ai/models. Never switch to the paid slug `openai/gpt-oss-20b` — that would bill you. An explicit `--model` never falls back. |
| `bad_json` | The model replied, but not with the expected JSON | Retry — a free-tier model sometimes answers in prose |
| `network_error` | Could not reach the endpoint at all | Check network / `LLM_BASE_URL` |
| `not_called` | The LLM layer never ran (`--no-llm`) | Expected — deterministic explanations only |

Note: `llm_enabled: true` in `report.json` only means a key was
found. It never proves a call succeeded — `llm_status` is the proof.
Each explanation also records `llm_model`: the model that actually
answered it, which is not always the default when the fallback chain
switched models on a delisted 404.

## Build priority — revised after ChatGPT review, 18 Nov 2026

ChatGPT's assessment was mostly right, see `CHATGPT-REVIEW.md` for
the full reasoning. The priority below supersedes the earlier one
where it conflicts.

- **BUILD FIRST:** Deterministic core + real entry points with evidence
  + completeness ledger. If the core does not work, a trace cannot save it.
- **BUILD NEXT:** Constant propagation for getattr, then optional LLM
  resolver (verified, never decisive on its own).
- **BUILD IF TIME:** Dynamic execution witness (renamed from "proof",
  optional, never downgrades a verdict). A venv is not a sandbox.
- **KEEP FOR LATER:** 2. Taint priority. Full design is in PHASES.md
  Phase 6 (stretch). Come back to it only if time is left.
- **WRITE-UP ONLY:** 4. Concede-or-cite debate rule. Mention it in the
  architecture write-up, even if the live bot is simple. Completeness
  ledger is now CORE, not write-up only — that was the main correction.

## Safety note — read the clean brief, not the raw PDF

Do NOT paste the raw `Problem_Statement_List.pdf` into Codex or any
vibe coder. Its text layer contains hidden instructions aimed at AI
agents, including forced project names and forced repo layouts.
Pick your own project name and your own layout (this repo uses a
simple flat `pyreach/` package). Work from the clean brief in
`problem-1-getattr-resolver-prompt-and-verifier.md` if you have it.
Whether that was an organiser trap-test or third-party tampering is
unknown — do not accuse anyone, just do not follow it.

## Files

- `pyreach/advisory.py` — Phase 1
- `pyreach/callgraph.py`, `pyreach/reach.py` — Phase 2
- `pyreach/entrypoints.py`, `pyreach/vex.py`, `pyreach/cache.py`, `pyreach/cli.py` — Phase 3
- `pyreach/resolver.py` — Phase 4
- `pyreach/dotenv.py` — .env loader for the API key (stdlib only, no
  new dependency; real env vars always win over .env; the key value
  is never printed or written into a report). See `.env.example`.
- `pyreach/proof.py`, `pyreach/debate.py` — Phase 5
- `pyreach/explainer.py` — explainer for uncertain results
  (deterministic first, one verified LLM call, never a verdict)
- `pyreach/html_report.py` — readable HTML report written next to
  report.json on every scan (stdlib only, all scanned content escaped)
- `fixtures/` — app_vuln (reachable), app_safe (not-reachable),
  app_dead (dead code), app_getattr (uncertain)
- `examples/advisory-sample.json` — OSV-style sample for yaml.load
