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

See `PHASES.md` for implementation details for Phases 1-5, the design
question answers, the 24-hour timeline, and the demo script.

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
- `fixtures/` — app_vuln (reachable), app_safe (not-reachable),
  app_dead (dead code), app_getattr (uncertain)
- `examples/advisory-sample.json` — OSV-style sample for yaml.load
