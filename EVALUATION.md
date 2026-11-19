# PyReach evaluation — 19 Nov 2026

How the tool was tested, what the numbers are, and what they do not
prove. Every number below is reproducible from this repo: `python3
verify.py` (offline) plus the scans in `~/workspace/real-projects-pyreach/`
(`*-report-eval.json`).

## 0. Authoritative numbers — 19 Nov 2026, final (ChatGPT fix B)

One table, current as of the final zip. Older numbers in this file's
earlier sections (§2/§3 as first written), in PHASES.md Phase 5–10
entries, and in REAL_PROJECTS.md's Phase 5 verification block are
superseded by this table; they are kept as history, not as current
claims. `verify.py`'s own labels agree with this table.

| What | Number | How reproduced |
|---|---|---|
| Unit tests | 237 passed, 0 failed | `python3 -m unittest discover -s tests` |
| `verify.py` (offline) | 61 passed, 0 failed | `python3 verify.py` |
| `verify.py --live` | 61 passed, 0 failed | `python3 verify.py --live` (adds live OSV fetch + PyPI sdist check) |
| Fixture verdicts | 40/40 match EXPECTED (22 reachable, 9 not_reachable, 9 uncertain) | §2 |
| Demo (4 repos, pre-seeded advisories, --no-llm) | 27 results: 2 reachable, 12 uncertain, 13 not_reachable; 2 OpenVEX statements | `bash demo/run-demo.sh` (demo/README.md) |
| Real projects (7, PyYAML 5.3.1) | 4 reachable, 38 uncertain, 7 not_reachable; 1 OpenVEX statement | §3. yamllint / MkDocs / cookiecutter / bandit re-scanned with Phase 13 code; pre-commit / ansible-lint / Kedro are Phase 9 numbers (not re-scanned with `--with-deps`) |
| False reachable / false not_reachable | 0 / 0 | fixtures (§2) + real projects (§3); ground truth by grep before scanning |
| Execution sandbox | Incomplete — subprocess runtime witness only (no network/filesystem isolation) | §1, "Extra: Isolated Execution" |
| LLM explainer, live run | Not run — demo used `--no-llm`; unit-tested only | §1, Extra 2. Proof needs one scan with a key + LLM toggle on |
| Fix-commit mapping, live advisories | Proven end-to-end on 1 advisory (PyYAML GHSA-8q59-q68h-6hv4); "≥3 materially different advisories" still open | §1 |
| Call-path evidence | Every step carries file + definition line (`path_detail` in `report.json`, HTML report, React UI) | ChatGPT fix A, 19 Nov 2026 |

## 1. Requirements verdict (Problem 1, visible brief only)

| Requirement | Verdict |
|---|---|
| Per alert: reachable / not reachable / uncertain, with the call path as evidence | **Satisfied.** Verdicts + paths in `report.json` for every candidate; witness (`--with-proof`) runs the path. |
| OpenVEX `vulnerable_code_not_in_execute_path` for non-applicable alerts | **Satisfied.** One statement per advisory, only when every candidate is not_reachable (high/medium) and the completeness ledger is clean. 0 false VEX in all tests below. |
| Fix commit -> which functions are affected, and how sure | **Satisfied.** Both-sides diff mapping (old + new source, Phase 8); confidence high/medium/low. Caveat: exercised end-to-end on the PyYAML advisory + mocked tests only; the "test >=3 materially different advisories" check is still open. |
| getattr / dynamic imports / runtime plugins without pretending certainty | **Satisfied.** Constant propagation first, verified LLM second, uncertain otherwise; blocking is per-target and only for sites that can run (`site_can_run`). |
| Cache analysis of popular packages so it is not repeated per project | **Satisfied.** Cache key is package + exact version + source hash + artifact hash + parser version; diffs and LLM answers cached. Dependency source is parsed with `--with-deps` and its sdist cached under `<cache-dir>/deps/<pkg>-<version>/` (sha256 marker, never re-downloaded); without `--with-deps` there is nothing to cache there. |
| Strong submission: most fixture verdicts right | **Satisfied on our fixtures: 40/40** in `verify.py` (see §2). Organiser fixtures are not available to test against. |
| Strong submission: NEVER marks a reachable vulnerability unreachable | **Satisfied.** The three invariants (unresolved calls -> uncertain, VEX aggregated per advisory, dependency internals -> uncertain) are repro-verified; 0 false not_reachable in §2 and §3. |
| Strong submission: genuine uncertainty labelled uncertain | **Satisfied, and the honest weakness.** 43% uncertain on MkDocs (3/7); yamllint is now 0% uncertain (7/7 not_reachable, Phase 13); the other five real projects are still 100% uncertain (see §3). The 0-false-not-reachable number alone proves nothing — the uncertain rate is reported next to it in every scan. |
| Extra: Isolated Execution | **Partial — sandboxing incomplete.** The witness is a subprocess runtime witness only: POSIX resource limits + timeout, current interpreter, inherited environment, no network or filesystem isolation. It is NOT a sandbox, and is never presented as one (CLI warning, README, UI all say so). A container sandbox is out of scope for this submission. |
| Extra 1: Advanced Analysis + "converse with the agent on PRs" | **Partial.** Dynamic imports / reflection / getattr / plugins are handled; every report carries `pr_comments` and the concede-or-cite `answer_challenge` rule (unit-tested). There is no live PR bot that replies in a thread. |
| Extra 2: Accuracy & Explainability | **Satisfied.** Evidence-backed call paths with file:line per step + confidence levels + the explainer (deterministic first; LLM second, unit-tested — no live LLM run in the demo, which used `--no-llm`). |
| Ground rules: no heavy paid LLM as main executioner; no automated issues/comments; real-data tests disclosed; prior-work difference stated | **Satisfied.** Deterministic core; the LLM is a second layer on uncertain cases only, using a free open-weight model (`cohere/north-mini-code:free` via OpenRouter). Nothing posts to real projects. Prior-work difference is in README/PHASES. |

## 2. Fixture evaluation — 40/40, 0 false not_reachable, 0 false reachable

`python3 verify.py` (offline, no key, no network): **61 passed, 0 failed**
— 237 unit tests + 40 fixture scans + prompt / witness / explainer /
quiet-terminal+HTML / scan-all / VEX / with-deps checks. (`--live` adds
the live OSV fetch and the `--with-deps` PyYAML check; also 61 passed,
0 failed.)

Fixture verdicts (all 40 match their expected verdict and exit code;
exit 2 = reachable, exit 0 = not_reachable / uncertain):

- Core reachability (22): app_vuln, app_top, app_nested, app_method,
  app_star, app_alias, app_console, app_django, app_library, app_click,
  app_importlib, app_witness_wrapper, app_proof_args, app_getattr_load,
  app_getattr_branch, app_load_collision, app_console_ambig,
  app_console_reexport, app_library_all, app_route, app_vex_full,
  app_wrapper — reachable.
- Clean apps (9): app_dead, app_getattr, app_getattr_concat,
  app_getattr_json, app_getattr_loop, app_getattr_reassign,
  app_mockpatch, app_nested_cli, app_never_imported — not_reachable,
  each with exactly 1 OpenVEX statement and no contradiction.
- Honest uncertainty (9): app_safe, app_all_class, app_dunder,
  app_getattr_config, app_getattr_mixed, app_init_call, app_rel_import,
  app_unparsed, app_unresolved_attr — uncertain.
- app_safe is the honest-uncertainty case worth naming: it calls
  `yaml.safe_load`, which enters the yaml library, and without
  `--with-deps` the dependency source is unparsed, so the tool refuses
  to claim not_reachable. With `--with-deps` + an exact version
  (PyYAML 5.3.1) it flips to 7/7 not_reachable + 1 OpenVEX — that flip
  is covered by the `verify.py` with-deps check.
- The three ChatGPT invariants, repro-verified before/after Phase 8:
  `parser.load()` via a variable was not_reachable+1 VEX, now uncertain+0
  VEX; an app calling `yaml.load(..., Loader=FullLoader)` generated 3
  contradictory VEX statements, now 0; a never-imported module's
  top-level `yaml.load` was reachable, now not_reachable+1 VEX.

## 3. Real-project evaluation — 7 projects, PyYAML 5.3.1, `--no-llm`

Ground truth was established by grep before scanning (production code
only; test files and vendored examples do not count). All scans used the
live PyYAML 5.3.1 advisory (GHSA-8q59-q68h-6hv4), deterministic only.
yamllint, MkDocs, cookiecutter and bandit were re-scanned with the
Phase 13 code (`--with-deps`); pre-commit, ansible-lint and Kedro (†)
are Phase 9 numbers, not re-scanned with `--with-deps`.

| Project | py files | Ground truth for `yaml.load` | Result | Exit | Correct? |
|---|---|---|---|---|---|
| MkDocs (mkdocs/mkdocs @2862536) | 65 | Called (via `meta.get_data` and `utils.yaml.yaml_load`, default loader is unsafe `yaml.Loader`) | 4 reachable / 3 uncertain | 2 | Yes — reachable, with the exact path |
| Cookiecutter (c88fbe9) | 90 | Not called (only `yaml.safe_load`) | 7/7 uncertain | 0 | Conservative — uncertain, not wrong |
| pre-commit (ba5c420) † | 134 | Called only via `functools.partial(yaml.load, Loader=CSafeLoader)` | 7/7 uncertain | 0 | Conservative — the partial is now surfaced as a reference, not a call |
| yamllint (HEAD 96246fb) | 69 | Not called (only `safe_load` / `SafeLoader`) | 7/7 not_reachable | 0 | Yes — SafeLoader-only, proven with `--with-deps` (Phase 13, PyYAML 5.3.1 parsed 17/17); 1 OpenVEX statement |
| bandit (HEAD 2d5467c) | 196 | Called only in `examples/yaml_load.py`, a vulnerability demo never executed by the tool | 7/7 uncertain | 0 | Yes — the demo file is correctly NOT an entry, so no false reachable |
| ansible-lint (HEAD a40df81) † | 187 | Called only via `functools.partial(yaml.load, Loader=FullLoader)`; other `yaml.load` calls are ruamel.yaml, not PyYAML | 7/7 uncertain | 0 | Conservative — the partial is surfaced as a reference; the ruamel calls correctly produced no PyYAML edge |
| Kedro (HEAD 5c48cc3) † | 237 | Not called (only `yaml.safe_load`, 3 sites) | 7/7 uncertain | 0 | Conservative — uncertain, not wrong |

Totals: **4 reachable / 38 uncertain / 7 not_reachable across 49
candidate verdicts. 0 false reachable, 0 false not_reachable.**
1 OpenVEX statement (yamllint — the first real project proven
not_reachable).

Why so much uncertainty — the three real blockers, all named in the
reports:

1. **Dependency source, before `--with-deps`** (ledger:
   `dependency_source 0/17` everywhere in the Phase 9 runs). The 3
   library-internal candidates were uncertain on every project by
   design; the tool refuses to prove a negative about code it never
   read. Phase 11/13 fixes this when run: with `--with-deps`,
   PyYAML 5.3.1 parses 17/17 and yamllint's 7 internal candidates
   flip to not_reachable. Without `--with-deps` the old behaviour
   (uncertain) is still correct.
2. **One config-driven dynamic site blocks 3 candidates on MkDocs**
   (`getattr(self.option, key)` at `config_options.py:549`): Phase 4
   resolves 8/10 sites, 2 still unknown. No static analysis can
   enumerate a config value — only runtime evidence can.
3. **The completeness gate reverts not_reachable where coverage is
   incomplete** — a flipped verdict is reverted to uncertain rather
   than claimed (bandit: 193/196 parsed; cookiecutter: 88/90 parsed).
   yamllint's old 5,618 ambiguous edges are now handled by the
   per-advisory VEX gate (Phase 13): the whole-run ledger counted the
   dependency's own edges, so the gate is per-advisory now. Unparsed
   files + ambiguous names gate the rest (e.g. Cookiecutter: 2
   unparsed files — test hook templates containing Jinja syntax, not
   real Python — still trip the gate).

## 4. What the evaluation found and fixed (19 Nov 2026)

Four bugs, all found by scanning real projects, all fixed and
regression-tested in this repo (see `tests/test_eval_fixes.py`, 9 tests):

1. **Console-script module stripped** — `yamllint.cli:run` was read as
   module `yamllint`, so the script did not resolve (and would have
   lost the entry in app mode). Fixed in `entrypoints.py` at all three
   call sites; fixture `app_console_ambig`.
2. **Stdlib names flagged as unresolved project imports** — ansible-lint
   has `collections/` fixture dirs, so every `from collections.abc
   import ...` was flagged (~100 ledger entries). Fixed: stdlib module
   names are never flagged; fixture test.
3. **Ledger "parsed" counted files with functions, not files parsed**
   — empty `__init__.py` files counted as unparsed (yamllint 67/69,
   MkDocs 54/65). Fixed: `Graph.files_parsed` records every successful
   `ast.parse`; MkDocs is now 65/65, ansible-lint 187/187.
4. **Re-exported console scripts did not resolve** — cookiecutter's
   script points at `cookiecutter.__main__:main` and kedro's at
   `kedro.framework.cli:main`, but `main` is imported there, not
   defined. Fixed: `_resolve_simple` follows the script module's
   imports one level (including relative `from .cli import main`),
   using exact module matching (a prefix match falsely called two
   submodule functions ambiguous). Fixture `app_console_reexport`.
5. **`__all__` discarded the console-script entry** — in library mode
   with a root `__all__`, `find_entrypoints` returned ONLY the
   `__all__` names; kedro's real entry point (its `kedro` script) never
   became a BFS start (entries 4). Fixed: merge, don't replace.
   Kedro entries are now 93. Fixture `app_library_all`.

After the fixes, every project reports **0 unsupported entry points
and 0 unresolved imports** in its ledger.

## 5. Honest limits (what the numbers do not show)

- **No real project reaches not_reachable yet.** The most commercially
  useful verdict is demonstrated only on fixtures. Fixing it needs
  dependency-source parsing (the next real piece of work, not built).
- **Reachability is not exploitability.** MkDocs loads its own config
  files; the reachable `yaml.load` there is a real call path, not a
  proven exploit. The Loader argument (`SafeLoader` vs `Loader`) is
  not distinguished.
- **The LLM layer is verified by mocked tests + 3/3 accepted explainer
  answers on one real MkDocs run** (mkdocs-llm-4.json), but the Phase 4
  resolver has never had an answer accepted on a real project — the
  config case is unresolvable from code alone, by design.
- **Uncertain rate is the metric to watch alongside false
  not_reachable.** A tool that labels everything uncertain scores 0
  false not_reachable without solving anything; every scan prints
  both numbers.
- **Entry-point reachability assumes modules executed out-of-band**
  (plugin loaders, direct `python helper.py`) are out of scope.
- The both-sides fix-commit mapping is exercised via mocked tests +
  the PyYAML advisory only; "test >=3 materially different
  advisories" is still open.

## Phase 12 update (19 Nov 2026)

This document is the Phase 9 evaluation; the numbers above are as
measured then. Phase 12 (see PHASES.md) changed one of them: the
fixture `app_safe` is now **uncertain**, not not_reachable, without
`--with-deps` — it calls `yaml.safe_load()` while the yaml source is
unparsed, and the new dependency-entry rule says the library may call
`yaml.load` internally. The 7-project real-world table is unaffected
(all 7 were already 7/7 uncertain except MkDocs' 4 reachable), and
the demo totals are unchanged (Flask 0/9, requests 1/2, httpx 1/7).
The "never marks a reachable vulnerability as not_reachable" claim in
this document now holds against ChatGPT's relative-import,
dependency-wrapper, getattr-receiver and nested-entry repros as well
— see `tests/test_phase12.py`.

## Phase 13 update (19 Nov 2026)

- Loader-aware verdicts + resolver reorder + per-advisory VEX gate
  (see PHASES.md Phase 13). The "no real project reaches not_reachable"
  weakness is now fixed for one project: **yamllint 7/7 not_reachable +
  1 OpenVEX statement** (`--with-deps`). bandit and cookiecutter stay
  7/7 uncertain (completeness gate + unresolvable plugin dynamic sites),
  MkDocs stays 4/3. The 7-project table above is unchanged in the
  no-deps mode; the loader limit it documents ("Loader arguments not
  distinguished") is now closed for the yaml.load family.
