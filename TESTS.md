# Tests to perform — pyreach, Phases 1–8

One command runs everything, and every check prints PASS or FAIL:

```bash
python verify.py            # offline: 173 unit tests + 32 fixture scans + prompt + witness + explain + quiet/HTML + scan-all + VEX
python verify.py --live     # also the real OSV fetch for PyYAML 5.3.1 (needs network)
```

## Setup first — Windows, read this

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Two traps that cost real debugging time on 19 Nov 2026:

1. **`python` vs `python3` are different Pythons on Windows.** If you have
   MSYS2/Git Bash installed, `python3` is usually the MSYS2 system Python,
   which has none of your packages. Your venv Python is `python`. Always
   run `python verify.py`, never `python3 verify.py`, or you get
   `ModuleNotFoundError: No module named 'requests'` even though the venv
   has requests installed. `verify.py` prints a dependency precheck first
   thing, so a wrong interpreter shows up immediately.
2. **pytest is not installed by `pip install -e .`** — it is not a runtime
   dependency. Either `pip install pytest` or use stdlib unittest:
   `python -m unittest discover -s tests -q`. `verify.py` tries pytest
   first and falls back to unittest on its own.

No API key is needed for any of these. If `verify.py` exits 0, the whole
pipeline works. If something fails, it tells you the expected verdict and
exit code versus what it got, per fixture.

## The checklist, by hand

### 1. Unit suite — the deterministic core

```bash
python3 -m pytest tests -q
# if pytest is not installed, the same 173 tests run with stdlib unittest:
python3 -m unittest discover -s tests -q
```

Expect: **173 passed**. These cover the call graph, the verifier's 10 rules,
constant propagation, the witness, the debate rule, and the explainer
(21 tests: citation verifier, evidence-pack caps, all four blocker
templates, LLM unavailable / rejected / accepted / not-called), plus 8 tests for
the quiet terminal and HTML report (short stdout, --verbose restore,
HTML written/escaped, `report` command), plus 26 tests for the LLM
status diagnosis and free-model fallback (no_key / timeout / 429 /
bad JSON / network error / cache hit / key redaction, the explainer
summary line, `llm-test`, delisted-404 fallback to the next free
model, all-fallbacks-404, 429 / other-404 / explicit --model never
falling back, fallback cache isolation, CLI --model choice).
(`verify.py` tries pytest first and falls back to unittest on its own.)

### 2. Fixture scans — expected verdicts (sample advisory, no network)

```bash
python3 -m pyreach.cli scan fixtures/<name> --advisory examples/advisory-sample.json
```

Exit code is part of the contract: **2 = reachable, 0 = not_reachable / uncertain**.

| Fixture | Expected | What it proves |
|---|---|---|
| app_vuln | reachable, exit 2 | basic path main → load_config → yaml.load |
| app_safe | not_reachable, exit 0 | only safe_load is used |
| app_dead | not_reachable, exit 0 | dead() calls yaml.load but is never called |
| app_getattr | not_reachable, exit 0 | `name = "safe_load"` resolved by constants |
| app_wrapper | reachable, exit 2 | call through helpers.parse_config |
| app_route | reachable, exit 2 | Flask @app.route handler is an entry |
| app_top | reachable, exit 2 | yaml.load at import time (top-level code) |
| app_nested | reachable, exit 2 | call after a nested def is not dropped |
| app_method | reachable, exit 2 | self./cls. resolves to the right class |
| app_star | reachable, exit 2 | star import picks the right module |
| app_alias | reachable, exit 2 | `load = yaml.load` then `load(f)` |
| app_console | reachable, exit 2 | console_scripts entry, dead() is NOT an entry |
| app_django | reachable, exit 2 | urlpatterns view is an entry, unused view is not |
| app_library | reachable, exit 2 | library mode: only `__all__` is an entry |
| app_click | reachable, exit 2 | click group command is an entry |
| app_getattr_load | reachable, exit 2 | constants: `name = "load"` |
| app_getattr_loop | not_reachable, exit 0 | constants: loop over safe names only |
| app_getattr_config | **uncertain**, exit 0 | name comes from config — must stay uncertain |
| app_getattr_branch | reachable, exit 2 | if/else union: either branch can hit |
| app_getattr_reassign | not_reachable, exit 0 | later assignment wins |
| app_getattr_concat | not_reachable, exit 0 | `"safe_" + "load"` |
| app_importlib | reachable, exit 2 | `importlib.import_module("yaml")` then `.load` |
| app_witness_wrapper | reachable, exit 2 | wrapper path, witness keeps the middle |
| app_proof_args | reachable, exit 2 | entry needs args: witness misses, verdict stays |
| app_getattr_mixed | **uncertain**, exit 0 | two dynamic sites: one safe literal, one config — one safe site must NOT clear the result |
| app_load_collision | reachable, exit 2 | dotted `yaml.load` beats a same-named test fake |
| app_unresolved_attr | **uncertain**, exit 0 | `parser.load()` where parser's type is unknown — must never be not_reachable (Phase 8) |
| app_never_imported | not_reachable, exit 0 | never-imported module's top-level call is dead code (Phase 8) |
| app_vex_full | reachable, exit 2 | yaml.load reachable — no VEX statement for its advisory (Phase 8) |
| app_unparsed | **uncertain**, exit 0 | 1/2 files parsed — completeness gate flips not_reachable (Phase 8) |
| app_mockpatch | not_reachable, exit 0 | `@mock.patch` is not a route, no phantom entry (Phase 8) |
| app_dunder | **uncertain**, exit 0 | getattr inside `__getattr__` runs at runtime though nothing calls it by name (Phase 8) |

### 3. Phase 4 — the resolver, no key needed

```bash
# See the exact prompt the LLM would get, grounded, no model call:
python3 -m pyreach.cli scan fixtures/app_getattr_config \
  --advisory examples/advisory-sample.json --print-prompt
```

Check the prompt lists only functions from that one file (same-file
candidates), the string literals, and the vulnerable function.

With a key (OpenRouter or Groq, free tier), the LLM path runs — put
the key in `.env` in the project root (see "The LLM" below) and run
a plain scan, no flag at all. A key in `.env` IS the request to use
the LLM:

```bash
python3 -m pyreach.cli scan fixtures/app_getattr_config \
  --advisory examples/advisory-sample.json
```

You should see two lines at the top:
`.env: loaded 1 key(s) from .../.env (OPENROUTER_API_KEY)` and
`LLM: key found via .env, resolver on (use --no-llm to skip it)`.
If you see no `.env:` line, there is no `.env` file where pyreach
looked, or the key is already set as a real env var (which wins over
`.env`). `--with-llm` still works as an explicit flag, and `--no-llm`
turns the resolver off even with a key present. `report.json` also
records `"llm_enabled": true/false`, so you can check after the run
whether the LLM was actually on.

Expect it to **stay uncertain** — the name comes from config, and a good
answer there is "unknown". If it ever flips that fixture to not_reachable,
the verifier failed.

### 4. Phase 5 — the witness

```bash
python3 -m pyreach.cli scan fixtures/app_witness_wrapper \
  --advisory examples/advisory-sample.json --with-proof
python3 -m pyreach.cli scan fixtures/app_proof_args \
  --advisory examples/advisory-sample.json --with-proof
```

Expect: the wrapper trace reads
`entry_mod.main -> helpers.parse_config -> yaml.load`; the args fixture
records a TypeError and keeps the verdict reachable.

### 5. Explainer — uncertain results, no key needed

```bash
# Deterministic explanations only (no LLM call at all):
python3 -m pyreach.cli scan fixtures/app_getattr_config \
  --advisory examples/advisory-sample.json --explain --no-llm --out /tmp/report.json
python3 -m pyreach.cli explain --report /tmp/report.json \
  --project fixtures/app_getattr_config --no-llm
```

Expect on app_getattr_config: blocker `dynamic_call` at app.py:10,
the name comes from `config["func"]`, `does_not_know` lists what
`config["func"]` is at runtime, the deterministic explanation ends
with "The verdict remains UNCERTAIN.", `llm_explanation` is null and
`llm_rejected` is false, and the report's `explanations` list has one
entry. `report.json` records `evidence_pack_tokens` (385 on this
fixture — well under the ~1,500 cap).

On app_getattr_mixed the blocked edge must be line 19 (the config
site), not line 15 (the safe literal `"safe_load"` — already decided).
On app_vuln `--explain` prints "no uncertain results to explain"
and the report's `explanations` list is empty.

The terminal shows one line per explanation only
(`explain [uncertain] yaml.load — blocker dynamic_call, blocked at
app.py:10`) — the full text is in `report.json` and in the readable
HTML report written next to it (`report.html`, same directory; open
it in a browser). `report.json` records `"html_report": "report.html"`.
`--verbose` restores the full explanation text on the terminal, and
`pyreach report --report /tmp/report.json` regenerates the HTML from
an existing report without re-scanning. A quiet scan has no terminal
line over ~500 characters — a MkDocs scan used to print ~240KB, mostly
one 151,785-character line of entry evidence (19 Nov 2026).

With a key in `.env`, a plain `--explain` scan also runs the LLM
layer (same auto-enable as Phase 4; `--no-llm` turns it off). The
LLM answer is accepted only if its verdict is exactly `"uncertain"`,
its blocker matches the deterministic one, and every cited snippet
matches the code verbatim — otherwise `llm_rejected` is true and
only the deterministic explanation is shown. The LLM layer has never
run with a real key in this repo; if you run it and it is rejected,
that is the safe outcome, not a failure.

### 6. Live test — the real advisory pipeline (needs network)

```bash
python3 -m pyreach.cli fetch PyYAML 5.3.1 --out /tmp/advisories.json
python3 -m pyreach.cli scan fixtures/app_vuln --advisory /tmp/advisories.json
```

Expect the fetch to print `GHSA-8q59-q68h-6hv4` (CVE-2020-14343, fixed
5.4) with 7 medium-confidence candidates, and the scan to report
**4 reachable / 3 not_reachable / 0 uncertain, exit 2**. Run the fetch
twice: the second run should report a cache hit with byte-identical output.

## Try to break it — the adversarial tests

These are the tests that matter for the judges. Each one is a one-line
change to a fixture, then re-scan and check the verdict flips the right way:

1. **app_safe → make it vulnerable.** Change `safe_load` to `load` in
   `fixtures/app_safe/app.py`. Expect reachable, exit 2. Change it back.
2. **app_dead → call dead().** Add a call to `dead()` in `main()`. Expect
   reachable. Remove it.
3. **app_getattr → config source.** Change `name = "safe_load"` to
   `name = config["func"]` (add `config = {"func": "load"}` at the top).
   Expect uncertain, never not_reachable.
4. **app_getattr_load → hide the name.** Change `name = "load"` to
   `name = os.environ["FUNC"]`. Expect uncertain.
5. **Delete a file.** Remove `fixtures/app_vuln/config.yaml` and scan with
   `--with-proof`. Expect the witness to fail gracefully and the static
   verdict to stay reachable. Restore the file.
6. **The worst failure — a false not_reachable.** Any change above that
   makes a reachable case report not_reachable is a fail-closed bug.
   Report it, do not work around it: that is exactly what the
   completeness ledger and the uncertain rate in the report are for.

## Test on a real library — PyYAML 5.3.1's own source

This is the real-workflow test. It caught a genuine bug on 19 Nov 2026
(see below), so run it exactly like this:

```bash
pip download PyYAML==5.3.1 --no-deps --no-binary :all: -d /tmp/real-test
cd /tmp/real-test && tar xzf PyYAML-5.3.1.tar.gz
python -m pyreach.cli scan PyYAML-5.3.1 --package PyYAML --version 5.3.1
```

Expect: **7 uncertain, 0 not_reachable, exit 0**, in about 6 seconds.
The report's reason for `yaml.load` should read
"resolved 9/51 dynamic sites safe, 42 still unknown — staying uncertain".

Why uncertain and not reachable? PyYAML's own tests genuinely call
`yaml.load` (tests/lib3/test_yaml_ext.py:248), but only through the test
runner's dynamic dispatch, so there is no static path from any entry
point. Uncertain is the honest answer here. Before the 19 Nov fix the
tool said **not_reachable** for all 7 candidates, because a single
`getattr(..., "encoding")` site resolved safe and the old Phase 4 let
one site decide the whole result. If you ever see not_reachable on
this scan again, that bug is back.

Also expect in the ledger: `project_source: 59/79 parsed`. The other 20
files are the Python 2 versions of the same code (lib/ and tests/lib/),
which Python 3's parser cannot parse. That is recorded, not hidden.

## Test on any real repo

```bash
git clone <any Python repo that uses PyYAML>
python -m pyreach.cli scan <repo> --package PyYAML --version 5.3.1
```

That fetches the live advisory and scans real code against it. Start with
a small project you know: one file that calls `yaml.load`, one that only
calls `yaml.safe_load`. Check the verdicts match what you know, then try a
bigger repo and read `report.json` — especially the completeness ledger
and the uncertain rate. On a big repo, skip `--with-proof` at first: the
witness runs one subprocess per reachable result.

## Test scan-all — the whole project (Phase 7, 19 Nov 2026)

Offline, deterministic, no network — advisory files stand in for OSV:

```bash
python -m pyreach.cli scan-all fixtures/app_scanall --advisory-dir fixtures/app_scanall_advisories --no-llm --out report.json
# expect exit 2. report.json "packages":
#   PyYAML 5.3.1 (pyproject): 1 advisory — 1 reachable (yaml.load)
#   requests 2.31.0: not-checked — no advisory file in the dir, NOT assumed clean
#   pyreach-skip-demo: skipped — range-only (>=1.0), no exact version anywhere
python -m pyreach.cli scan-all fixtures/app_scanall --advisory-dir fixtures/app_scanall_advisories --only pyyaml --no-llm --out report.json
# expect exit 2, packages == [PyYAML] only
```

Live, on a real repo (needs network). Pin the version you want checked —
a bare `pyproject.toml` range is not a version, and a range-only dep is
skipped, not guessed:

```bash
git clone --depth 1 https://github.com/mkdocs/mkdocs.git
printf 'PyYAML==5.3.1\n' > /tmp/demo-reqs.txt
python -m pyreach.cli scan-all mkdocs --requirements /tmp/demo-reqs.txt --no-llm --out report.json
# expect exit 2: PyYAML 5.3.1 (requirements) 1 advisory, 4 reachable / 3 uncertain —
# identical verdicts to the single-package scan — plus packaging from the
# installed environment (0 advisories) and 12 range-only deps skipped, listed.
```

`verify.py` section I runs the offline check; `tests/test_deps.py`
covers resolution (pin priority, lockfiles, installed fallback, skip),
`tests/test_scanall.py` covers the offline/live-stubbed/fetch-failed
paths and `--only`. Phase 8 (19 Nov 2026): lockfile-only packages are
added as pinned transitive entries, and direct-URL / editable
requirements are recorded as SKIPPED with a reason instead of being
silently dropped (same for poetry git/path/url deps) —
`tests/test_phase8.py::TestDepsPhase8`.

## Test Phase 8 — the three invariants (19 Nov 2026)

The ChatGPT review fixes, all in `tests/test_phase8.py` (24 tests)
and `verify.py` section J:

```bash
python -m pyreach.cli scan fixtures/app_unresolved_attr --advisory examples/advisory-sample.json --no-llm
# expect uncertain, exit 0, 0 VEX: parser.load() may call yaml.load
python -m pyreach.cli scan fixtures/app_vex_full --advisory examples/advisory-real-pyyaml.json --no-llm
# expect exit 2, 0 VEX statements: yaml.load reachable blocks not_affected
# for the whole advisory even though full_load and yaml.full_load are not_reachable
python -m pyreach.cli scan fixtures/app_safe --advisory examples/advisory-sample.json --no-llm
# expect not_reachable, exit 0, exactly 1 VEX statement
python -m pyreach.cli scan fixtures/app_dunder --advisory examples/advisory-sample.json --no-llm
# expect uncertain, exit 0: the getattr inside __getattr__ runs at runtime
```

## The LLM — do you need it, and where the key goes

**No, not for the core workflow.** Phases 1, 2, 3 and 5 run with no LLM
and no key. The LLM runs only for results that are still uncertain
after constant propagation — it is the last resort for dynamic cases,
never the decider (the 10-rule verifier decides, and a failed
verification stays uncertain). It turns on by itself when a key is in
`.env` or the environment; `--with-llm` is the explicit way to ask
for it, `--no-llm` turns it off even with a key present.

To enable it, get a free key from OpenRouter:

1. Go to [openrouter.ai/keys](https://openrouter.ai/keys) and sign up
   (GitHub or Google, no credit card). Create a key, copy it — it starts
   with `sk-or-v1-` and is shown once.
2. Use the free model id `cohere/north-mini-code:free` (the `:free`
   suffix matters: without it, it is the paid variant). Free tier is
   rate-limited, roughly tens to a couple hundred requests a day.
   (19 Nov 2026: the old default `openai/gpt-oss-20b:free` was
   delisted by OpenRouter — `llm-test` got HTTP 404 "This model is
   unavailable for free" — so the default changed. Do NOT use the paid
   slug `openai/gpt-oss-20b` instead: that would bill you. Free slugs
   churn every few weeks; if `llm-test` 404s, re-check the live
   catalog at openrouter.ai/models, and note pyreach now falls back
   automatically — see "LLM not working?" below.)
3. Put the key in a `.env` file in the project root — this is the
   easiest way, and pyreach loads it automatically on every `scan`
   and `fetch` (no extra flag, no new dependency, stdlib parser in
   `pyreach/dotenv.py`):
   ```powershell
   Copy-Item .env.example .env
   # then open .env in Notepad and replace sk-or-v1-paste-your-key-here
   # with your real key. One line, no quotes, no spaces around the =:
   #   OPENROUTER_API_KEY=sk-or-v1-...
   ```
   On Linux/macOS: `cp .env.example .env`, then edit the same line.
   `.env` is in `.gitignore` — never commit it. If a key ever leaks
   into git, revoke it at openrouter.ai/keys and make a new one.
   pyreach prints `.env: loaded 1 key(s) from .../.env
   (OPENROUTER_API_KEY)` — the key value itself is never printed,
   logged, or written into report.json / openvex.json.
   A `.env` in the scanned project's folder also works, and
   `--env-file <path>` points at a `.env` somewhere else.
   A real environment variable always wins over `.env`: if
   `OPENROUTER_API_KEY` is already set, the `.env` value is ignored
   for that key (pyreach says so on the `.env:` line).
   The old way still works too — PowerShell, this session only:
   ```powershell
   $env:OPENROUTER_API_KEY='sk-or-v1-...'
   ```
   Permanent (then restart the terminal):
   ```powershell
   [System.Environment]::SetEnvironmentVariable('OPENROUTER_API_KEY','sk-or-v1-...','User')
   ```
   On Linux/macOS: `export OPENROUTER_API_KEY='sk-or-v1-...'`.
4. Run it — plain scan, no flag (the `.env` key turns the resolver
   on by itself):
   ```bash
   python -m pyreach.cli scan fixtures/app_getattr_config \
     --advisory examples/advisory-sample.json \
     --model cohere/north-mini-code:free
   ```
   Expect `app_getattr_config` to **stay uncertain** — its name comes
   from config, and the correct LLM answer there is "unknown". If it
   ever flips to not_reachable, the verifier failed.

Groq is the alternative: a free key from console.groq.com/keys, set
`GROQ_API_KEY`, and pass `--model llama-3.1-8b-instant` with
`LLM_BASE_URL=https://api.groq.com/openai/v1/chat/completions`.

### LLM not working? Diagnose it before re-scanning

On the first real MkDocs run with a key (19 Nov 2026), all 3
explanations had `llm_explanation: null` and `llm_rejected: false`
with `llm_enabled: true`. That combination meant the LLM call itself
had returned nothing — not rejected, just unavailable — and the code
swallowed the reason, so there was zero evidence any call had ever
succeeded. That gap is now closed: every explanation carries
`llm_status` / `llm_error`, and `pyreach llm-test` diagnoses the
layer with one call and no scan:

```bash
pyreach llm-test
# ok:    LLM key: present / LLM test: ok in 1.23s (model cohere/north-mini-code:free)  (exit 0)
# no key: LLM key: missing ... / LLM test: no_key — no OPENROUTER_API_KEY ...   (exit 1)
```

`llm_enabled: true` only means a key was found — it never proves a
call succeeded. `llm_status` is the proof. Kinds and what to do:

| `llm_status` | Means | What to do |
|---|---|---|
| `ok` | A parsed JSON answer came back | Nothing; check `llm_rejected` next |
| `rejected` | Answer failed the citation verifier | Safe outcome — read `llm_error` for the rule |
| `no_key` | No key in env or `.env` | Check the `.env` location (project root, scanned project, or `--env-file`) |
| `no_requests` | `requests` not installed | `pip install requests` |
| `timeout` | No reply in 60 s | Check network, retry once |
| `rate_limited` | HTTP 429, free-tier limit | Wait, retry; fewer calls per run |
| `http_error` | Another HTTP status | Read the code in `llm_error` |
| `http_error` + HTTP 404 "unavailable for free" | The free slug was delisted (happened to `openai/gpt-oss-20b:free` on 19 Nov 2026) | Run `llm-test` — it now falls back automatically to the next free model (`google/gemma-4-31b-it:free`, then `nvidia/nemotron-3.5-lightning:free`) and prints which model answered. If all fallbacks 404, re-check the live catalog at openrouter.ai/models and update `FREE_MODEL_FALLBACKS` in `pyreach/resolver.py`. An explicit `--model` never falls back: that choice is yours, delisted or not. |
| `bad_json` | Model replied, but not the expected JSON | Retry — free-tier models sometimes answer in prose |
| `network_error` | Endpoint unreachable | Check network / `LLM_BASE_URL` |
| `not_called` | Layer never ran (`--no-llm`) | Expected — deterministic only |

If `llm_error` names a local file instead of the network — e.g.
`OSError: [Errno 22] Invalid argument: '.reachcache\llm:...json'` —
that was a cache bug, not the API: `:` is illegal in a Windows
filename and the LLM cache key contains it. Fixed 19 Nov 2026
(`cache.py` sanitises every Windows-illegal character; a cache
failure can no longer be reported as `network_error`). The failure
happened when *saving* the model's answer, after a successful POST,
so the key, model and endpoint were fine. `llm-test` never touches
the cache (`cache=None`), which is why it is the right first check:
if it says ok, a scan failure is local.

A scan with `--explain` prints one summary line after the
explanations, e.g. `LLM explainer: 3 called, 0 accepted, 0 rejected,
3 unavailable (timeout)`; `--llm-debug` adds the per-result status
and safe detail. The detail never contains the key or a response
body — at most the HTTP status plus ~120 chars of an error message,
key redacted. `verify.py` section H checks the no-key case: exit 1,
kind `no_key`, no key value printed.
