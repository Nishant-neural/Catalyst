# pyreach demo — three real repos, scanned whole

Run it: `bash demo/run-demo.sh [workdir]` (defaults to `./demo-work`).
It clones Flask, requests and httpx, scans each repo's **whole runtime
dependency set** with `pyreach scan-all`, and writes one report per repo
(`<repo>-demo.json` + a readable `<repo>-demo.html` next to it).

## What the demo shows

| repo | deps scanned | advisories | reachable | uncertain | not_reachable |
|------|--------------|------------|-----------|-----------|---------------|
| Flask (2023 pins) | 6 | 4 | 0 | 9 | 0 |
| requests (2023 pins) | 4 | 2 | 1 | 2 | 0 |
| httpx (2023 pins) | 4 | 3 | 1 | 7 | 0 |
| **total** | **14** | **9** | **2** | **18** | **0** |

The two reachable findings (recorded 19 Nov 2026):

- **requests → `urllib3.util.retry.Retry.__init__`** (GHSA-34jh-p97f-mpxf,
  Proxy-Authorization header not stripped on cross-origin redirect).
  Path: `Session.__init__ → HTTPAdapter → HTTPAdapter.__init__ → Retry`
  — every `requests` session builds a `Retry`, so the vulnerable code
  runs on every session.
- **httpx → `idna.encode`** (GHSA-jjg7-2v4v-x38h, IDNA denial of service).
  Path: `URL.__init__ → urlparse → encode_host → idna.encode` — every
  URL httpx parses goes through `idna.encode`.

Everything else is **uncertain, with a pre-seeded deterministic
explanation** for each one (blocker, evidence, what is not known, and one
discriminating check). Nothing in the demo calls an LLM: the explanations
are the deterministic explainer's output (`--explain --no-llm`), computed
ahead of time and stored in the reports. The LLM explainer is left out
on purpose — it depends on a free-model API whose slugs get delisted.

## Why 2023 pins?

At the latest installed versions, these three repos have **zero**
advisories affecting them (verified: `requests` at latest = 0 advisories,
0 results). That is itself a correct answer, but it makes a poor demo.
The 2023 pins are versions these projects actually shipped with, and
they carry real, known CVEs — so the demo shows the tool catching real
vulnerabilities in real code, not a synthetic fixture.

## What is pre-seeded, and what is live?

- **Pre-seeded** (in `demo/advisories/`): one JSON file per package with
  the real OSV advisories for the pinned version, each with pyreach's
  own fix-commit mapping (vulnerable functions + confidence). Seeding
  this is a demo choice, not a shortcut: the live path fetches the fix
  commit for *every* advisory of *every* package (Jinja2 + Werkzeug
  alone have 24), which takes 5–10 minutes and burns the
  unauthenticated GitHub API quota (60/hr). The mapping itself was
  produced by pyreach's Phase 1 code (`demo/build_advisories.py` is
  not shipped; the script used is recorded in the project history).
- **Live** (computed by the demo run): the call graph, entry points,
  reachability verdicts, call paths, the completeness ledger, the
  deterministic explanations, and the OpenVEX output. Nothing about a
  verdict is pre-seeded.

## Exclusions, stated plainly

- Two advisories were **dropped from the demo set** because OSV lists
  no fix commit for them, so no vulnerable function can be identified
  (GHSA-qccp-gfcp-xxvc for urllib3, GHSA-65pc-fj4g-8rjx for idna).
  The tool's honest answer for them is "uncertain, low confidence";
  they are excluded rather than shown as a row with an empty function
  name.
- The `--only` lists restrict each scan to the repo's **runtime**
  dependencies. Without it, `scan-all` also reads the repo's lockfile,
  and Flask's `uv.lock` alone adds 73 transitive (mostly dev) packages
  — the scan then takes 5+ minutes and the results are dominated by
  dev-tool CVEs. Scanning dev dependencies is a legitimate mode, but
  it is not the demo's story.
- Flask has **0 reachable** findings: its Jinja2 filter and Werkzeug
  `safe_join` candidates are genuinely not callable from Flask's own
  code (filters run from templates; `safe_join` runs inside Werkzeug).
  The tool says uncertain rather than clearing them. That is the
  fail-closed design working, not a gap in the demo.

## The three design questions (from the brief), answered by the demo

1. **Fix commit → vulnerable functions, and how sure?** The advisory
   files carry the fix commit, the diff-mapped functions, and a
   high/medium/low confidence per function (1–2 functions = high,
   3–5 = medium, more = low). The demo's `Retry.__init__` is high
   confidence (function-level diff mapping); the `Request.max_content_length`
   text candidate is medium and is correctly *not* called reachable.
2. **Dynamic features without pretending certainty?** Jinja2's filters
   are invoked from templates, not from code — the tool marks them
   uncertain with a named dynamic-call blocker and a concrete runtime
   check (log what the dynamic call resolves to), instead of guessing.
3. **Caching?** The advisory files and the `.reachcache` diff cache
   mean the second run of the demo is fast: the fix-commit diffs are
   cached by (repo, sha) and the LLM answers (when used) by
   (model, prompt hash). The demo's full run takes ~10 seconds.
