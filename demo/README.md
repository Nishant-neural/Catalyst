# pyreach demo — four real repos, scanned whole

Run it: `bash demo/run-demo.sh [workdir]` (defaults to `./demo-work`).
It clones Flask, requests and httpx, scans each repo's **whole runtime
dependency set** with `pyreach scan-all`, and writes one report per repo
(`<repo>-demo.json` + a readable `<repo>-demo.html` next to it).

## What the demo shows

| repo | deps scanned | advisories | reachable | uncertain | not_reachable |
|------|--------------|------------|-----------|-----------|---------------|
| Flask (2023 pins) | 6 | 4 | 0 | 9 | 0 |
| requests (2023 pins) | 4 | 2 | 1 | 2 | 0 |
| httpx (2023 pins) | 4 | 3 | 1 | 1 | 6 |
| yamllint (2023 pins) | 2 | 1 | 0 | 0 | 7 |
| **total** | **16** | **10** | **2** | **12** | **13** |

The two reachable findings (recorded 19 Nov 2026):

- **requests → `urllib3.util.retry.Retry.__init__`** (GHSA-34jh-p97f-mpxf,
  Proxy-Authorization header not stripped on cross-origin redirect).
  Path: `Session.__init__ → HTTPAdapter → HTTPAdapter.__init__ → Retry`
  — every `requests` session builds a `Retry`, so the vulnerable code
  runs on every session.
- **httpx → `idna.encode`** (GHSA-jjg7-2v4v-x38h, IDNA denial of service).
  Path: `URL.__init__ → urlparse → encode_host → idna.encode` — every
  URL httpx parses goes through `idna.encode`.

The 12 uncertain findings each carry a **pre-seeded deterministic
explanation** (blocker, evidence, what is not known, and one
discriminating check). The 13 not_reachable findings (7 yamllint +
6 httpx) carry no explanation — there is nothing uncertain left to
explain — and 2 of them come with an OpenVEX `not_affected` statement
(yamllint's GHSA-8q59-q68h-6hv4 and httpx's GHSA-82r6-8w77-94w6). Nothing in the demo calls an LLM: the explanations
are the deterministic explainer's output (`--explain --no-llm`), computed
ahead of time and stored in the reports. The LLM explainer is left out
on purpose — it depends on a free-model API whose slugs get delisted.

## yamllint — the not_reachable demo (Phase 13, 19 Nov 2026)

yamllint is the fourth repo because it is the one that proves the tool
can clear an alert, not just find or shrug at one: **7/7 not_reachable,
0% uncertain, plus 1 OpenVEX `not_affected` statement** for
GHSA-8q59-q68h-6hv4 (PyYAML 5.3.1). It only ever uses `yaml.safe_load`
and `yaml.SafeLoader` — never `yaml.load` with the unsafe Loader, never
`full_load`, never `FullLoader`. Two Phase 13 features make that provable:

- **Loader-aware verdicts**: the tool records the Loader argument at
  every call into `yaml.load` (including `safe_load`, which is
  `load(stream, SafeLoader)`). yamllint reaches `yaml.load` only
  through `SafeLoader`, so `yaml.load` and the three
  `FullConstructor.construct_*` internals flip from reachable to
  not_reachable — with the loader named in the reason. Any unsafe or
  unknown loader anywhere reachable blocks the flip (MkDocs keeps its
  4 reachable for exactly that reason: its wrapper passes
  `Loader=yaml.Loader`).
- **Resolver reorder**: the three remaining candidates (`FullLoader`,
  `full_load`, `yaml.full_load`) were blocked by dynamic sites whose
  names are literals (`getattr(rule, 'CONF')`, `getattr(rule,
  'DEFAULT')`, `getattr(stream, 'name')` in PyYAML's reader). Constant
  propagation on the name now runs before the receiver check, so all
  four dynamic sites resolve safe in Phase 4 and the candidates flip
  to not_reachable. The per-advisory VEX gate (fully parsed, no
  unresolved imports or entry points, no dynamic site left unresolved,
  no ambiguous edge matching the advisory's targets) then emits the
  statement — the old whole-run gate never would have, because
  PyYAML's own code contributes 64 ambiguous edges that cannot be any
  of these targets.

yamllint's scan is the only one in the demo that passes `--with-deps`
(it needs PyYAML's source parsed, and the sdist download needs
network the first time; it is cached after that). The other three
repos keep their no-deps numbers — but httpx's numbers still moved in
Phase 13, because the resolver reorder (below) let all 7 of its
dynamic sites resolve safe: `locals()` and four `setattr()` calls,
which cannot call a function at all, plus `getattr(value, "name")`
and `getattr(result, "close")`, whose names are literals. All 6
anyio candidates that were uncertain on those sites are now
not_reachable, and GHSA-82r6-8w77-94w6 (all four candidates cleared)
gets the demo's second OpenVEX statement. `sys.stderr` stays
uncertain — it is referenced in httpx's code, so the reference rule
keeps it open.

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

## `--with-deps`: parsing the dependency's own source (Phase 11)

The demo above runs WITHOUT dependency parsing: the tool reads the
project's code but never opens Jinja2's or Werkzeug's code, so
library-internal candidates stay uncertain by design. `--with-deps`
changes that: for each pinned advisory package it downloads the sdist
from PyPI (cached under `.reachcache/deps/`) and merges its call graph
into the project's, so an internal function can be proven reachable
or not-reachable.

Proven on ONE project only so far (19 Nov 2026, limited scope):
requests, same 2023 pins, same advisory files, `--with-deps` added
(~7 s, sdists cached after the first run). idna 8/8 + urllib3 39/39
parsed, dependency 47/47. Verdicts unchanged — 1 reachable
(Retry.__init__, same path), 2 uncertain — but the reasons are now
grounded: huntr.com is "not found in the parsed idna source", and
idna.encode is uncertain because a reachable dynamic trigger may hide
a path (the path breaks at `poolmanager.urlopen`, an attribute call on
an object of unknown type). Report:
`~/workspace/real-projects-pyreach/requests-demo-deps.json` (+ .html).

That limit is now FIXED (Phase 13, 19 Nov 2026): Loader-aware
verdicts (above) tell `safe_load` apart from unsafe `load`, so
`app_safe --with-deps` is now 7/7 not_reachable instead of yaml.load
reading reachable. `verify.py` section K asserts the new behaviour.
What remains a real limit: a project whose dynamic sites cannot be
resolved (bandit's plugin `import_module` calls) or whose files do
not all parse (cookiecutter's 2 Jinja-template files) still goes
uncertain — the completeness gate flips any not_reachable back when
the project is incomplete, and that is by design.
