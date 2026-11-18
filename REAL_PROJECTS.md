# Real-project tests — pyreach, 19 Nov 2026

Three public Python projects, scanned with the live PyYAML 5.3.1
advisory (GHSA-8q59-q68h-6hv4, CVE-2020-14343, fixed 5.4), `--no-llm`,
deterministic only. No LLM, no key. Commands, verbatim:

```bash
git clone --depth 1 https://github.com/mkdocs/mkdocs.git
git clone --depth 1 https://github.com/cookiecutter/cookiecutter.git
git clone --depth 1 https://github.com/pre-commit/pre-commit.git
python -m pyreach.cli scan <project> --package PyYAML --version 5.3.1 --no-llm
```

## Results (after the two fixes below)

| Project | Files | Scan | Verdicts (7 candidates) | Uncertain rate | Exit |
|---|---|---|---|---|---|
| MkDocs | 65 py, 54/65 parsed | 6 s | 4 reachable / 3 uncertain | 43% | 2 |
| Cookiecutter | 90 py, 77/90 parsed | 4 s | 0 reachable / 7 uncertain | 100% | 0 |
| pre-commit | 134 py, 121/134 parsed | 5 s | 0 reachable / 7 uncertain | 100% | 0 |

MkDocs, the one real hit: `yaml.load` reachable, path
`mkdocs.utils.meta.get_data -> yaml.load` (exit 2). The three
library-internal candidates (`FullConstructor.construct_python_*`)
are reachable too, via yaml.load. Honest nuance: the shortest path
shown calls `yaml.load(..., SafeLoader)`, which is safe — but a
second path exists through `mkdocs.utils.yaml.yaml_load`, whose
default loader is `get_yaml_loader()` wrapping `yaml.Loader`
(the unsafe loader). Reachability ≠ exploitability: MkDocs loads
its own config files, not untrusted input, so this is a reachable
call, not a proven exploit. The tool reports the call; a human
still judges the input.

Cookiecutter uses only `yaml.safe_load` in production code
(`cookiecutter/config.py:70`) — and still reports 7/7 uncertain,
never not_reachable. Pre-commit is the same. That is the honest
limit below, not a bug in the scan: the tool cannot yet prove
not_reachable on a real project.

## Two real bugs these scans found (both fixed, both with regression tests)

### Bug 1 — `yaml.load` resolved to a test fake's `.load` (callgraph.py)

Before the fix, all three projects reported 7/7 uncertain, and
MkDocs — which really calls `yaml.load` — was missed entirely.
Cause: Pass 2 resolved a dotted call by simple name first.
`yaml.load` matched exactly one project function whose simple name
is `load`: MkDocs' test fake `FakeEntryPoint.load`. So the graph had
`yaml_load -> FakeEntryPoint.load` and no edge to `yaml.load` at all.
Fix: a dotted call from a known import is resolved as an external
library node BEFORE the simple-name fallback. A dotted call names
its module explicitly — `yaml.load` cannot be `FakeEntryPoint.load`.
Guard: if the dotted base IS a project top-level package (e.g.
`self.load` resolved to `mkdocs...load`), normal resolution still
applies. Regression: `fixtures/app_load_collision` + test
`test_dotted_library_call_beats_same_simple_name` (65 tests total).

### Bug 2 — external library functions became entry points (entrypoints.py)

After Bug 1 was fixed, MkDocs reported `yaml.load` reachable with
path `["yaml.load"]` — no evidence chain. Cause: library mode added
EVERY public function in the graph as an entry, including external
nodes (`yaml.load`, `os.path.join`, … — 1,697 entries, ~500 of them
external). BFS then found the target as its own entry. Fix: entry
points must be project code; external functions (`file="external"`)
are excluded from library mode, from the no-entry fallback, and
from `_resolve_simple`. Entries fell 1,697 → 1,194 for MkDocs, and
the path is now the real one above. Regression: test
`test_external_library_functions_are_never_entries` (temp library
project, path must be `["pkg.core.load_config", "yaml.load"]`).

## Honest limits these scans confirm (not fixed — bigger work)

1. **No real project reaches not_reachable yet.** Three reasons,
   all in the ledger: (a) the 3 library-internal candidates are
   always uncertain because dependency source is 0/0 parsed — the
   tool never parses PyYAML itself; (b) any ambiguous edge anywhere
   blocks not_reachable for the other 4 candidates (Cookiecutter:
   12 ambiguous edges, pre-commit: 301, MkDocs: 1,980); (c) any
   reachable dynamic trigger does the same (MkDocs 11, pre-commit 5).
   Fail-closed is the design, but on real code it means "uncertain"
   is the common answer, and the uncertain rate is the metric to
   watch — MkDocs 43% after the fixes, the other two still 100%.
2. **`functools.partial` wrappers are invisible.** Pre-commit's
   real YAML entry is `yaml_load = functools.partial(yaml.load,
   Loader=CSafeLoader)` in `pre_commit/yaml.py`. The graph only
   records Call nodes, so a `yaml.load` passed as an argument to
   `partial` is never an edge. Here that is safe (CSafeLoader), so
   the uncertain verdict is safe but for the wrong reason. Tracking
   `partial` (and similar wrappers) is the next graph feature, not
   a one-line fix.
3. **The tool does not distinguish the Loader argument.**
   `yaml.load(x, SafeLoader)` and `yaml.load(x, Loader=yaml.Loader)`
   are both just `yaml.load` to the graph. MkDocs shows why that
   matters: one is safe, one is not, same verdict. Loader-aware
   verdicts would need the call's argument tracked through the
   wrapper (`yaml_load` → `yaml.load` with its loader).
4. **Entry-point count in library mode is still broad** (MkDocs
   1,194, Cookiecutter 456) — every public function is an entry.
   That is by design for libraries, but it means a "reachable"
   verdict on a library can come from a test helper or an unused
   public function. The path in the report is the check: read it,
   don't just read the verdict.

## Verification — fresh extract, 19 Nov 2026 (after both fixes)

Verified from a fresh extract of `pyreach-phase5-real-projects.zip`
(md5 `4c7420e660cbb04af82355422e57a795`), NOT from the source dir:

- Unit tests: **65/65 OK**. `verify.py --live`: **31/31** (26 fixtures
  + prompt + 2 witness + live OSV fetch).
- Thorough check script (`../real-projects-pyreach/verify-check.py`,
  explicit PASS/FAIL assertions, no eyeballing): **32/32 passed**.
  It re-scanned all three projects from the fresh extract and checked:
  all three `yaml.load` callers in MkDocs have the edge, none points
  at `FakeEntryPoint.load`; no external function is an entry point;
  MkDocs entries 1,194 (< 1,697 pre-fix); MkDocs exit 2 with path
  exactly `["mkdocs.utils.meta.get_data", "yaml.load"]`; Cookiecutter
  and pre-commit exit 0, `yaml.load` uncertain with no path; no false
  `not_reachable` anywhere; `llm_enabled` false (`--no-llm`); OpenVEX
  0 statements everywhere. Reports: `*-verify.json` in the same folder.
- **One minor new finding, not a failure:** 123 "phantom" entries in
  MkDocs — names not in the graph at all, e.g.
  `...config_options_tests.test_invalid_dict_item` (a method, missing
  its class). Cause: entrypoints matches `@mock.patch` via the
  `".patch"` substring in `ROUTE_DECORATORS`, and builds the name
  without the class. They are dead starts with no edges, so they
  cannot create a reachable verdict — but they inflate the entry
  count. Recorded here, deliberately NOT fixed in this verification
  pass, so the verified zip stays the verified zip.

## Files

- Full reports (after fixes): `../real-projects-pyreach/`
  `mkdocs-report.json`, `cookiecutter-report.json`,
  `pre-commit-report.json` (report3 runs), plus `*-verify.json`
  (fresh-extract re-runs) and `verify-check.py` (the 32 checks).
- Before-fix runs are not kept: MkDocs was 7/7 uncertain, exit 0;
  after Bug 1 alone it was 4 reachable / 3 uncertain with the
  bogus `["yaml.load"]` path; after Bug 2 the path is real.
