#!/usr/bin/env bash
# pyreach demo: scan four real repos WHOLE (all runtime dependencies,
# not just PyYAML) and report the vulnerabilities.
#
#   bash demo/run-demo.sh [workdir]
#
# What it does:
#   1. Clones Flask, requests, httpx and yamllint at the pinned commits
#      used for the recorded demo numbers (19 Nov 2026).
#   2. Runs `pyreach scan-all` on each repo with its 2023-pinned runtime
#      dependencies (demo/requirements/*.txt) and the pre-seeded advisory
#      files (demo/advisories/ — real OSV advisories with pyreach's own
#      fix-commit mapping baked in, so the demo needs no GitHub API
#      quota and no network beyond the clones).
#   3. Writes one report per repo (<repo>-demo.json) plus an HTML report
#      next to each JSON, and prints the verdict summary.
#
#   yamllint's scan passes --with-deps, so it downloads the PyYAML 5.3.1
#   sdist from PyPI (cached under .reachcache/deps/ after the first run).
#   The other three scans need no network beyond the clones.
#
# No LLM is involved anywhere in the demo: explanations are the
# deterministic explainer's output (--explain --no-llm), pre-seeded in
# the reports. The LLM explainer is deliberately left out of the demo
# because it depends on a free-model API that changes under you.
#
# Exit code: 2 if any repo has a reachable vulnerability, else 0.
set -euo pipefail

WORKDIR="${1:-$PWD/demo-work}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYREACH="$REPO_ROOT"

echo "pyreach demo — four real repos, whole-repo scan"
echo "workdir: $WORKDIR"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

clone() {
  local name="$1" url="$2" sha="$3"
  if [ -d "$name" ]; then
    echo "--- $name: already cloned, checking out $sha"
    (cd "$name" && git checkout -q "$sha")
  else
    echo "--- cloning $name"
    git clone -q "$url" "$name"
    (cd "$name" && git checkout -q "$sha")
  fi
}

clone flask    https://github.com/pallets/flask.git    49943b5
clone requests https://github.com/psf/requests.git      3c7baaa
clone httpx    https://github.com/encode/httpx.git      7cff5f7
clone yamllint https://github.com/adrienverge/yamllint.git 96246fb

# Runtime-only dependency sets (the --only lists keep dev/lockfile
# packages out of the demo; see demo/README.md for why).
declare -A ONLY=(
  [flask]="blinker,click,itsdangerous,jinja2,markupsafe,werkzeug"
  [requests]="certifi,charset-normalizer,idna,urllib3"
  [httpx]="certifi,httpcore,anyio,idna"
  [yamllint]="pathspec,pyyaml"
)
# yamllint is the not_reachable demo: it only ever uses yaml.safe_load,
# so its PyYAML verdicts need the dependency source parsed (--with-deps,
# Phase 11/13). The other three repos keep their no-deps numbers, so
# their scans do NOT get --with-deps here.
declare -A WITH_DEPS=(
  [yamllint]="--with-deps"
)

OVERALL=0
for repo in flask requests httpx yamllint; do
  echo ""
  echo "=== $repo ==="
  set +e
  python -m pyreach.cli scan-all "$WORKDIR/$repo" \
    --requirements "$PYREACH/demo/requirements/$repo-2023.txt" \
    --advisory-dir "$PYREACH/demo/advisories" \
    --only "${ONLY[$repo]}" \
    ${WITH_DEPS[$repo]:-} \
    --no-llm --explain \
    --out "$WORKDIR/$repo-demo.json" \
    --vex "$WORKDIR/$repo-demo-vex.json"
  code=$?
  set -e
  if [ "$code" -eq 2 ]; then OVERALL=2; fi
  echo "report: $WORKDIR/$repo-demo.json (+ .html next to it)"
done

echo ""
echo "demo done. exit=$OVERALL (2 = a reachable vulnerability was found)"
exit "$OVERALL"
