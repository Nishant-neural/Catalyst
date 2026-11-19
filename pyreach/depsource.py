"""Phase 11 (19 Nov 2026): parse a vulnerable dependency's own source.

Until now pyreach never read dependency source: the ledger reported
dependency 0 parsed, and every library-internal candidate stayed
uncertain by design (reach._is_library_internal) — the tool could not
prove a function the project never calls directly is never called,
because the library itself might call it. That is why no real project
ever reached not_reachable, and why the demo's Flask/Jinja2 results
were all uncertain.

With --with-deps, for each advisory package pinned to an exact version,
pyreach downloads that version's sdist from PyPI (cached under
<cache-dir>/deps/<pkg>-<version>/), finds the top-level package inside
it (src/ layout, lib/ or lib3/ layout, flat layout, or a single .py
module), builds the SAME AST call graph over it, and merges it into
the project graph. Then:
- a project call into a public API that internally calls the vulnerable
  function becomes a real reachable path (BFS follows the merged edges);
- an internal function nothing reachable calls becomes not_reachable,
  with the dependency graph as the evidence;
- the ledger reports real dependency discovered/parsed counts.

Fail-closed throughout: no sdist, no network, an unrecognised layout,
or a version that cannot be resolved exactly -> the dependency is left
unparsed and its candidates stay uncertain exactly as before. Merging
never overwrites a real project function (project wins on a name
collision) but DOES replace the external placeholder node for a library
call (file="external") with the real dependency function — that
replacement is what lets BFS continue from the project call into the
dependency body. Merged dependency functions are never entry points
(entrypoints.py excludes them by file).
"""
from __future__ import annotations

import hashlib
import io
import shutil
import tarfile
from pathlib import Path

from .callgraph import Graph, build_graph
from .deps import normalize_name
from .phase1 import _get_requests


def import_names_for_advisory(adv) -> list[str]:
    """Top-level import names an advisory's candidates use: the first
    dotted segment of each vulnerable function (yaml.load -> yaml,
    jinja2.filters.do_attr -> jinja2). These are the names to look for
    inside the sdist — the PyPI name alone is not enough (PyYAML's
    import name is yaml, not pyyaml)."""
    names: list[str] = []
    for vf in getattr(adv, "vulnerable_functions", []) or []:
        first = (vf.qualified or "").split(".")[0]
        if first and first not in names:
            names.append(first)
    return names


def _sdist_meta(package: str, version: str, requests):
    r = requests.get(f"https://pypi.org/pypi/{package}/{version}/json",
                     timeout=10)
    r.raise_for_status()
    urls = r.json().get("urls", [])
    return next((u for u in urls if u.get("packagetype") == "sdist"), None)


def fetch_sdist(package: str, version: str, cache_dir) -> Path | None:
    """Download the sdist for package==version from PyPI and extract it
    once under <cache_dir>/deps/<pkg>-<version>/. Returns the extract
    dir, or None when there is no sdist, no network, or no requests
    library. A .pyreach-sha256 marker records the sdist hash, so a
    cached extract is never stale and never re-downloaded."""
    try:
        requests = _get_requests()
    except Exception:
        return None
    dest = Path(cache_dir) / "deps" / f"{normalize_name(package)}-{version}"
    marker = dest / ".pyreach-sha256"
    try:
        meta = _sdist_meta(package, version, requests)
    except Exception:
        return None
    if not meta:
        return None
    sha = (meta.get("digests") or {}).get("sha256", "")
    if sha and marker.exists():
        try:
            if marker.read_text(encoding="utf-8").strip() == sha:
                return dest
        except OSError:
            pass
    try:
        data = requests.get(meta["url"], timeout=60).content
        if sha and hashlib.sha256(data).hexdigest() != sha:
            return None
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            try:
                tf.extractall(dest, filter="data")
            except TypeError:
                # Python < 3.12 has no filter argument.
                tf.extractall(dest)
        if sha:
            marker.write_text(sha, encoding="utf-8")
        return dest
    except Exception:
        return None


def find_package_root(extract_dir, import_names):
    """Find the top-level package inside an extracted sdist.

    Returns (parent_dir, package_dir, import_name) or None. parent_dir
    is the directory build_graph should run on, so _module_name yields
    real import names (jinja2.filters, not src.jinja2.filters):
    for a src/ layout that is src/, for lib/ it is lib/, for a flat
    layout it is the sdist root. A package dir wins over a single .py
    module of the same name. Between lib/ and lib3/ (PyYAML ships
    both), lib3/ wins — it is the Python 3 source. top_level.txt in
    an egg-info dir is a fallback source of import names.
    """
    extract = Path(extract_dir)
    names = set(import_names)
    for tl in extract.rglob("top_level.txt"):
        try:
            names |= {ln.strip() for ln in tl.read_text(
                encoding="utf-8", errors="ignore").splitlines()
                if ln.strip() and not ln.strip().startswith("#")}
        except OSError:
            continue
    cands = []
    for init in extract.rglob("__init__.py"):
        pkg = init.parent
        if pkg.name in names:
            try:
                rel = pkg.relative_to(extract)
            except ValueError:
                continue
            rank = {"src": 0, "lib3": 1, "lib": 2}.get(pkg.parent.name, 3)
            cands.append((len(rel.parts), rank, pkg))
    if cands:
        cands.sort(key=lambda t: (t[0], t[1]))
        pkg = cands[0][2]
        return pkg.parent, pkg, pkg.name
    singles = []
    for name in names:
        for mod in extract.rglob(f"{name}.py"):
            try:
                rel = mod.relative_to(extract)
            except ValueError:
                continue
            singles.append((len(rel.parts), mod))
    if singles:
        singles.sort(key=lambda t: t[0])
        mod = singles[0][1]
        return mod.parent, mod.parent, mod.stem
    return None


def parse_dependency(package: str, version: str, import_names,
                     cache_dir):
    """Fetch + build the call graph for one pinned dependency.

    Returns (dep_graph, discovered, parsed, import_name) or None.
    discovered/parsed count .py files under the package dir only:
    test files elsewhere in the sdist are parsed by build_graph but
    never counted, never entries, and never reachable — they are not
    part of the package."""
    extract = fetch_sdist(package, version, cache_dir)
    if extract is None:
        return None
    found = find_package_root(extract, import_names)
    if found is None:
        return None
    parent, pkg_dir, import_name = found
    dep = build_graph(parent)
    discovered = len(list(pkg_dir.rglob("*.py")))
    parsed = sum(1 for rel in dep.files_parsed
                 if (parent / rel).is_relative_to(pkg_dir))
    return dep, discovered, parsed, import_name


def merge_dependency(graph: Graph, dep: Graph, import_name: str,
                     discovered: int, parsed: int) -> None:
    """Merge a dependency graph into the project graph, in place.

    Rules: a real project function always wins a name collision; an
    external placeholder node (file="external", created when project
    code calls yaml.load) LOSES to the real dependency function, which
    is what lets BFS continue into the dependency body. Edges and
    ambiguous calls are merged only for callers that are not real
    project functions (a class -> __init__ edge caller is a class
    prefix, never a project function, so it merges). Project
    files_parsed is untouched — the ledger counts project and
    dependency files separately.
    """
    project_defined = {q for q, info in graph.functions.items()
                       if info.file != "external"}
    dep_files = set(dep.module_by_file.keys())
    for q, info in dep.functions.items():
        if q not in project_defined:
            graph.functions[q] = info
    for caller, callees in dep.edges.items():
        if caller in project_defined:
            continue
        graph.edges.setdefault(caller, set()).update(callees)
    for caller, cands in dep.ambiguous.items():
        if caller in project_defined:
            continue
        graph.ambiguous.setdefault(caller, set()).update(cands)
    graph.dynamic.extend(dep.dynamic)
    graph.unresolved_attrs.extend(dep.unresolved_attrs)
    # Deliberately NOT merged: referenced_dotted / referenced_names.
    # The reference rule (reach._referenced_in_project) is about
    # PROJECT code handing a target to something (Loader=yaml.FullLoader
    # in app code). References inside dependency code are the
    # dependency's own business and are already covered by the merged
    # graph itself: if reachable dep code references the target, the
    # dynamic / unresolved-attr sites around it are what can invoke it,
    # and those DO merge. Merging dep references made every dep-internal
    # cross-reference (idna's own code mentioning idna.encode) fire the
    # rule — a false trigger (19 Nov 2026, requests --with-deps).
    graph.imports_by_file.update(dep.imports_by_file)
    graph.module_by_file.update(dep.module_by_file)
    for mod, imps in dep.file_imports.items():
        graph.file_imports.setdefault(mod, set()).update(imps)
    graph.imported_modules |= dep.imported_modules
    graph.unresolved_imports.extend(dep.unresolved_imports)
    graph.dependency_files |= dep_files
    graph.dependency_parsed_modules.add(import_name)
    graph.dependency_coverage[import_name] = (discovered, parsed)
    # Re-export aliases: the top-level __init__ (module == import_name)
    # re-exports names defined in submodules (fakepkg/__init__.py does
    # `from .core import public_api`). Project code calls the public
    # name (fakepkg.public_api), which the project graph recorded as an
    # external node; link it to the real definition so BFS continues
    # into the dependency body. A star re-export (`from .core import *`)
    # has no per-name record, so that alias is missed and the path
    # stays uncertain — fail-closed, not guessed.
    for fpath, mod in dep.module_by_file.items():
        if mod != import_name:
            continue
        for local, target in dep.imports_by_file.get(fpath, {}).items():
            alias = f"{import_name}.{local}"
            if (alias != target and alias in graph.functions
                    and target in graph.functions):
                graph.edges.setdefault(alias, set()).add(target)
