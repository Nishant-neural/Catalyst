"""Phase 7 — scan-all: read a project's real dependencies, resolve each
one to an EXACT version, and scan every package, not just one --package.

Why this exists: until now `pyreach scan` only checked the one package
given with --package/--version. A judge scanning a real project wants
the whole dependency list checked. This module is the dependency half
of that: it answers "which packages, at which exact versions".

Exact versions only, never guessed. A version range (PyYAML >=5.1) is
not a version: OSV advisories are version-specific, and scanning the
wrong version would produce verdicts about code the project does not
run. Exact version sources, in priority order:

  1. an == pin in requirements.txt (the deployed pin wins),
  2. an == pin in pyproject.toml,
  3. a lockfile (poetry.lock / Pipfile.lock / uv.lock),
  4. the installed environment (importlib.metadata — the version
     actually importable in the venv running the scan).

A dependency with no exact version anywhere is SKIPPED, listed in the
report with its spec and where a pin would come from — never scanned
against a guessed version, never silently dropped.

Only stdlib is used (tomllib for pyproject/lockfiles, importlib.metadata
for installed versions), so scan-all works in the same bare venv as the
rest of pyreach.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.10: tomllib is 3.11+
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(.*)$")
_PIN_RE = re.compile(r"==\s*([^\s,;]+)")
_SPEC_SPLIT_RE = re.compile(r"\s*,\s*")


def normalize_name(name: str) -> str:
    """PEP 503: lowercase, runs of -_. collapse to one dash."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirement(line: str) -> tuple[str, str] | None:
    """Parse one requirement line -> (name, spec) or None if not a requirement.

    Handles extras (requests[security]==2.31.0), markers
    (foo>=1.0; python_version>"3.8" — the marker is dropped, the spec kept),
    and inline comments. Direct-URL requirements (foo @ https://...) and
    -e / -r / --index-url lines return None here; -r is followed by the
    caller, not by this function.
    """
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-") or line.startswith("--"):
        return None
    if "://" in line and "@" in line.split(";")[0]:
        return None  # direct URL requirement: no PyPI version to scan
    line = line.split(";")[0].strip()  # drop environment markers
    line = line.split("#")[0].strip()  # drop inline comments
    m = _NAME_RE.match(line)
    if not m:
        return None
    name, _extras, spec = m.group(1), m.group(2), m.group(3).strip()
    return name, spec


def exact_pin(spec: str) -> str | None:
    """The == version in a spec, if the spec pins exactly one version."""
    m = _PIN_RE.search(spec or "")
    return m.group(1).strip() if m else None


def skipped_dependency(line: str, declared_in: str) -> Dependency | None:
    """A dependency that cannot be scanned, recorded as SKIPPED instead
    of silently dropped (19 Nov 2026, ChatGPT §4): direct-URL
    requirements (foo @ https://...) and editable installs (-e ...).
    Neither has a PyPI version to query OSV for, but a scan that drops
    them without a word looks complete when it is not."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Editable: -e <url-or-path>[#egg=name] or --editable <...>
    if line.startswith("-e ") or line.startswith("--editable "):
        rest = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
        name = "unknown"
        m = re.search(r"#egg=([A-Za-z0-9_.\-]+)", rest)
        if m:
            name = m.group(1)
        else:
            tail = rest.split("/")[-1].split("#")[0].strip()
            if tail:
                name = tail
        return Dependency(name=name, spec=rest, declared_in=declared_in,
                          status="skipped",
                          reason=f"editable install ({rest}) — no PyPI version to scan")
    # Direct URL: name @ <scheme>://... (PEP 508). parse_requirement
    # returns None for these; record them here.
    if "://" in line and "@" in line.split(";")[0]:
        name = line.split("@", 1)[0].strip()
        if not name:
            return None
        return Dependency(name=name, spec=line, declared_in=declared_in,
                          status="skipped",
                          reason=f"direct URL requirement ({line}) — no PyPI version to scan")
    return None


@dataclass
class Dependency:
    name: str  # as declared, e.g. "PyYAML"
    spec: str = ""  # version spec as declared, e.g. ">=5.1" or "==5.3.1"
    version: str | None = None  # exact version, or None when unknown
    version_source: str = ""  # requirements | pyproject | lockfile | installed
    pin_source: str = ""  # where an == pin came from: requirements | pyproject
    status: str = "pinned"  # pinned | skipped
    reason: str = ""  # for skipped: why, and where a pin would come from
    declared_in: str = ""  # pyproject.toml | requirements.txt | ...

    @property
    def key(self) -> str:
        return normalize_name(self.name)


def installed_version(name: str) -> str | None:
    """Version importable in this environment, or None if not installed."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version(name)
    except PackageNotFoundError:
        return None
    except Exception:
        return None


def _read_toml(path: Path) -> dict:
    if tomllib is None or not path.exists():
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def read_pyproject_deps(root: Path, include_dev: bool = False) -> list[Dependency]:
    """Dependencies declared in pyproject.toml (project + poetry)."""
    data = _read_toml(root / "pyproject.toml")
    out: list[Dependency] = []
    project = data.get("project", {}) or {}
    for spec_line in project.get("dependencies", []) or []:
        parsed = parse_requirement(str(spec_line))
        if parsed:
            out.append(Dependency(name=parsed[0], spec=parsed[1],
                                  declared_in="pyproject.toml",
                                  pin_source="pyproject"))
        else:
            skip = skipped_dependency(str(spec_line), "pyproject.toml")
            if skip:
                out.append(skip)
    if include_dev:
        groups = data.get("dependency-groups", {}) or {}
        for spec_line in groups.get("dev", []) or []:
            parsed = parse_requirement(str(spec_line))
            if parsed:
                out.append(Dependency(name=parsed[0], spec=parsed[1],
                                      declared_in="pyproject.toml [dependency-groups.dev]",
                                      pin_source="pyproject"))
        for extra in ("dev", "test", "tests"):
            for spec_line in (project.get("optional-dependencies", {}) or {}).get(extra, []) or []:
                parsed = parse_requirement(str(spec_line))
                if parsed:
                    out.append(Dependency(name=parsed[0], spec=parsed[1],
                                          declared_in=f"pyproject.toml [optional-dependencies.{extra}]",
                                          pin_source="pyproject"))
    poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
    for name, req in (poetry.get("dependencies", {}) or {}).items():
        if normalize_name(name) == "python":
            continue
        spec = ""
        reason = ""
        if isinstance(req, str):
            spec = req if req.strip() != "*" else ""
        elif isinstance(req, dict):
            spec = str(req.get("version", "") or "")
            if spec.strip() == "*":
                spec = ""
            # Direct references (git/path/url) have no PyPI version.
            for kind in ("git", "path", "url"):
                if kind in req:
                    reason = (f"direct {kind} reference "
                              f"({req.get(kind)}) — no PyPI version to scan")
                    break
        out.append(Dependency(name=name, spec=spec, reason=reason,
                              status="skipped" if reason else "pinned",
                              declared_in="pyproject.toml [tool.poetry.dependencies]",
                              pin_source="pyproject"))
    if include_dev:
        groups = poetry.get("group", {}) or {}
        for group in groups.values():
            for name, req in (group.get("dependencies", {}) or {}).items():
                if normalize_name(name) == "python":
                    continue
                spec = req if isinstance(req, str) and req.strip() != "*" else ""
                out.append(Dependency(name=name, spec=spec,
                                      declared_in="pyproject.toml [tool.poetry.group.dev]",
                                      pin_source="pyproject"))
    return out


def read_requirements_file(path: Path, _depth: int = 0) -> list[Dependency]:
    """requirements.txt -> deps. Follows -r includes (max depth 3)."""
    out: list[Dependency] = []
    if _depth > 3 or not path.exists():
        return out
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return out
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("-r ") or stripped.startswith("--requirement"):
            inc = stripped.split(None, 1)[1].strip().split()[0]
            out.extend(read_requirements_file(path.parent / inc, _depth + 1))
            continue
        parsed = parse_requirement(stripped)
        if parsed:
            out.append(Dependency(name=parsed[0], spec=parsed[1],
                                  declared_in=path.name,
                                  pin_source="requirements"))
            continue
        skip = skipped_dependency(stripped, path.name)
        if skip:
            out.append(skip)
    return out


def read_lockfile_versions(root: Path) -> dict[str, tuple[str, str]]:
    """Lockfiles -> {normalized name: (version, lockfile name)}."""
    found: dict[str, tuple[str, str]] = {}
    poetry = _read_toml(root / "poetry.lock")
    for pkg in poetry.get("package", []) or []:
        name = str(pkg.get("name", ""))
        ver = str(pkg.get("version", ""))
        if name and ver:
            found.setdefault(normalize_name(name), (ver, "poetry.lock"))
    uv = _read_toml(root / "uv.lock")
    for pkg in uv.get("package", []) or []:
        name = str(pkg.get("name", ""))
        ver = str(pkg.get("version", ""))
        if name and ver:
            found.setdefault(normalize_name(name), (ver, "uv.lock"))
    pipfile = root / "Pipfile.lock"
    if pipfile.exists():
        try:
            data = json.loads(pipfile.read_text(encoding="utf-8"))
            for section in ("default", "develop"):
                for name, info in (data.get(section, {}) or {}).items():
                    ver = str((info or {}).get("version", "")).lstrip("=")
                    if ver:
                        found.setdefault(normalize_name(name), (ver, "Pipfile.lock"))
        except Exception:
            pass
    return found


def resolve_dependencies(root: Path, requirements: str | None = None,
                         include_dev: bool = False
                         ) -> tuple[list[Dependency], list[str]]:
    """All of a project's dependencies, each with an exact version or a
    recorded skip. Returns (deps, notes): notes are human-readable lines
    about what was read and what was skipped, for the terminal summary.
    """
    root = Path(root)
    notes: list[str] = []
    declared: dict[str, Dependency] = {}

    def _add(dep: Dependency) -> None:
        # An exact pin beats a range for the same package; first exact
        # source wins, and a later range never overwrites an exact spec.
        old = declared.get(dep.key)
        if old is None:
            declared[dep.key] = dep
            return
        if exact_pin(dep.spec) and not exact_pin(old.spec):
            dep.declared_in = old.declared_in + " + " + dep.declared_in
            declared[dep.key] = dep

    for dep in read_pyproject_deps(root, include_dev=include_dev):
        _add(dep)
    req_paths: list[Path] = []
    if requirements:
        req_paths.append(Path(requirements))
    else:
        req_paths.append(root / "requirements.txt")
        req_dir = root / "requirements"
        if req_dir.is_dir():
            req_paths.extend(sorted(req_dir.glob("*.txt")))
    for rp in req_paths:
        if rp.exists():
            for dep in read_requirements_file(rp):
                _add(dep)
    lock = read_lockfile_versions(root)
    # Transitive deps (19 Nov 2026, ChatGPT §4): packages the lockfile
    # pins that no direct declaration mentions are still installed and
    # still scannable — add them as pinned lockfile entries. The
    # lockfile is the deployed set, so this covers dev packages too;
    # the report shows version_source "lockfile" for each.
    transitive = 0
    for key, (ver, lock_name) in lock.items():
        if key not in declared:
            declared[key] = Dependency(
                name=key, spec=f"=={ver}", version=ver,
                version_source="lockfile", pin_source="lockfile",
                status="pinned", declared_in=f"{lock_name} (transitive)")
            transitive += 1
    if not declared:
        notes.append("no dependencies found in pyproject.toml, requirements.txt or a lockfile")
        return [], notes

    for dep in declared.values():
        # A Dependency already carrying a skip reason (direct URL /
        # editable / direct git reference) is final: it has no version
        # to resolve, and the specific reason must not be overwritten
        # with the generic "no exact version" text.
        if dep.status == "skipped" and dep.reason:
            continue
        # Transitive lockfile entries already carry their exact version
        # and source — the pin logic below must not relabel them.
        if dep.version:
            continue
        # Priority: requirements == pin, then pyproject == pin, then
        # lockfile, then the installed environment.
        pin = exact_pin(dep.spec)
        if pin and dep.pin_source == "requirements":
            dep.version, dep.version_source = pin, "requirements"
        elif pin:
            dep.version, dep.version_source = pin, "pyproject"
        elif dep.key in lock:
            dep.version, dep.version_source = lock[dep.key][0], "lockfile"
        else:
            inst = installed_version(dep.name)
            if inst:
                dep.version, dep.version_source = inst, "installed"
        if dep.version:
            dep.status = "pinned"
        else:
            dep.status = "skipped"
            where = "pin it with == in requirements.txt, add a lockfile, or install the project in this venv"
            dep.reason = (f"no exact version (spec {dep.spec!r} in {dep.declared_in}); "
                          f"{where}")
    pinned = sum(1 for d in declared.values() if d.status == "pinned")
    skipped = sum(1 for d in declared.values() if d.status == "skipped")
    notes.append(f"{len(declared)} dependencies, "
                 f"{pinned} with an exact version, {skipped} skipped"
                 + (f" ({transitive} transitive from the lockfile)" if transitive else ""))
    return sorted(declared.values(), key=lambda d: d.key), notes


def advisory_file_for(package: str, advisory_dir: str | Path) -> Path | None:
    """<advisory-dir>/<normalized-name>.json, if it exists. Lets scan-all
    run fully offline and reproducibly from pre-fetched advisory files —
    and gives verify.py a deterministic scan-all check with no network.
    """
    base = Path(advisory_dir)
    for cand in (base / f"{normalize_name(package)}.json",
                 base / f"{package.lower()}.json"):
        if cand.exists():
            return cand
    return None
