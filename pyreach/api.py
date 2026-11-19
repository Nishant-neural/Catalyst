"""Local HTTP API for the PyReach React frontend.

Run from the repository root:
    python -m pip install -e ".[api]"
    uvicorn pyreach.api:app --reload --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_ADVISORY = ROOT / "examples" / "advisory-sample.json"
CACHE_DIR = ROOT / ".reachcache"

app = FastAPI(
    title="PyReach API",
    version="0.1.0",
    description="HTTP interface for the PyReach vulnerability reachability scanner.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    project: str = Field(min_length=1)
    advisory: str | None = None
    package: str | None = None
    version: str | None = None
    with_proof: bool = True
    with_llm: bool = False
    no_llm: bool = True
    # Gap fixes (19 Nov 2026): the UI must show what the CLI can prove.
    # --explain fills report["explanations"] (was always [] via the API);
    # --with-deps parses the advisory package's own source, which is what
    # lets loader-aware verdicts flip to not_reachable (was never passed).
    # Both default on; the UI has toggles to turn them off (e.g. offline).
    explain: bool = True
    with_deps: bool = True


class DebateRequest(BaseModel):
    verdict: str
    evidence_lines: list[int] = Field(default_factory=list)
    new_citation: int | None = None
    file_path: str = ""
    support_tokens: list[str] = Field(default_factory=list)
    project: str = ""


def _resolve_path(value: str, *, must_exist: bool = True) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve()
    if must_exist and not path.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {value}")
    return path


def _run_scan(project: str, advisory: str | None, package: str | None,
              version: str | None, with_proof: bool, with_llm: bool,
              no_llm: bool, explain: bool = True,
              with_deps: bool = True) -> dict[str, Any]:
    project_path = _resolve_path(project)
    if not project_path.is_dir():
        raise HTTPException(status_code=400, detail="Project path must be a directory.")

    if bool(package) != bool(version):
        raise HTTPException(
            status_code=400,
            detail="For a live package scan, provide both package and version.",
        )
    if not advisory and not (package and version):
        advisory_path = SAMPLE_ADVISORY
    elif advisory:
        advisory_path = _resolve_path(advisory)
        if not advisory_path.is_file():
            raise HTTPException(status_code=400, detail="Advisory path must be a file.")
    else:
        advisory_path = None

    with tempfile.TemporaryDirectory(prefix="pyreach-api-") as temp_dir:
        report_path = Path(temp_dir) / "report.json"
        # Gap fix: VEX used to be written to openvex.json in the repo root
        # and never returned, so the UI always showed 0 statements. Write
        # it next to the temp report and merge it into the response below.
        vex_path = Path(temp_dir) / "openvex.json"
        command = [
            sys.executable, "-m", "pyreach.cli", "scan", str(project_path),
            "--out", str(report_path),
            "--vex", str(vex_path),
            "--cache-dir", str(CACHE_DIR),
            "--no-html",
        ]
        if advisory_path:
            command.extend(["--advisory", str(advisory_path)])
        # --package/--version is passed even with an advisory file: the
        # advisory supplies the alert list, but the exact version is what
        # --with-deps needs to parse the dependency's own source. Without
        # it the CLI prints "no exact version" and internals stay uncertain.
        if package and version:
            command.extend(["--package", str(package), "--version", str(version)])
        if with_proof:
            command.append("--with-proof")
        if with_llm:
            command.append("--with-llm")
        if no_llm:
            command.append("--no-llm")
        if explain:
            command.append("--explain")
        if with_deps:
            command.append("--with-deps")

        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=900,
                env=os.environ.copy(),
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="The scan exceeded the 15-minute time limit.")
        except OSError as exc:
            raise HTTPException(status_code=500, detail=f"Could not start PyReach: {exc}")

        if not report_path.exists():
            detail = (completed.stderr or completed.stdout or "PyReach did not create a report.")[-3000:]
            raise HTTPException(status_code=500, detail=detail)

        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=500, detail=f"Could not read scan report: {exc}")

        # Exit 2 is an expected PyReach result: at least one reachable finding.
        if completed.returncode not in (0, 2):
            detail = (completed.stderr or completed.stdout or "PyReach scan failed.")[-3000:]
            raise HTTPException(status_code=500, detail=detail)

        # Gap fix: the CLI writes OpenVEX to a separate file and the report
        # dict has no "openvex" key, so the UI could never show it. Merge
        # the file into the response the frontend already reads
        # (report.openvex.statements). Always present the key, even when
        # the scan produced no statements.
        try:
            report["openvex"] = json.loads(vex_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            report["openvex"] = {"statements": []}
        return report


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "pyreach"}


@app.get("/api/fixtures")
def fixtures() -> list[dict[str, str]]:
    fixtures_dir = ROOT / "fixtures"
    expected: dict[str, tuple[str, int]] = {}
    verify_file = ROOT / "verify.py"
    if verify_file.exists():
        spec = importlib.util.spec_from_file_location("pyreach_verify_matrix", verify_file)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            expected = getattr(module, "EXPECTED", {})

    items = []
    for path in sorted(fixtures_dir.iterdir()):
        if path.is_dir():
            verdict = expected.get(path.name, ("unknown", 0))[0]
            items.append({
                "name": path.name,
                "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                "expected_verdict": verdict,
            })
    return items


@app.post("/api/scan")
def scan(request: ScanRequest) -> dict[str, Any]:
    return _run_scan(
        request.project,
        request.advisory,
        request.package,
        request.version,
        request.with_proof,
        request.with_llm,
        request.no_llm,
        request.explain,
        request.with_deps,
    )


@app.post("/api/debate")
def debate(request: DebateRequest) -> dict[str, Any]:
    # Keep the project's own concede-or-cite rule as the only authority.
    from pyreach.debate import answer_challenge

    if request.verdict not in {"reachable", "not_reachable", "uncertain"}:
        raise HTTPException(status_code=400, detail="Invalid verdict.")

    source_lines: list[str] = []
    if request.file_path:
        source_path = _resolve_path(request.file_path)
        if not source_path.is_file():
            raise HTTPException(status_code=400, detail="Evidence path must be a file.")
        source_lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    elif request.project:
        project_path = _resolve_path(request.project)
        if not project_path.is_dir():
            raise HTTPException(status_code=400, detail="Project path must be a directory.")
        # The UI provides a line number but no file picker. Check Python source
        # files for a matching support token at that line; if none supports it,
        # the core's fail-closed rule concedes to UNCERTAIN.
        if request.new_citation is not None:
            for source_path in project_path.rglob("*.py"):
                if any(part in {".git", ".venv", "venv", "__pycache__"} for part in source_path.parts):
                    continue
                try:
                    lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                line_no = request.new_citation
                if 1 <= line_no <= len(lines):
                    source_lines = lines
                    if any(token in lines[line_no - 1] for token in request.support_tokens):
                        break
                    source_lines = []

    new_verdict = answer_challenge(
        request.verdict,
        list(request.evidence_lines),
        request.new_citation,
        source_lines,
        request.support_tokens,
    )
    updated_lines = list(request.evidence_lines)
    if (new_verdict == request.verdict and request.new_citation is not None
            and request.new_citation not in updated_lines
            and 1 <= request.new_citation <= len(source_lines)
            and any(token in source_lines[request.new_citation - 1]
                    for token in request.support_tokens)):
        updated_lines.append(request.new_citation)
    return {"new_verdict": new_verdict, "evidence_lines": updated_lines}


@app.post("/api/verify")
def verify_matrix() -> dict[str, Any]:
    """Run each offline fixture through the deterministic CLI core."""
    verify_file = ROOT / "verify.py"
    spec = importlib.util.spec_from_file_location("pyreach_verify_matrix", verify_file)
    if not spec or not spec.loader:
        raise HTTPException(status_code=500, detail="Could not load fixture expectations.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    expected = module.EXPECTED
    advisory = SAMPLE_ADVISORY
    results = []
    with tempfile.TemporaryDirectory(prefix="pyreach-verify-api-") as temp_dir:
        for fixture, (expected_verdict, expected_exit) in expected.items():
            project_path = ROOT / "fixtures" / fixture
            report_path = Path(temp_dir) / f"{fixture}.json"
            command = [
                sys.executable, "-m", "pyreach.cli", "scan", str(project_path),
                "--advisory", str(advisory), "--out", str(report_path),
                "--cache-dir", str(CACHE_DIR), "--no-llm",
            ]
            try:
                completed = subprocess.run(
                    command, cwd=ROOT, capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=120,
                    env=os.environ.copy(),
                )
                report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
                got = report.get("results", [{}])[0].get("verdict", "no_report")
                passed = got == expected_verdict and completed.returncode == expected_exit
                results.append({
                    "fixture": fixture,
                    "expected": expected_verdict,
                    "got": got,
                    "exit_code": completed.returncode,
                    "passed": passed,
                })
            except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as exc:
                results.append({
                    "fixture": fixture,
                    "expected": expected_verdict,
                    "got": f"error: {exc}",
                    "exit_code": -1,
                    "passed": False,
                })
    return {
        "total": len(results),
        "passed": sum(1 for row in results if row["passed"]),
        "failed": sum(1 for row in results if not row["passed"]),
        "results": results,
    }
