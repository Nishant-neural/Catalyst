"""Phase 5 (part 1): Dynamic execution WITNESS, not proof — ChatGPT fix.

Renamed from "execution proof" on purpose. A harness that fails to
reach the vulnerable function does NOT prove it is unreachable:
branch conditions, configs, different inputs, background tasks, and
framework dispatch can all change the path. A witness only corroborates
a statically discovered path, for one run, with one input.

Isolation warning: a venv separates package installs, it does NOT
isolate the process from host permissions. Untrusted code in a venv
can still access resources available to that process. For a real
tool use a restricted container / sandbox with filesystem, network,
process and resource limits. For the hackathon, the witness is
OPTIONAL and never changes a verdict: a failed run keeps the static
verdict, it never downgrades reachable or uncertain to not_reachable.

sys.settrace is also thread-specific, so multi-threaded harnesses
need tracing configured for other threads too. Keep the witness
single-threaded in the base.

Phase 5 fixes over the base harness:
1. The trace filter kept only `entry_mod.*` and the vulnerable call,
   so a wrapper path lost its middle: main -> helpers.parse_config ->
   yaml.load came back as main -> yaml.load. Now the harness records
   the filename of every call and keeps calls whose file is under the
   project root (any project module), plus the vulnerable call.
2. Dotted entries work: `mod.Class.method` is resolved by walking
   attributes, and `<module>` entries (top-level code) are witnessed
   by importing the module only, no call.
3. SystemExit (click commands, sys.exit(main())) used to kill the
   harness before it printed, because only Exception was caught.
   Now BaseException is caught, so the trace is still reported.
4. Resource limits in the harness: RLIMIT_CPU and RLIMIT_AS on POSIX,
   so a runaway entry function cannot hang the scan or eat memory.
   The subprocess timeout (default 10s) is the outer bound.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


HARNESS = '''
import sys, json

def _tracer(frame, event, arg):
    if event == "call":
        name = frame.f_code.co_qualname
        mod = frame.f_globals.get("__name__", "")
        trace_log.append({"mod": mod, "name": name, "file": frame.f_code.co_filename})
    return _tracer

# Resource limits, POSIX only: a runaway entry cannot hang the scan.
try:
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
except Exception:
    pass

trace_log = []
entry_file = sys.argv[1]
entry_func = sys.argv[2]
root = sys.argv[3]
sys.path.insert(0, root)
sys.settrace(_tracer)
error = None
executed = False
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("entry_mod", entry_file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    executed = True
    if entry_func == "<module>":
        pass  # top-level code already ran on import; that is the witness
    else:
        # Dotted entry: mod.Class.method -> walk attributes.
        target = mod
        for part in entry_func.split("."):
            target = getattr(target, part, None)
            if target is None:
                break
        if target is None:
            error = "entry not found"
        else:
            try:
                target()
            except BaseException as e:
                # fn() may need args or call sys.exit(); the trace still counts.
                error = f"{type(e).__name__}: {e}"
finally:
    sys.settrace(None)
print(json.dumps({"executed": executed, "trace": trace_log, "error": error}))
'''


def run_execution_proof(project_root: str, entry_file: str, entry_func: str,
                        vulnerable: str, timeout: int = 10) -> dict:
    """Run harness in a subprocess. Returns proof dict."""
    root = str(Path(project_root).resolve())
    harness_src = HARNESS
    with tempfile.TemporaryDirectory() as td:
        harness = Path(td) / "harness.py"
        harness.write_text(harness_src, encoding="utf-8")
        try:
            r = subprocess.run(
                [sys.executable, str(harness), entry_file, entry_func, root],
                cwd=root, capture_output=True, text=True, timeout=timeout,
                env={"PATH": "/usr/bin:/bin", "PYTHONPATH": root, "PYTHONNOUSERSITE": "1"},
            )
        except subprocess.TimeoutExpired:
            return {"executed": False, "vulnerable_hit": False, "trace": [], "error": "timeout"}
        except Exception as e:
            return {"executed": False, "vulnerable_hit": False, "trace": [], "error": str(e)}
    # Last JSON line is the result
    for line in reversed(r.stdout.strip().splitlines()):
        try:
            data = json.loads(line)
            break
        except Exception:
            continue
    else:
        return {"executed": False, "vulnerable_hit": False, "trace": [], "error": r.stderr[-500:] if r.stderr else "no output"}
    raw_trace = data.get("trace", [])
    # Keep project code (any file under the project root) + the vulnerable
    # call. Stdlib / site-packages calls are dropped so report.json stays
    # small, but the middle of a wrapper path is kept this time.
    relevant = []
    for t in raw_trace:
        q = f"{t.get('mod', '')}.{t.get('name', '')}"
        f = t.get("file", "")
        if q == vulnerable or f.startswith(root):
            relevant.append(q)
    simple = vulnerable.split(".")[-1]
    hit = any(t.get("mod", "") + "." + t.get("name", "") == vulnerable for t in raw_trace)
    return {"executed": bool(data.get("executed")), "vulnerable_hit": hit,
            "trace": relevant[:50], "error": data.get("error")}
