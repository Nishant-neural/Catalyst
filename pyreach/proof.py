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
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


HARNESS = '''
import sys, json, trace

def _tracer(frame, event, arg):
    if event == "call":
        name = frame.f_code.co_qualname
        mod = frame.f_globals.get("__name__", "")
        trace_log.append(f"{mod}.{name}")
    return _tracer

trace_log = []
entry_file = sys.argv[1]
entry_func = sys.argv[2]
sys.path.insert(0, __ROOT__)
sys.settrace(_tracer)
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("entry_mod", entry_file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fn = getattr(mod, entry_func, None)
    if fn is None:
        # try nested: mod.Class.method is out of scope for the base harness
        print(json.dumps({"executed": False, "trace": trace_log, "error": "entry not found"}))
    else:
        try:
            fn()
        except Exception as e:
            pass  # harness may need args; trace still counts
        print(json.dumps({"executed": True, "trace": trace_log, "error": None}))
finally:
    sys.settrace(None)
'''


def run_execution_proof(project_root: str, entry_file: str, entry_func: str,
                        vulnerable: str, timeout: int = 10) -> dict:
    """Run harness in a subprocess. Returns proof dict."""
    root = str(Path(project_root).resolve())
    harness_src = HARNESS.replace("__ROOT__", repr(root))
    with tempfile.TemporaryDirectory() as td:
        harness = Path(td) / "harness.py"
        harness.write_text(harness_src, encoding="utf-8")
        try:
            r = subprocess.run(
                [sys.executable, str(harness), entry_file, entry_func],
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
    trace = data.get("trace", [])
    # Keep only relevant trace entries: project code + target package.
    # Full sys.settrace output is thousands of stdlib calls and would
    # bloat report.json to 200KB+. Filter here, not in the harness.
    simple = vulnerable.split(".")[-1]
    # Keep only project code + the exact vulnerable call, not every
    # stdlib / yaml submodule load. That keeps report.json small.
    relevant = [t for t in trace if t.startswith("entry_mod.") or t == vulnerable]
    hit = any(t == vulnerable for t in trace)
    return {"executed": bool(data.get("executed")), "vulnerable_hit": hit,
            "trace": relevant[:50], "error": data.get("error")}
