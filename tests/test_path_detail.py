"""ChatGPT fix A (19 Nov 2026): every call-path step carries file + line.

Lines are definition lines (FuncInfo.start): a judge opens file:line and
sees the function. Call-site lines are NOT claimed: resolved edges do
not store which line called them. A step the graph does not know (e.g.
yaml.load with the dependency unparsed) is file "external", line null.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADV = str(ROOT / "examples" / "advisory-sample.json")

sys.path.insert(0, str(ROOT))

from pyreach.callgraph import FuncInfo, Graph
from pyreach.cli import _path_detail
from pyreach.html_report import write_html_report


def run_cli(args, cwd=ROOT):
    return subprocess.run([sys.executable, "-m", "pyreach.cli", *args],
                          cwd=cwd, capture_output=True, text=True, timeout=120)


def _scan_app_vuln(tmp):
    out = Path(tmp) / "r.json"
    r = run_cli(["scan", "fixtures/app_vuln", "--advisory", ADV,
                 "--no-llm", "--no-html",
                 "--out", str(out), "--cache-dir", str(Path(tmp) / "c")])
    assert r.returncode == 2, r.stdout + r.stderr
    return json.loads(out.read_text(encoding="utf-8")), out


class TestPathDetail(unittest.TestCase):
    def test_app_vuln_path_detail(self):
        """app.main (app.py:15) -> app.load_config (app.py:10) ->
        yaml.load (external: dependency unparsed, never invented)."""
        with tempfile.TemporaryDirectory() as tmp:
            report, _ = _scan_app_vuln(tmp)
            res = report["results"][0]
            self.assertEqual(res["path"],
                             ["app.main", "app.load_config", "yaml.load"])
            self.assertEqual(res["path_detail"], [
                {"function": "app.main", "file": "app.py", "line": 15},
                {"function": "app.load_config", "file": "app.py", "line": 10},
                {"function": "yaml.load", "file": "external", "line": None},
            ])

    def test_helper_relative_paths_and_external(self):
        graph = Graph()
        graph.functions["pkg.mod.fn"] = FuncInfo(
            qualified="pkg.mod.fn", file="/proj/pkg/mod.py",
            start=42, end=50, name="fn")
        graph.functions["yaml.load"] = FuncInfo(
            qualified="yaml.load", file="/cache/deps/pyyaml-5.3.1/yaml/__init__.py",
            start=150, end=160, name="load")
        got = _path_detail(graph, Path("/proj"), Path("/cache"),
                           ["pkg.mod.fn", "yaml.load", "missing.fn"])
        self.assertEqual(got, [
            {"function": "pkg.mod.fn", "file": "pkg/mod.py", "line": 42},
            {"function": "yaml.load",
             "file": "deps/pyyaml-5.3.1/yaml/__init__.py", "line": 150},
            {"function": "missing.fn", "file": "external", "line": None},
        ])

    def test_html_report_shows_file_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            report, out = _scan_app_vuln(tmp)
            html_path = write_html_report(report, out)
            html = html_path.read_text(encoding="utf-8")
            self.assertIn("app.main (app.py:15)", html)
            self.assertIn("app.load_config (app.py:10)", html)
            self.assertIn("yaml.load (external:?)", html)

    def test_html_report_old_report_fallback(self):
        """A report written before path_detail existed still renders
        with bare function names instead of crashing."""
        report = {
            "project": "demo", "advisories": [], "entry_note": "",
            "entry_evidence": {}, "llm_enabled": False,
            "completeness_ledger": {}, "uncertain_rate": 0.0,
            "cache": {"hits": 0, "misses": 0},
            "results": [{"advisory_id": "OSV-1", "package": "pyyaml",
                         "vulnerable_function": "yaml.load",
                         "verdict": "reachable", "confidence": "high",
                         "path": ["app.main", "app.load_config", "yaml.load"],
                         "reason": "x"}],
            "proofs": {}, "explanations": [], "pr_comments": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            out.write_text(json.dumps(report), encoding="utf-8")
            html = write_html_report(report, out).read_text(encoding="utf-8")
            self.assertIn("app.main -&gt; app.load_config -&gt; yaml.load", html)


if __name__ == "__main__":
    unittest.main()
