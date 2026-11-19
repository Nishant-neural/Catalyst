"""Tests for the quiet terminal + readable HTML report (19 Nov 2026).

The bug: a MkDocs scan printed ~240KB to the terminal — the whole
entry-evidence dict (1,194 entries) on one line, the full sorted
entry-point list, and the full text of every explanation. The terminal
is now a summary only; full detail is in report.json and the .html
file written next to it.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADV = str(ROOT / "examples" / "advisory-sample.json")


def run_cli(args, cwd=ROOT):
    return subprocess.run([sys.executable, "-m", "pyreach.cli", *args],
                          cwd=cwd, capture_output=True, text=True, timeout=120)


class TestQuietTerminal(unittest.TestCase):
    def test_quiet_scan_short_lines_no_dump(self):
        """Default scan: no line over ~500 chars, no evidence dict dump."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            r = run_cli(["scan", "fixtures/app_getattr_config",
                         "--advisory", ADV, "--explain", "--no-llm",
                         "--out", str(out), "--cache-dir", str(Path(tmp) / "c")])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            lines = r.stdout.splitlines()
            longest = max((len(ln) for ln in lines), default=0)
            self.assertLess(longest, 500, f"longest line {longest}: "
                            + max(lines, key=len)[:200])
            self.assertNotIn("entry evidence: {", r.stdout)
            self.assertIn("entry points (", r.stdout)
            self.assertIn("entry evidence: 2 entries (see report.json)",
                          r.stdout)

    def test_quiet_explain_is_one_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            r = run_cli(["scan", "fixtures/app_getattr_config",
                         "--advisory", ADV, "--explain", "--no-llm",
                         "--out", str(out), "--cache-dir", str(Path(tmp) / "c")])
            one_liners = [ln for ln in r.stdout.splitlines()
                          if ln.startswith("explain [uncertain]")]
            self.assertEqual(len(one_liners), 1)
            self.assertIn("blocker dynamic_call", one_liners[0])
            self.assertIn("blocked at", one_liners[0])
            self.assertIn("app.py:10", one_liners[0])
            # Full explanation text stays OUT of the terminal.
            self.assertNotIn("The verdict remains UNCERTAIN", r.stdout)
            self.assertIn("readable report:", r.stdout)

    def test_verbose_restores_full_dump(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            r = run_cli(["scan", "fixtures/app_getattr_config",
                         "--advisory", ADV, "--explain", "--no-llm",
                         "--verbose",
                         "--out", str(out), "--cache-dir", str(Path(tmp) / "c")])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("entry evidence: {", r.stdout)
            self.assertIn("app.<module>", r.stdout)
            self.assertIn("The verdict remains UNCERTAIN", r.stdout)

    def test_no_html_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            r = run_cli(["scan", "fixtures/app_getattr_config",
                         "--advisory", ADV, "--explain", "--no-llm",
                         "--no-html",
                         "--out", str(out), "--cache-dir", str(Path(tmp) / "c")])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertFalse(Path(tmp, "r.html").exists())
            self.assertIsNone(json.loads(out.read_text())["html_report"])
            self.assertNotIn("readable report:", r.stdout)


class TestHtmlReport(unittest.TestCase):
    def test_html_written_next_to_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            r = run_cli(["scan", "fixtures/app_getattr_config",
                         "--advisory", ADV, "--explain", "--no-llm",
                         "--out", str(out), "--cache-dir", str(Path(tmp) / "c")])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            html_path = Path(tmp) / "r.html"
            self.assertTrue(html_path.exists())
            rep = json.loads(out.read_text())
            self.assertEqual(rep["html_report"], "r.html")
            page = html_path.read_text(encoding="utf-8")
            self.assertIn("yaml.load", page)
            self.assertIn("dynamic_call", page)
            self.assertIn("The verdict remains UNCERTAIN", page)
            self.assertIn("app.py:10", page)
            self.assertIn("verdicts are deterministic", page)

    def test_html_escapes_scanned_content(self):
        from pyreach.html_report import render_html
        report = {
            "project": "evil<script>alert(1)</script>",
            "advisories": [{"id": "OSV-1", "package": "p",
                            "fixed_version": "2", "fix_commit": "",
                            "candidates": 1}],
            "completeness_ledger": {"project_source": "1/1 parsed"},
            "uncertain_rate": 1.0,
            "results": [{"advisory_id": "OSV-1", "package": "p",
                         "vulnerable_function": "yaml.load",
                         "verdict": "uncertain", "confidence": "low",
                         "path": ["a<script>", "yaml.load"],
                         "reason": "bad <script>alert(1)</script> reason"}],
            "proofs": {},
            "explanations": [{
                "vulnerable_function": "yaml.load", "advisory_id": "OSV-1",
                "blocker": "dynamic_call",
                "deterministic_explanation":
                    "[deterministic] Verdict: UNCERTAIN — yaml.load.\n"
                    "[deterministic] Blocked at evil<script>.py:3 (getattr).\n"
                    "[deterministic] This explanation is limited. "
                    "The verdict remains UNCERTAIN.",
                "llm_explanation": None, "llm_rejected": False,
                "discriminating_check": {"check": "check it",
                                         "command": "rg <script>"},
                "does_not_know": ["what <script> does"],
                "evidence_pack_tokens": 10}],
        }
        page = render_html(report)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_report_command_from_existing_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            r = run_cli(["scan", "fixtures/app_getattr_config",
                         "--advisory", ADV, "--no-llm",
                         "--out", str(out), "--cache-dir", str(Path(tmp) / "c")])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            html_path = Path(tmp) / "regen.html"
            r2 = run_cli(["report", "--report", str(out),
                          "--out", str(html_path)])
            self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
            self.assertTrue(html_path.exists())
            self.assertIn("yaml.load", html_path.read_text(encoding="utf-8"))
            # Default --out: <report>.html next to the report.
            r3 = run_cli(["report", "--report", str(out)])
            self.assertEqual(r3.returncode, 0, r3.stdout + r3.stderr)
            self.assertTrue(Path(tmp, "r.html").exists())

    def test_report_command_missing_file_fails_cleanly(self):
        r = run_cli(["report", "--report", "/tmp/does-not-exist-pyreach.json"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("error", r.stderr)
        self.assertNotIn("Traceback", r.stderr)


if __name__ == "__main__":
    unittest.main()
