"""Tests for Phase 7 scan-all (pyreach scan-all).

No network in any test: the offline path reads advisory files from
--advisory-dir, and the live path stubs analyse_advisory_live.
installed_version is patched to None so the version-unknown skip does
not depend on what happens to be installed on the machine running the
tests.
"""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pyreach.cli as cli_mod

BASE = Path(__file__).resolve().parent.parent
SAMPLE = json.loads((BASE / "examples" / "advisory-sample.json").read_text())

APP_PY = '''"""Scan-all fixture project: main() -> load_config() -> yaml.load()."""
import yaml


def load_config(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.Loader)


def main():
    print(load_config("config.yaml"))


if __name__ == "__main__":
    main()
'''


def _make_project(tmp: Path) -> tuple[Path, Path]:
    proj = tmp / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(APP_PY, encoding="utf-8")
    (proj / "config.yaml").write_text("a: 1\n", encoding="utf-8")
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = [\n'
        '  "PyYAML==5.3.1",\n  "requests==2.31.0",\n  "pyreach-skip-demo>=1.0",\n]\n',
        encoding="utf-8")
    adv_dir = tmp / "advisories"
    adv_dir.mkdir()
    (adv_dir / "pyyaml.json").write_text(json.dumps(SAMPLE), encoding="utf-8")
    return proj, adv_dir


class TestScanAllOffline(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_mod.main(argv)
        return code, buf.getvalue()

    def test_offline_scan_all(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            proj, adv_dir = _make_project(tmp)
            report = tmp / "report.json"
            with mock.patch("pyreach.deps.installed_version", return_value=None):
                code, out = self._run([
                    "scan-all", str(proj),
                    "--advisory-dir", str(adv_dir),
                    "--no-llm", "--no-html",
                    "--out", str(report), "--vex", str(tmp / "openvex.json"),
                    "--cache-dir", str(tmp / "cache")])
            self.assertEqual(code, 2, out)  # yaml.load reachable
            data = json.loads(report.read_text())
            self.assertEqual(data.get("mode"), "scan-all")
            by_name = {p["name"]: p for p in data["packages"]}
            self.assertEqual(by_name["PyYAML"]["status"], "scanned")
            self.assertEqual(by_name["PyYAML"]["version"], "5.3.1")
            self.assertEqual(by_name["PyYAML"]["version_source"], "pyproject")
            self.assertEqual(by_name["PyYAML"]["advisories"], 1)
            self.assertEqual(by_name["PyYAML"]["results"]["reachable"], 1)
            # No advisory file supplied: checked as not-checked, never
            # silently treated as clean.
            self.assertEqual(by_name["requests"]["status"], "not-checked")
            self.assertIn("not checked", by_name["requests"]["reason"])
            # Range-only, nothing installed, no lockfile: skipped, listed.
            # (pyreach-skip-demo is not a real package, so no machine can
            # resolve it via the installed environment — the skip is
            # deterministic, not an accident of what is installed.)
            self.assertEqual(by_name["pyreach-skip-demo"]["status"], "skipped")
            self.assertIsNone(by_name["pyreach-skip-demo"]["version"])
            self.assertIn("no exact version", by_name["pyreach-skip-demo"]["reason"])
            # The aggregated results carry the package, and the verdict
            # is the same call path as the single-package scan.
            yaml_load = [r for r in data["results"]
                         if r["vulnerable_function"] == "yaml.load"]
            self.assertEqual(len(yaml_load), 1)
            self.assertEqual(yaml_load[0]["verdict"], "reachable")
            self.assertEqual(yaml_load[0]["package"], "pyyaml")
            self.assertEqual(yaml_load[0]["path"],
                             ["app.main", "app.load_config", "yaml.load"])
            self.assertIn("scan-all packages:", out)

    def test_only_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            proj, adv_dir = _make_project(tmp)
            report = tmp / "report.json"
            with mock.patch("pyreach.deps.installed_version", return_value=None):
                code, _ = self._run([
                    "scan-all", str(proj),
                    "--advisory-dir", str(adv_dir), "--only", "pyyaml",
                    "--no-llm", "--no-html",
                    "--out", str(report), "--vex", str(tmp / "openvex.json"),
                    "--cache-dir", str(tmp / "cache")])
            self.assertEqual(code, 2)
            data = json.loads(report.read_text())
            self.assertEqual([p["name"] for p in data["packages"]], ["PyYAML"])

    def test_live_path_uses_analyse_advisory_live(self):
        # The live fetch is stubbed, but the dicts -> temp file ->
        # load_advisories conversion is the real code.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            proj, _ = _make_project(tmp)
            report = tmp / "report.json"
            with mock.patch("pyreach.deps.installed_version", return_value=None), \
                    mock.patch.object(cli_mod, "analyse_advisory_live",
                                      side_effect=lambda pkg, ver, cache=None:
                                      SAMPLE if pkg == "PyYAML" else []) as fetch:
                code, _ = self._run([
                    "scan-all", str(proj),
                    "--no-llm", "--no-html",
                    "--out", str(report), "--vex", str(tmp / "openvex.json"),
                    "--cache-dir", str(tmp / "cache")])
            self.assertEqual(code, 2)
            called = {(c.args[0], c.args[1]) for c in fetch.call_args_list}
            self.assertEqual(called, {("PyYAML", "5.3.1"), ("requests", "2.31.0")})
            data = json.loads(report.read_text())
            by_name = {p["name"]: p for p in data["packages"]}
            self.assertEqual(by_name["PyYAML"]["status"], "scanned")
            self.assertEqual(by_name["requests"]["status"], "no-advisories")

    def test_fetch_failure_is_visible_not_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            proj, _ = _make_project(tmp)
            report = tmp / "report.json"

            def _fetch(pkg, ver, cache=None):
                if pkg == "PyYAML":
                    return SAMPLE
                raise RuntimeError("OSV is down")

            with mock.patch("pyreach.deps.installed_version", return_value=None), \
                    mock.patch.object(cli_mod, "analyse_advisory_live",
                                      side_effect=_fetch):
                code, out = self._run([
                    "scan-all", str(proj),
                    "--no-llm", "--no-html",
                    "--out", str(report), "--vex", str(tmp / "openvex.json"),
                    "--cache-dir", str(tmp / "cache")])
            # PyYAML still scanned and reachable; the failed package is
            # reported, not dropped, and the scan does not crash.
            self.assertEqual(code, 2)
            data = json.loads(report.read_text())
            by_name = {p["name"]: p for p in data["packages"]}
            self.assertEqual(by_name["requests"]["status"], "fetch-failed")
            self.assertIn("OSV is down", by_name["requests"]["reason"])
            self.assertIn("fetch failed for requests", out)

    def test_no_dependencies_is_an_empty_report_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            proj = tmp / "proj"
            proj.mkdir()
            (proj / "app.py").write_text("def main():\n    pass\n", encoding="utf-8")
            report = tmp / "report.json"
            code, out = self._run([
                "scan-all", str(proj),
                "--no-llm", "--no-html",
                "--out", str(report), "--vex", str(tmp / "openvex.json"),
                "--cache-dir", str(tmp / "cache")])
            self.assertEqual(code, 0)
            data = json.loads(report.read_text())
            self.assertEqual(data["packages"], [])
            self.assertEqual(data["results"], [])
            self.assertIn("no advisories", out)


if __name__ == "__main__":
    unittest.main()
