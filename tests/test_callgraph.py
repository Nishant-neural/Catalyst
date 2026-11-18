import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pyreach.callgraph import build_graph
from pyreach.entrypoints import find_entrypoints
from pyreach.reach import analyze
from pyreach.advisory import load_advisories

ROOT = Path(__file__).resolve().parents[1]


class TestCallGraphBase(unittest.TestCase):
    # Plain functions, not TestCase methods, so `python -m unittest`
    # skipped these 4 tests while pytest ran them. Fixed 19 Nov 2026.
    def _results(self, fixture):
        g = build_graph(ROOT / "fixtures" / fixture)
        entries, _ = find_entrypoints(ROOT / "fixtures" / fixture, g)
        advs = load_advisories(str(ROOT / "examples" / "advisory-sample.json"))
        return analyze(advs, g, entries)

    def test_vuln_is_reachable(self):
        self.assertEqual(self._results("app_vuln")[0].verdict, "reachable")

    def test_safe_is_not_reachable(self):
        self.assertEqual(self._results("app_safe")[0].verdict, "not_reachable")

    def test_dead_code_is_not_reachable(self):
        self.assertEqual(self._results("app_dead")[0].verdict, "not_reachable")

    def test_getattr_is_uncertain(self):
        self.assertEqual(self._results("app_getattr")[0].verdict, "uncertain")


if __name__ == "__main__":
    unittest.main()
