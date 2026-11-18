"""Phase 5 tests: execution witness (wrapper path kept, method/<module>
entries, SystemExit/args handled, verdict never downgraded) and the
concede-or-cite debate rule."""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyreach.debate import answer_challenge
from pyreach.proof import run_execution_proof

BASE = Path(__file__).resolve().parent.parent


class TestWitness(unittest.TestCase):
    def test_app_vuln_hit(self):
        root = BASE / "fixtures" / "app_vuln"
        p = run_execution_proof(str(root), str(root / "app.py"), "main", "yaml.load")
        self.assertTrue(p["executed"])
        self.assertTrue(p["vulnerable_hit"])
        self.assertIn("entry_mod.main", p["trace"])
        self.assertIn("yaml.load", p["trace"])

    def test_wrapper_middle_kept(self):
        # Old harness dropped helpers.parse_config from the trace.
        root = BASE / "fixtures" / "app_witness_wrapper"
        p = run_execution_proof(str(root), str(root / "app.py"), "main", "yaml.load")
        self.assertTrue(p["vulnerable_hit"])
        self.assertTrue(any("parse_config" in t for t in p["trace"]),
                        f"wrapper middle missing from trace: {p['trace']}")

    def test_module_entry_import_only(self):
        # app_top calls yaml.load at import time; <module> means import only.
        root = BASE / "fixtures" / "app_top"
        p = run_execution_proof(str(root), str(root / "app.py"), "<module>", "yaml.load")
        self.assertTrue(p["executed"])
        self.assertTrue(p["vulnerable_hit"])

    def test_entry_needing_args_keeps_static_verdict(self):
        # main(args) raises TypeError with no args: witness misses, but the
        # proof dict must say so honestly instead of crashing.
        root = BASE / "fixtures" / "app_proof_args"
        p = run_execution_proof(str(root), str(root / "app.py"), "main", "yaml.load")
        self.assertTrue(p["executed"])
        self.assertFalse(p["vulnerable_hit"])
        self.assertIsNotNone(p["error"])
        self.assertIn("TypeError", p["error"])


class TestDebate(unittest.TestCase):
    SRC = ['import yaml\n', 'def f():\n', '    return yaml.load(open("c.yaml"))\n']

    def test_no_citation_concedes(self):
        self.assertEqual(answer_challenge("reachable", [], None, self.SRC), "uncertain")

    def test_out_of_range_citation_concedes(self):
        self.assertEqual(answer_challenge("reachable", [], 99, self.SRC), "uncertain")

    def test_unrelated_line_concedes(self):
        # Line 1 has no support token: citing it does not defend anything.
        self.assertEqual(answer_challenge("reachable", [], 1, self.SRC,
                                          support_tokens=["yaml.load"]), "uncertain")

    def test_supporting_line_keeps_verdict(self):
        ev = []
        self.assertEqual(answer_challenge("reachable", ev, 3, self.SRC,
                                          support_tokens=["yaml.load"]), "reachable")
        self.assertEqual(ev, [3])

    def test_same_line_twice_concedes(self):
        ev = [3]
        self.assertEqual(answer_challenge("reachable", ev, 3, self.SRC,
                                          support_tokens=["yaml.load"]), "uncertain")


if __name__ == "__main__":
    unittest.main()
