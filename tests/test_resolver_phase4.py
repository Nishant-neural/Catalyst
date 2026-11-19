"""Phase 4 tests: constant propagation (source order, branch union,
concat, var-to-var, importlib), the 10-rule verifier, and the
resolve_getattr_case helper (constants only — no network, no key)."""
import json
import os
import re
import unittest
from pathlib import Path
import sys
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyreach.advisory import load_advisories
from pyreach.callgraph import build_graph
from pyreach.entrypoints import find_entrypoints
from pyreach.reach import analyze
from pyreach.resolver import (
    CONFIDENCE_THRESHOLD,
    build_prompt,
    constant_propagate_getattr,
    resolve_getattr_case,
    verify_answer,
)

BASE = Path(__file__).resolve().parent.parent
ADV = load_advisories(str(BASE / "examples" / "advisory-sample.json"))
SYMS = {"yaml.load", "yaml.safe_load", "yaml.dump", "yaml.full_load"}


def _src(fixture: str) -> tuple[str, int]:
    # The real getattr CALL line, via AST — the fixture docstrings also
    # mention getattr, so a text search would pick the wrong line.
    import ast as _ast
    app = BASE / "fixtures" / fixture / "app.py"
    src = app.read_text(encoding="utf-8")
    tree = _ast.parse(src)
    line = next(n.lineno for n in _ast.walk(tree)
                if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Name)
                and n.func.id == "getattr")
    return src, line


class TestConstantPropagation(unittest.TestCase):
    def test_literal_load(self):
        src, line = _src("app_getattr_load")
        self.assertEqual(constant_propagate_getattr(src, line), ["load"])

    def test_loop_over_literals(self):
        src, line = _src("app_getattr_loop")
        self.assertEqual(sorted(constant_propagate_getattr(src, line) or []),
                         ["dump", "safe_load"])

    def test_config_is_unknown(self):
        src, line = _src("app_getattr_config")
        self.assertIsNone(constant_propagate_getattr(src, line))

    def test_branch_unions(self):
        src, line = _src("app_getattr_branch")
        self.assertEqual(sorted(constant_propagate_getattr(src, line) or []),
                         ["load", "safe_load"])

    def test_reassignment_last_wins(self):
        src, line = _src("app_getattr_reassign")
        self.assertEqual(constant_propagate_getattr(src, line), ["safe_load"])

    def test_concat(self):
        src, line = _src("app_getattr_concat")
        self.assertEqual(constant_propagate_getattr(src, line), ["safe_load"])

    def test_var_to_var(self):
        src = 'import yaml\ndef f():\n    a = "load"\n    b = a\n    return getattr(yaml, b)\n'
        self.assertEqual(constant_propagate_getattr(src, 5), ["load"])


class TestVerifier(unittest.TestCase):
    def _ans(self, **kw):
        a = {"can_reach": False, "possible_values": ["safe_load"],
             "vulnerable_hit": None, "reason": "only safe",
             "evidence_lines": [3], "confidence": 0.9}
        a.update(kw)
        return a

    def test_rule10_false_with_vulnerable_value_fails(self):
        # The old verifier did NOT check this half of rule 10.
        a = self._ans(possible_values=["load"])
        ok, failures = verify_answer(a, SYMS, 'import yaml\n\nname = "load"\n', "uncertain",
                                     vulnerable=["yaml.load"])
        self.assertFalse(ok)
        self.assertTrue(any("load" in f for f in failures))

    def test_can_reach_1_is_not_true(self):
        a = self._ans(can_reach=1, possible_values=["load"], vulnerable_hit="yaml.load")
        ok, _ = verify_answer(a, SYMS, 'import yaml\n\nname = "load"\n', "uncertain", vulnerable=["yaml.load"])
        self.assertFalse(ok)

    def test_no_evidence_line_fails(self):
        a = self._ans(evidence_lines=[])
        ok, _ = verify_answer(a, SYMS, 'import yaml\n\nname = "safe_load"\n', "uncertain", vulnerable=["yaml.load"])
        self.assertFalse(ok)

    def test_low_confidence_stays_uncertain(self):
        a = self._ans(confidence=0.5)
        ok, _ = verify_answer(a, SYMS, 'import yaml\n\nname = "safe_load"\n', "uncertain", vulnerable=["yaml.load"])
        self.assertFalse(ok)

    def test_never_downgrade_reachable(self):
        a = self._ans()
        ok, _ = verify_answer(a, SYMS, 'import yaml\n\nname = "safe_load"\n', "reachable", vulnerable=["yaml.load"])
        self.assertFalse(ok)

    def test_good_answer_passes(self):
        # Evidence line 3 must exist and contain "safe_load".
        src = 'import yaml\n\nname = "safe_load"\n'
        a = self._ans()
        ok, failures = verify_answer(a, SYMS, src, "uncertain",
                                     vulnerable=["yaml.load"])
        self.assertTrue(ok, failures)


class TestResolveCase(unittest.TestCase):
    def test_resolve_without_llm_or_key(self):
        # No key in env here, so the LLM step returns None; constants decide.
        src, line = _src("app_getattr_load")
        out = resolve_getattr_case(src, line, ["yaml.load"], SYMS)
        self.assertEqual(out["verdict"], "reachable")
        self.assertEqual(out["confidence"], "high")

    def test_config_stays_uncertain_without_key(self):
        # Hermetic: resolve_with_llm falls back to ./.env (resolver.py),
        # so a real .env in the working directory would make this a live
        # LLM call that can return a verified verdict. Patch the dotenv
        # loader at its source module and clear the environment, so
        # "without key" is actually true on any machine.
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("pyreach.dotenv.load_dotenv_file", return_value={}):
            src, line = _src("app_getattr_config")
            out = resolve_getattr_case(src, line, ["yaml.load"], SYMS)
        self.assertIsNone(out)


class TestPhase4FixturesEndToEnd(unittest.TestCase):
    def _scan(self, fixture):
        root = BASE / "fixtures" / fixture
        graph = build_graph(root)
        entries, _ = find_entrypoints(root, graph)
        return graph, analyze(ADV, graph, entries)

    def test_importlib_alias_is_reachable_statically(self):
        graph, results = self._scan("app_importlib")
        self.assertEqual(results[0].verdict, "reachable")
        self.assertIn("yaml.load", results[0].path[-1])


if __name__ == "__main__":
    unittest.main()


class TestPhase4Aggregation(unittest.TestCase):
    """19 Nov 2026 regression: one safe dynamic site must not clear a
    result when another site is unresolvable. The real PyYAML 5.3.1
    sdist had 51 dynamic triggers; a single getattr(..., "encoding")
    marked all 7 candidates not_reachable, including yaml.load."""

    def test_mixed_sites_stay_uncertain(self):
        from pyreach.cli import main as cli_main
        out = Path("/tmp") / "mixed-report.json"
        code = cli_main(["scan", str(BASE / "fixtures" / "app_getattr_mixed"),
                         "--advisory", str(BASE / "examples" / "advisory-sample.json"),
                         "--out", str(out), "--cache-dir", "/tmp/mixed-cache"])
        rep = json.loads(out.read_text())
        self.assertEqual(rep["results"][0]["verdict"], "uncertain")
        self.assertEqual(code, 0)
        self.assertIn("1/2", rep["results"][0]["reason"])


class TestPromptContract(unittest.TestCase):
    """19 Nov 2026 regression, live MkDocs run: the model answered 3
    Phase 4 calls with can_reach false + empty possible_values (one
    also confidence 0.0), and the verifier correctly rejected all 3.
    Two prompt defects fed that: the JSON example showed
    "confidence": 0.0, which the model copied verbatim, and nothing in
    the prompt said a false answer needs a non-empty possible_values
    list — rule 10 demanded something the prompt never asked for."""

    def _prompt(self):
        return build_prompt("x = getattr(mod, name)", ["yaml.load"],
                            ["load"], ["yaml.load"], "app.py", 1)

    def test_example_confidence_meets_threshold(self):
        m = re.search(r'"confidence":\s*([0-9.]+)', self._prompt())
        self.assertIsNotNone(m, "prompt must show an example confidence")
        self.assertGreaterEqual(float(m.group(1)), CONFIDENCE_THRESHOLD)

    def test_false_answer_must_list_values(self):
        self.assertIn("possible_values MUST list every value",
                      self._prompt())

    def test_rejected_shape_still_rejected(self):
        # The exact answers from the live run must still fail: false
        # with no values, and 0.0 confidence. The prompt fix must not
        # have weakened the verifier — only the prompt changed.
        ok, failures = verify_answer(
            {"can_reach": False, "possible_values": [],
             "vulnerable_hit": None, "reason": "x",
             "evidence_lines": [1], "confidence": 0.0},
            SYMS, "x = getattr(mod, name)\n", "uncertain",
            vulnerable=["yaml.load"])
        self.assertFalse(ok)
        self.assertIn("can_reach false needs non-empty possible_values",
                      failures)
        self.assertTrue(any("below threshold" in f for f in failures))
