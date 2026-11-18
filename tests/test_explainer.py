"""Explainer tests: deterministic first, LLM only as a verified explainer.

No network, no key, no LLM call in any test — the LLM layer is tested
by monkeypatching pyreach.explainer.resolve_with_llm.
"""
import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pyreach.explainer as expl
from pyreach.advisory import Advisory, VulnerableFunction, load_advisories
from pyreach.callgraph import build_graph
from pyreach.entrypoints import find_entrypoints
from pyreach.reach import Result, analyze

BASE = Path(__file__).resolve().parent.parent
ADV = load_advisories(str(BASE / "examples" / "advisory-sample.json"))
ADV_DICT = {"id": "OSV-2020-1234", "package": "pyyaml", "fixed_version": "5.4"}


def _uncertain_yaml_load(fixture: str):
    """(result, graph, root, entries) for an uncertain yaml.load result."""
    root = BASE / "fixtures" / fixture
    graph = build_graph(root)
    entries, _ = find_entrypoints(root, graph)
    results = analyze(ADV, graph, entries)
    r = next(x for x in results
             if x.vulnerable_function == "yaml.load" and x.verdict == "uncertain")
    return r, graph, root, entries


def _good_answer(pack):
    """A valid LLM answer built from the pack's own evidence."""
    ev = pack["snippets"][0]
    return {
        "blocker": pack["blocker"],
        "what_blocks": "The dynamic name cannot be proved from the code.",
        "evidence": [{"file": ev["file"], "line": ev["line"],
                      "snippet": ev["snippet"].splitlines()[0]}],
        "what_would_resolve": [{"check": "log the resolved name",
                                "command": "rg -n load ."}],
        "does_not_know": ["what the name is at runtime"],
        "verdict": "uncertain",
    }


class TestVerifier(unittest.TestCase):
    def setUp(self):
        self.result, self.graph, self.root, self.entries = _uncertain_yaml_load(
            "app_getattr_config")
        _, self.pack = expl.deterministic_explanation(
            self.result, self.graph, self.root, self.entries, ADV_DICT)

    def test_rejects_invented_file(self):
        ans = _good_answer(self.pack)
        ans["evidence"] = [{"file": str(self.root / "nope.py"), "line": 1,
                            "snippet": "x = 1"}]
        ok, failures, _ = expl.verify_explainer_answer(ans, self.pack, self.root)
        self.assertFalse(ok)
        self.assertTrue(any("outside the evidence pack" in f for f in failures))

    def test_rejects_snippet_that_does_not_match_verbatim(self):
        ans = _good_answer(self.pack)
        ev = self.pack["snippets"][0]
        ans["evidence"] = [{"file": ev["file"], "line": ev["line"],
                            "snippet": "def totally_not_this_code(): pass"}]
        ok, failures, _ = expl.verify_explainer_answer(ans, self.pack, self.root)
        self.assertFalse(ok)
        self.assertTrue(any("verbatim" in f for f in failures))

    def test_rejects_verdict_upgrade_to_reachable(self):
        ans = _good_answer(self.pack)
        ans["verdict"] = "reachable"
        ok, failures, _ = expl.verify_explainer_answer(ans, self.pack, self.root)
        self.assertFalse(ok)
        self.assertTrue(any("uncertain" in f for f in failures))

    def test_rejects_verdict_upgrade_to_not_reachable(self):
        ans = _good_answer(self.pack)
        ans["verdict"] = "not_reachable"
        ok, _, _ = expl.verify_explainer_answer(ans, self.pack, self.root)
        self.assertFalse(ok)

    def test_rejects_wrong_blocker(self):
        ans = _good_answer(self.pack)
        ans["blocker"] = "ambiguous_name"  # pack blocker is dynamic_call
        ok, failures, _ = expl.verify_explainer_answer(ans, self.pack, self.root)
        self.assertFalse(ok)
        self.assertTrue(any("blocker" in f for f in failures))

    def test_rejects_missing_does_not_know(self):
        ans = _good_answer(self.pack)
        del ans["does_not_know"]
        ok, failures, _ = expl.verify_explainer_answer(ans, self.pack, self.root)
        self.assertFalse(ok)
        self.assertTrue(any("does_not_know" in f for f in failures))

    def test_rejects_empty_does_not_know(self):
        # An uncertain verdict always has something unknown; an empty
        # list is overconfidence, not an explanation.
        ans = _good_answer(self.pack)
        ans["does_not_know"] = []
        ok, failures, _ = expl.verify_explainer_answer(ans, self.pack, self.root)
        self.assertFalse(ok)
        self.assertTrue(any("does_not_know" in f for f in failures))

    def test_accepts_good_answer(self):
        ans = _good_answer(self.pack)
        ok, failures, cleaned = expl.verify_explainer_answer(ans, self.pack, self.root)
        self.assertTrue(ok, failures)
        self.assertEqual(cleaned["verdict"], "uncertain")


class TestEvidencePack(unittest.TestCase):
    def test_pack_respects_token_and_line_caps(self):
        result, graph, root, entries = _uncertain_yaml_load("app_getattr_config")
        _, pack = expl.deterministic_explanation(result, graph, root, entries, ADV_DICT)
        self.assertLessEqual(pack["tokens_estimate"], expl.TOKEN_CAP)
        for s in pack["snippets"]:
            self.assertLessEqual(len(s["snippet"].splitlines()), expl.SNIPPET_MAX_LINES)

    def test_pack_never_includes_files_outside_the_project(self):
        result, graph, root, entries = _uncertain_yaml_load("app_getattr_config")
        _, pack = expl.deterministic_explanation(result, graph, root, entries, ADV_DICT)
        for f in pack["files"]:
            self.assertTrue(str(Path(f).resolve()).startswith(str(root.resolve())),
                            f)
        self.assertNotIn("yaml/__init__.py", pack["files"])  # library source: not parsed

    def test_ripgrep_evidence_is_capped_and_grounded(self):
        root = BASE / "fixtures" / "app_getattr_config"
        matches = expl.ripgrep_evidence(root, "dynamic_call", "yaml.load")
        self.assertLessEqual(len(matches), expl.RG_MAX_MATCHES)
        self.assertGreaterEqual(len(matches), 1)  # getattr site must show up
        for m in matches:
            self.assertTrue(Path(m["file"]).exists())
            self.assertGreaterEqual(m["line"], 1)


class TestDeterministicTemplates(unittest.TestCase):
    def test_config_case_says_it_does_not_know(self):
        result, graph, root, entries = _uncertain_yaml_load("app_getattr_config")
        exp, _ = expl.deterministic_explanation(result, graph, root, entries, ADV_DICT)
        self.assertEqual(exp["blocker"], "dynamic_call")
        self.assertTrue(exp["does_not_know"])
        self.assertIn("config", exp["deterministic_explanation"].lower())
        self.assertIn("not known", exp["deterministic_explanation"].lower())
        self.assertIn(expl.FOOTER, exp["deterministic_explanation"])
        self.assertIsNone(exp["llm_explanation"])

    def test_library_not_parsed_template(self):
        root = BASE / "fixtures" / "app_safe"
        graph = build_graph(root)
        entries, _ = find_entrypoints(root, graph)
        r = Result(advisory_id="OSV-2020-1234", package="pyyaml",
                   vulnerable_function="yaml.constructor.construct_python_object_new",
                   verdict="uncertain", confidence="medium")
        exp, _ = expl.deterministic_explanation(r, graph, root, entries, ADV_DICT)
        self.assertEqual(exp["blocker"], "library_not_parsed")
        self.assertIn("pip show pyyaml", exp["discriminating_check"]["command"])
        self.assertIn("not parsed", exp["deterministic_explanation"])

    def test_ambiguous_template(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "helpers.py").write_text(
                "import yaml\n\ndef load(f):\n    return yaml.safe_load(f)\n")
            (root / "legacy.py").write_text(
                "import yaml\n\ndef load(f):\n    return yaml.load(f)\n")
            (root / "app.py").write_text(
                "def main():\n    return load('x')\n\n"
                "if __name__ == '__main__':\n    main()\n")
            graph = build_graph(root)
            entries, _ = find_entrypoints(root, graph)
            results = analyze(ADV, graph, entries)
            r = next(x for x in results
                     if x.vulnerable_function == "yaml.load"
                     and x.verdict == "uncertain")
            exp, _ = expl.deterministic_explanation(r, graph, root, entries, ADV_DICT)
            self.assertEqual(exp["blocker"], "ambiguous_name")
            self.assertIn("def load", exp["discriminating_check"]["command"])
            self.assertIn("helpers.py", exp["deterministic_explanation"])
            self.assertIn("legacy.py", exp["deterministic_explanation"])

    def test_unparsed_file_template(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "app.py").write_text(
                "import yaml\n\ndef main():\n    return yaml.safe_load('x: 1')\n\n"
                "if __name__ == '__main__':\n    main()\n")
            (root / "broken.py").write_text("def broken(:\n")
            low = [Advisory(id="TEST-1", package="pyyaml", fixed_version="5.4",
                            vulnerable_functions=[VulnerableFunction(
                                qualified="yaml.load", file="", confidence="low",
                                evidence="test")])]
            graph = build_graph(root)
            entries, _ = find_entrypoints(root, graph)
            results = analyze(low, graph, entries)
            r = next(x for x in results if x.verdict == "uncertain")
            exp, _ = expl.deterministic_explanation(
                r, graph, root, entries,
                {"id": "TEST-1", "package": "pyyaml", "fixed_version": "5.4"})
            self.assertEqual(exp["blocker"], "unparsed_file")
            self.assertIn("broken.py", exp["deterministic_explanation"])
            self.assertIn("py_compile", exp["discriminating_check"]["command"])

    def test_mixed_blocker_is_the_unresolved_site(self):
        # app_getattr_mixed has two dynamic sites: line 15 resolves to
        # the safe literal "safe_load", line 19 reads config and cannot
        # be resolved. The explanation must name the blocking one (19),
        # not the already-decided safe one (15).
        result, graph, root, entries = _uncertain_yaml_load("app_getattr_mixed")
        exp, pack = expl.deterministic_explanation(result, graph, root, entries, ADV_DICT)
        self.assertEqual(exp["blocker"], "dynamic_call")
        self.assertEqual(pack["blocked_edge"]["line"], 19)
        self.assertIn('config["func"]', exp["deterministic_explanation"])

    def test_discriminating_check_templates_exist_for_every_blocker(self):
        edge = {"file": str(BASE / "fixtures" / "app_getattr_config" / "app.py"),
                "line": 10}
        for blocker in expl.BLOCKERS:
            check = expl.discriminating_check(blocker, "yaml.load", "pyyaml",
                                              edge, BASE)
            self.assertTrue(check["check"])
            self.assertTrue(check["command"])
            # The verified file:line is in the check text for the
            # blockers that name a call site.
            if blocker in ("dynamic_call", "ambiguous_name"):
                self.assertIn("app.py:10", check["check"])


class TestLlmLayer(unittest.TestCase):
    def _explain(self, **kw):
        result, graph, root, entries = _uncertain_yaml_load("app_getattr_config")
        return expl.explain_result(result, graph, root, ADV_DICT, entries, **kw), result

    def test_llm_unavailable_falls_back_to_deterministic_only(self):
        real = expl.resolve_with_llm
        expl.resolve_with_llm = lambda *a, **k: None
        try:
            exp, result = self._explain(use_llm=True)
        finally:
            expl.resolve_with_llm = real
        self.assertIsNone(exp["llm_explanation"])
        self.assertFalse(exp["llm_rejected"])  # unavailable, not rejected
        self.assertIn(expl.FOOTER, exp["deterministic_explanation"])
        self.assertIn("[llm-explainer unavailable — deterministic result unchanged]",
                      expl.format_explanation(exp))
        self.assertEqual(result.verdict, "uncertain")  # verdict untouched

    def test_llm_rejected_answer_falls_back_to_deterministic_only(self):
        real = expl.resolve_with_llm
        bad = {"blocker": "dynamic_call", "what_blocks": "It is safe.",
               "evidence": [], "what_would_resolve": [],
               "does_not_know": ["nothing"], "verdict": "not_reachable"}
        expl.resolve_with_llm = lambda *a, **k: bad
        try:
            exp, _ = self._explain(use_llm=True)
        finally:
            expl.resolve_with_llm = real
        self.assertTrue(exp["llm_rejected"])
        self.assertTrue(exp["llm_failures"])
        self.assertIsNone(exp["llm_explanation"])
        self.assertIn("[llm-explainer unavailable — deterministic result unchanged]",
                      expl.format_explanation(exp))

    def test_llm_accepted_answer_is_labelled_and_kept(self):
        real = expl.resolve_with_llm
        result, graph, root, entries = _uncertain_yaml_load("app_getattr_config")
        _, pack = expl.deterministic_explanation(result, graph, root, entries, ADV_DICT)
        expl.resolve_with_llm = lambda *a, **k: _good_answer(pack)
        try:
            exp = expl.explain_result(result, graph, root, ADV_DICT, entries,
                                      use_llm=True)
        finally:
            expl.resolve_with_llm = real
        self.assertFalse(exp["llm_rejected"])
        self.assertIsNotNone(exp["llm_explanation"])
        self.assertIn("[llm-explainer]", exp["llm_explanation"])
        self.assertNotIn("not_reachable", exp["llm_explanation"])


if __name__ == "__main__":
    unittest.main()
