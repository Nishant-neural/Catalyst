"""Phase 1/2 fix: library-internal candidates must never be a false
not_reachable. If yaml.load is reachable, FullConstructor.construct_*
is reachable too (the library calls it internally), even though the
project never calls it directly. If yaml.load is NOT reachable, the
internal stays uncertain, never not_reachable, because the dependency
source was not parsed."""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyreach.advisory import Advisory, VulnerableFunction
from pyreach.callgraph import build_graph
from pyreach.entrypoints import find_entrypoints
from pyreach.reach import analyze


def _advisory():
    return Advisory(id="GHSA-8q59-q68h-6hv4", package="pyyaml", vulnerable_functions=[
        VulnerableFunction("yaml.load", "yaml/__init__.py", "medium", "test"),
        VulnerableFunction("FullConstructor.construct_python_object_new", "yaml/constructor.py", "medium", "diff"),
        VulnerableFunction("yaml.full_load", "yaml/__init__.py", "medium", "text"),
    ])


class TestLibraryInternals(unittest.TestCase):
    def test_internal_reachable_via_yaml_load(self):
        root = Path(__file__).resolve().parent.parent / "fixtures" / "app_vuln"
        graph = build_graph(root)
        entries, _ = find_entrypoints(root, graph)
        results = {r.vulnerable_function: r for r in analyze([_advisory()], graph, entries)}
        self.assertEqual(results["yaml.load"].verdict, "reachable")
        self.assertEqual(results["FullConstructor.construct_python_object_new"].verdict, "reachable")
        self.assertIn("yaml.load", results["FullConstructor.construct_python_object_new"].reason)

    def test_internal_uncertain_when_loader_not_reachable(self):
        root = Path(__file__).resolve().parent.parent / "fixtures" / "app_safe"
        graph = build_graph(root)
        entries, _ = find_entrypoints(root, graph)
        results = {r.vulnerable_function: r for r in analyze([_advisory()], graph, entries)}
        # Phase 12: yaml.load is uncertain without --with-deps — the
        # app calls yaml.safe_load() and yaml source is unparsed.
        self.assertEqual(results["yaml.load"].verdict, "uncertain")
        # Internal must NOT be claimed not_reachable — dependency not parsed.
        self.assertEqual(results["FullConstructor.construct_python_object_new"].verdict, "uncertain")
        # Phase 12: same dep-entry rule as yaml.load above.
        self.assertEqual(results["yaml.full_load"].verdict, "uncertain")


def _same_name_advisory(confidence):
    # Mirrors the Werkzeug form-parse advisory's text candidate
    # Request.max_content_length (medium) and Flask's own property of
    # the same name (19 Nov 2026).
    return Advisory(id="GHSA-q34m-jh98-gwm2", package="werkzeug", vulnerable_functions=[
        VulnerableFunction("Request.max_content_length", "werkzeug/wrappers.py", confidence, "advisory text"),
    ])


class TestSingleNodeMatch(unittest.TestCase):
    def test_medium_text_candidate_matching_public_name_is_uncertain(self):
        root = Path(__file__).resolve().parent.parent / "fixtures" / "app_same_name"
        graph = build_graph(root)
        entries, _ = find_entrypoints(root, graph)
        self.assertIn("pkg.wrappers.Request.max_content_length", entries)
        results = analyze([_same_name_advisory("medium")], graph, entries)
        self.assertEqual(results[0].verdict, "uncertain")
        self.assertIn("single-node", results[0].reason)

    def test_high_confidence_candidate_matching_public_name_is_reachable(self):
        root = Path(__file__).resolve().parent.parent / "fixtures" / "app_same_name"
        graph = build_graph(root)
        entries, _ = find_entrypoints(root, graph)
        results = analyze([_same_name_advisory("high")], graph, entries)
        self.assertEqual(results[0].verdict, "reachable")
        self.assertEqual(results[0].path, ["pkg.wrappers.Request.max_content_length"])


class TestInitCall(unittest.TestCase):
    def test_class_init_candidate_reachable_via_construction(self):
        # 19 Nov 2026: a candidate ending in .__init__ is invoked by
        # constructing the class (Retry(...) calls Retry.__init__).
        # The call graph records constructor calls as calls to the
        # class, so the candidate must match the class node.
        root = Path(__file__).resolve().parent.parent / "fixtures" / "app_init_call"
        graph = build_graph(root)
        entries, _ = find_entrypoints(root, graph)
        adv = Advisory(id="GHSA-34jh-p97f-mpxf", package="urllib3", vulnerable_functions=[
            VulnerableFunction("urllib3.util.retry.Retry.__init__", "urllib3/util/retry.py", "high", "fix commit"),
        ])
        results = analyze([adv], graph, entries)
        self.assertEqual(results[0].verdict, "reachable")
        self.assertEqual(results[0].path, ["app.main", "app.make_session", "urllib3.util.retry.Retry"])

    def test_relative_import_and_constructor_chain(self):
        # 19 Nov 2026: `from .helpers import Adapter` in a src-layout
        # package must resolve to pkg.helpers.Adapter (relative imports
        # were recorded unresolved), and calling the class must reach
        # its __init__ (class -> __init__ edge), which constructs Retry.
        root = Path(__file__).resolve().parent.parent / "fixtures" / "app_rel_import"
        graph = build_graph(root)
        entries, _ = find_entrypoints(root, graph)
        adv = Advisory(id="GHSA-34jh-p97f-mpxf", package="urllib3", vulnerable_functions=[
            VulnerableFunction("urllib3.util.retry.Retry.__init__", "urllib3/util/retry.py", "high", "fix commit"),
        ])
        results = analyze([adv], graph, entries)
        self.assertEqual(results[0].verdict, "reachable")
        self.assertEqual(results[0].path, [
            "pkg.main.main", "pkg.helpers.Adapter",
            "pkg.helpers.Adapter.__init__", "urllib3.util.retry.Retry",
        ])


if __name__ == "__main__":
    unittest.main()
