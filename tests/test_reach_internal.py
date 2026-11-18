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
        self.assertEqual(results["yaml.load"].verdict, "not_reachable")
        # Internal must NOT be claimed not_reachable — dependency not parsed.
        self.assertEqual(results["FullConstructor.construct_python_object_new"].verdict, "uncertain")
        self.assertEqual(results["yaml.full_load"].verdict, "not_reachable")


if __name__ == "__main__":
    unittest.main()
