"""Phase 2 hardening tests: nested functions, top-level code, self.,
star imports, assignment aliases, and no external-node pollution.
Each test scans a fixture with the sample advisory (yaml.load, high)
and checks the verdict, plus the graph shape where it matters."""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyreach.advisory import load_advisories
from pyreach.callgraph import build_graph
from pyreach.entrypoints import find_entrypoints
from pyreach.reach import analyze

BASE = Path(__file__).resolve().parent.parent
ADV = load_advisories(str(BASE / "examples" / "advisory-sample.json"))


def scan(fixture: str):
    root = BASE / "fixtures" / fixture
    graph = build_graph(root)
    entries, _ = find_entrypoints(root, graph)
    results = analyze(ADV, graph, entries)
    return graph, entries, {r.vulnerable_function: r for r in results}


class TestPhase2Fixtures(unittest.TestCase):
    def test_top_level_call_is_reachable(self):
        graph, entries, res = scan("app_top")
        self.assertIn("app.<module>", entries)
        self.assertEqual(res["yaml.load"].verdict, "reachable")
        self.assertIn("app.<module>", res["yaml.load"].path[0])

    def test_nested_function_call_after_def(self):
        graph, entries, res = scan("app_nested")
        self.assertEqual(res["yaml.load"].verdict, "reachable")
        # Path must go through main, not be a bare module edge.
        self.assertIn("app.main", res["yaml.load"].path)

    def test_self_resolves_to_enclosing_class(self):
        graph, entries, res = scan("app_method")
        self.assertEqual(res["yaml.load"].verdict, "reachable")
        self.assertIn("app.Loader.load_config", res["yaml.load"].path)
        self.assertNotIn("app.SafeLoader.load_config", res["yaml.load"].path)
        # No ambiguous edge for the self.helper call.
        self.assertFalse(graph.ambiguous)

    def test_star_import_picks_star_module(self):
        graph, entries, res = scan("app_star")
        self.assertEqual(res["yaml.load"].verdict, "reachable")
        self.assertIn("helpers.parse_config", res["yaml.load"].path)
        self.assertFalse(graph.ambiguous)

    def test_assignment_alias_is_reachable(self):
        graph, entries, res = scan("app_alias")
        self.assertEqual(res["yaml.load"].verdict, "reachable")

    def test_dotted_library_call_beats_same_simple_name(self):
        # Regression, 19 Nov 2026 (real MkDocs scan): yaml.load was
        # resolved to FakeEntryPoint.load — the only project function
        # whose simple name is "load" — and yaml.load was never
        # reachable. A dotted import call names its module explicitly.
        graph, _, res = scan("app_load_collision")
        self.assertEqual(res["yaml.load"].verdict, "reachable")
        self.assertIn("app.main", res["yaml.load"].path)
        self.assertNotIn("app.FakeEntryPoint.load", res["yaml.load"].path)
        self.assertIn("yaml.load", graph.edges.get("app.main", set()))

    def test_no_external_node_for_local_variable_call(self):
        # app_method has Loader().load_config() — a call on a Call node.
        # Its base must not become an external 'Loader' node, and
        # self.helper must not become an external 'self.helper' node.
        graph, _, _ = scan("app_method")
        self.assertNotIn("self.helper", graph.functions)
        self.assertNotIn("config.load", graph.functions)

    def test_old_fixtures_still_pass(self):
        for fixture, expected in [
            ("app_vuln", "reachable"),
            ("app_safe", "not_reachable"),
            ("app_dead", "not_reachable"),
            ("app_wrapper", "reachable"),
            ("app_route", "reachable"),
        ]:
            _, _, res = scan(fixture)
            self.assertEqual(res["yaml.load"].verdict, expected, fixture)


if __name__ == "__main__":
    unittest.main()
