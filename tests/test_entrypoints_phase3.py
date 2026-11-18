"""Phase 3 tests: console_scripts, Django urlpatterns, library __all__,
click commands, and the cache actually being used (diffs cached by sha)."""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyreach.advisory import load_advisories
from pyreach.cache import Cache, cache_key
from pyreach.callgraph import build_graph
from pyreach.entrypoints import find_entrypoints, find_entrypoints_with_evidence
from pyreach.phase1 import fetch_github_diff
from pyreach.reach import analyze

BASE = Path(__file__).resolve().parent.parent
ADV = load_advisories(str(BASE / "examples" / "advisory-sample.json"))


def scan(fixture: str):
    root = BASE / "fixtures" / fixture
    graph = build_graph(root)
    entries, note = find_entrypoints(root, graph)
    results = analyze(ADV, graph, entries)
    return graph, entries, note, {r.vulnerable_function: r for r in results}


class TestEntryPointsPhase3(unittest.TestCase):
    def test_console_scripts_is_the_only_entry(self):
        graph, entries, note, res = scan("app_console")
        self.assertEqual(entries, {"app.run"})
        self.assertEqual(res["yaml.load"].verdict, "reachable")
        self.assertIn("app.run", res["yaml.load"].path)
        self.assertNotIn("app.dead", res["yaml.load"].path)
        ev = find_entrypoints_with_evidence(BASE / "fixtures" / "app_console", graph)
        self.assertIn("console_scripts", ev["app.run"])

    def test_django_urlpatterns(self):
        graph, entries, note, res = scan("app_django")
        # urls.<module> is also an entry (top-level path() calls run on
        # import) — that is correct, just noisy. What matters: upload is
        # an entry, unused is not, and the path goes through upload.
        self.assertIn("views.upload", entries)
        self.assertNotIn("views.unused", entries)
        self.assertEqual(res["yaml.load"].verdict, "reachable")
        self.assertIn("views.upload", res["yaml.load"].path)
        self.assertNotIn("views.unused", res["yaml.load"].path)

    def test_library_all_limits_entries(self):
        graph, entries, note, res = scan("app_library")
        self.assertEqual(entries, {"pkg.lib.load_config"})
        self.assertIn("__all__", note)
        self.assertEqual(res["yaml.load"].verdict, "reachable")
        self.assertIn("pkg.lib.load_config", res["yaml.load"].path)

    def test_click_command_still_works(self):
        graph, entries, note, res = scan("app_click")
        self.assertEqual(entries, {"app.cli"})
        self.assertEqual(res["yaml.load"].verdict, "reachable")
        self.assertNotIn("app.dead", res["yaml.load"].path)

    def test_old_fixtures_unchanged(self):
        # Entries may also include app.<module> (Phase 2: top-level code
        # such as `if __name__ == "__main__": main()` runs on import).
        # What must not change: the expected entries are present, and
        # the verdicts are the same.
        for fixture, expected_entries, expected in [
            ("app_vuln", {"app.main"}, "reachable"),
            ("app_safe", {"app.main"}, "not_reachable"),
            ("app_dead", {"app.main"}, "not_reachable"),
            ("app_route", {"app.upload", "app.main"}, "reachable"),
        ]:
            _, entries, _, res = scan(fixture)
            self.assertTrue(expected_entries <= entries, fixture)
            self.assertEqual(res["yaml.load"].verdict, expected, fixture)


class TestCachePhase3(unittest.TestCase):
    def test_cache_key_changes_with_parser_and_artifact(self):
        k1 = cache_key("yaml", "5.3.1", "abc", "def")
        k2 = cache_key("yaml", "5.3.1", "abc", "xyz")
        self.assertNotEqual(k1, k2)
        k3 = cache_key("yaml", "5.3.1", "abc", "def", parser_version="other")
        self.assertNotEqual(k1, k3)

    def test_cache_round_trip(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            c = Cache(d)
            self.assertIsNone(c.get("k"))
            self.assertEqual(c.misses, 1)
            c.put("k", {"diff": "x"})
            self.assertEqual(c.get("k"), {"diff": "x"})
            self.assertEqual(c.hits, 1)

    def test_github_diff_uses_cache_without_network(self):
        """A pre-seeded cache must be used and no HTTP made. The fake
        cache only implements get/put and records whether get was called."""
        class FakeCache:
            def __init__(self):
                self.store = {cache_key("yaml/pyyaml", "a001", "a001"): {"diff": "FAKE-DIFF"}}
                self.hits = 0
                self.misses = 0
            def get(self, key):
                if key in self.store:
                    self.hits += 1
                    return self.store[key]
                self.misses += 1
                return None
            def put(self, key, data):
                self.store[key] = data
        fc = FakeCache()
        # This would raise / hang on network if the cache were ignored,
        # because 'a001' is not a real sha — but the cache hit returns first.
        self.assertEqual(fetch_github_diff("yaml/pyyaml", "a001", cache=fc), "FAKE-DIFF")
        self.assertEqual(fc.hits, 1)


if __name__ == "__main__":
    unittest.main()
