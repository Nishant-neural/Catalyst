"""Phase 11 tests: dependency-source parsing and graph merging.

No network in these tests: dependency graphs are built from synthetic
packages in tmp dirs and the merge is exercised directly. The live
PyPI path (fetch_sdist) is covered by the --live verify.py check.
"""
import unittest
from pathlib import Path

from pyreach.advisory import Advisory, VulnerableFunction
from pyreach.callgraph import build_graph
from pyreach.depsource import (
    find_package_root,
    import_names_for_advisory,
    merge_dependency,
)
from pyreach.entrypoints import find_entrypoints
from pyreach.reach import analyze, bfs_path


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _adv(pkg: str, *qualified: str) -> Advisory:
    return Advisory(
        id="GHSA-test-1", package=pkg,
        vulnerable_functions=[
            VulnerableFunction(qualified=q, file="", confidence="high",
                               evidence="test") for q in qualified
        ],
    )


class TestFindPackageRoot(unittest.TestCase):
    def test_src_layout(self):
        with __import__("tempfile").TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "src/fakepkg/__init__.py", "from .core import public_api\n")
            _write(root, "src/fakepkg/core.py", "def public_api(): pass\n")
            parent, pkg, name = find_package_root(root, ["fakepkg"])
            self.assertEqual(name, "fakepkg")
            self.assertEqual(pkg, root / "src" / "fakepkg")
            self.assertEqual(parent, root / "src")

    def test_lib3_beats_lib(self):
        # PyYAML ships both lib/ (py2) and lib3/ (py3) copies of yaml.
        with __import__("tempfile").TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "lib/yaml/__init__.py", "")
            _write(root, "lib3/yaml/__init__.py", "")
            parent, pkg, name = find_package_root(root, ["yaml"])
            self.assertEqual(name, "yaml")
            self.assertEqual(pkg, root / "lib3" / "yaml")

    def test_flat_layout(self):
        with __import__("tempfile").TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "fakepkg/__init__.py", "")
            parent, pkg, name = find_package_root(root, ["fakepkg"])
            self.assertEqual(parent, root)
            self.assertEqual(pkg, root / "fakepkg")

    def test_single_module(self):
        with __import__("tempfile").TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "helper.py", "def run(): pass\n")
            parent, pkg, name = find_package_root(root, ["helper"])
            self.assertEqual(name, "helper")
            self.assertEqual(parent, root)

    def test_top_level_txt_fallback(self):
        with __import__("tempfile").TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "weirdname/__init__.py", "")
            _write(root, "pkg.egg-info/top_level.txt", "weirdname\n")
            found = find_package_root(root, ["nosuch"])
            self.assertIsNotNone(found)
            self.assertEqual(found[2], "weirdname")

    def test_missing_returns_none(self):
        with __import__("tempfile").TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "other/__init__.py", "")
            self.assertIsNone(find_package_root(root, ["fakepkg"]))


class TestImportNames(unittest.TestCase):
    def test_first_segments(self):
        adv = _adv("jinja2", "jinja2.filters.do_attr",
                   "jinja2.filters.do_xmlattr", "os.path.isabs")
        self.assertEqual(import_names_for_advisory(adv),
                         ["jinja2", "os"])


class TestMerge(unittest.TestCase):
    def _build(self, tmp: str):
        base = Path(tmp)
        proj = base / "proj"
        _write(proj, "app.py",
               "import fakepkg\n\n"
               "def main():\n"
               "    fakepkg.public_api('x')\n\n"
               "if __name__ == '__main__':\n"
               "    main()\n")
        dep = base / "dep"
        _write(dep, "fakepkg/__init__.py", "from .core import public_api\n")
        _write(dep, "fakepkg/core.py",
               "def public_api(data):\n"
               "    return _internal_vuln(data)\n\n"
               "def _internal_vuln(data):\n"
               "    return data\n\n"
               "def _unused(data):\n"
               "    return data\n")
        graph = build_graph(proj)
        dep_graph = build_graph(dep)
        return graph, dep_graph

    def test_merge_links_public_api_to_internal(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            graph, dep_graph = self._build(tmp)
            entries, _ = find_entrypoints(Path(tmp) / "proj", graph)
            # Before the merge the internal function is invisible.
            self.assertIsNone(bfs_path(graph, entries,
                                       "fakepkg.core._internal_vuln"))
            merge_dependency(graph, dep_graph, "fakepkg", 2, 2)
            path = bfs_path(graph, entries, "fakepkg.core._internal_vuln")
            self.assertEqual(path, ["app.main", "fakepkg.public_api",
                                    "fakepkg.core.public_api",
                                    "fakepkg.core._internal_vuln"])

    def test_analyze_with_dep_parsed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            graph, dep_graph = self._build(tmp)
            entries, _ = find_entrypoints(Path(tmp) / "proj", graph)
            merge_dependency(graph, dep_graph, "fakepkg", 2, 2)
            results = analyze(
                [_adv("fakepkg", "fakepkg.core._internal_vuln",
                      "fakepkg.core._unused")], graph, entries)
            by_fn = {r.vulnerable_function: r for r in results}
            # Reached through the public API, with a real path.
            self.assertEqual(by_fn["fakepkg.core._internal_vuln"].verdict,
                             "reachable")
            self.assertTrue(by_fn["fakepkg.core._internal_vuln"].path)
            # First real not_reachable for a dependency internal: the
            # dependency source was parsed and nothing calls it.
            self.assertEqual(by_fn["fakepkg.core._unused"].verdict,
                             "not_reachable")

    def test_dep_functions_are_never_entries(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            graph, dep_graph = self._build(tmp)
            merge_dependency(graph, dep_graph, "fakepkg", 2, 2)
            entries, _ = find_entrypoints(Path(tmp) / "proj", graph)
            self.assertFalse(any(e.startswith("fakepkg.")
                                 for e in entries))
            self.assertIn("app.main", entries)

    def test_coverage_recorded(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            graph, dep_graph = self._build(tmp)
            merge_dependency(graph, dep_graph, "fakepkg", 2, 2)
            self.assertEqual(graph.dependency_coverage, {"fakepkg": (2, 2)})
            self.assertEqual(graph.dependency_parsed_modules, {"fakepkg"})
            self.assertTrue(graph.dependency_files)

    def test_unparsed_dep_stays_uncertain(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            graph, _ = self._build(tmp)
            entries, _ = find_entrypoints(Path(tmp) / "proj", graph)
            results = analyze([_adv("fakepkg", "hidden._secret")],
                              graph, entries)
            self.assertEqual(results[0].verdict, "uncertain")
            self.assertIn("dependency source not parsed",
                          results[0].reason)

    def test_project_function_wins_collision(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            proj = base / "proj"
            _write(proj, "app.py", "def main():\n    pkg.helper()\n")
            _write(proj, "pkg/__init__.py", "")
            _write(proj, "pkg/helper.py", "def helper():\n    return 1\n")
            dep = base / "dep"
            _write(dep, "pkg/__init__.py", "")
            _write(dep, "pkg/helper.py", "def helper():\n    return 2\n")
            graph = build_graph(proj)
            dep_graph = build_graph(dep)
            merge_dependency(graph, dep_graph, "pkg", 2, 2)
            # Module pkg.helper, function helper -> qualified pkg.helper.helper.
            info = graph.functions["pkg.helper.helper"]
            self.assertTrue(str(info.file).startswith(str(proj)))


if __name__ == "__main__":
    unittest.main()
