"""Loader-aware verdicts + resolver reorder (Phase 13, 19 Nov 2026).

The Loader argument is the difference between yaml.load being a real
vulnerability and safe_load-only use: load(stream) defaults to the
unsafe Loader, load(stream, SafeLoader) cannot construct arbitrary
Python objects. These tests pin the extraction, the flip rule, and
the resolver reorder that stopped literal-name dynamic sites
('CONF', 'DEFAULT', 'name') blocking every not_reachable verdict.
"""
import tempfile
import unittest
from pathlib import Path

from pyreach.callgraph import build_graph
from pyreach.reach import Graph, Result, apply_loader_rule
from pyreach.resolver import resolve_getattr_case


def _scan_tree(files: dict[str, str]):
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    graph = build_graph(root)
    return tmp, root, graph


class TestLoaderExtraction(unittest.TestCase):
    def test_safe_load_records_safeloader(self):
        tmp, root, graph = _scan_tree({
            "app.py": ("import yaml\n\n\n"
                       "def main():\n"
                       "    with open('c.yaml') as f:\n"
                       "        return yaml.safe_load(f)\n"),
        })
        self.assertEqual(
            graph.loader_calls.get(("app.main", "yaml.safe_load")),
            {"SafeLoader"})
        tmp.cleanup()

    def test_explicit_loader_keyword(self):
        tmp, root, graph = _scan_tree({
            "app.py": ("import yaml\n\n\n"
                       "def main():\n"
                       "    return yaml.load('x: 1', Loader=yaml.SafeLoader)\n"
                       "\n\n"
                       "def other():\n"
                       "    return yaml.load('x: 1')\n"),
        })
        self.assertEqual(
            graph.loader_calls.get(("app.main", "yaml.load")),
            {"SafeLoader"})
        self.assertEqual(
            graph.loader_calls.get(("app.other", "yaml.load")),
            {"Loader"})
        tmp.cleanup()

    def test_positional_loader_and_variable_loader(self):
        tmp, root, graph = _scan_tree({
            "app.py": ("import yaml\n\n\n"
                       "def main():\n"
                       "    return yaml.load('x: 1', yaml.FullLoader)\n"
                       "\n\n"
                       "def other(loader_cls):\n"
                       "    return yaml.load('x: 1', loader_cls)\n"),
        })
        self.assertEqual(
            graph.loader_calls.get(("app.main", "yaml.load")),
            {"FullLoader"})
        # A variable loader is recorded as its name, not as a known
        # safe loader — apply_loader_rule will not flip on it.
        self.assertEqual(
            graph.loader_calls.get(("app.other", "yaml.load")),
            {"loader_cls"})
        tmp.cleanup()

    def test_dep_internal_safe_load_calls_load_with_safeloader(self):
        tmp, root, graph = _scan_tree({
            "yaml/__init__.py": ("def load(stream, Loader):\n"
                                 "    return Loader(stream)\n"
                                 "\n\n"
                                 "def safe_load(stream):\n"
                                 "    return load(stream, SafeLoader)\n"
                                 "\n\n"
                                 "class SafeLoader:\n"
                                 "    pass\n"),
        })
        self.assertEqual(
            graph.loader_calls.get(("yaml.safe_load", "load")),
            {"SafeLoader"})
        tmp.cleanup()

    def test_bare_load_outside_yaml_is_not_recorded(self):
        tmp, root, graph = _scan_tree({
            "app.py": ("import json\n\n\n"
                       "def main():\n"
                       "    return json.load(open('c.json'))\n"),
        })
        self.assertEqual(graph.loader_calls, {})
        tmp.cleanup()


def _graph_with_loader_edges():
    graph = Graph()
    from pyreach.callgraph import FuncInfo
    for q in ("app.main", "yaml.safe_load", "yaml.load",
              "FullConstructor.construct_python_object"):
        graph.functions[q] = FuncInfo(
            qualified=q,
            file="app.py" if q == "app.main" else "external",
            start=0, end=0, name=q.split(".")[-1])
    graph.edges["app.main"] = {"yaml.safe_load"}
    graph.edges["yaml.safe_load"] = {"yaml.load"}
    graph.edges["yaml.load"] = {"FullConstructor.construct_python_object"}
    graph.loader_calls[("app.main", "yaml.safe_load")] = {"SafeLoader"}
    graph.loader_calls[("yaml.safe_load", "yaml.load")] = {"SafeLoader"}
    return graph


class TestApplyLoaderRule(unittest.TestCase):
    def test_safe_loader_only_flips_yaml_load(self):
        graph = _graph_with_loader_edges()
        results = [Result("GHSA-1", "PyYAML", "yaml.load", "reachable", "high",
                          path=["app.main", "yaml.safe_load", "yaml.load"])]
        out = apply_loader_rule(graph, results, {"app.main"})
        self.assertEqual(out[0].verdict, "not_reachable")
        self.assertIn("SafeLoader", out[0].reason)

    def test_unsafe_loader_anywhere_blocks_the_flip(self):
        graph = _graph_with_loader_edges()
        graph.loader_calls[("app.other", "yaml.load")] = {"Loader"}
        graph.functions["app.other"] = graph.functions["app.main"]
        graph.edges["app.other"] = {"yaml.load"}
        results = [Result("GHSA-1", "PyYAML", "yaml.load", "reachable", "high",
                          path=["app.main", "yaml.safe_load", "yaml.load"])]
        out = apply_loader_rule(graph, results, {"app.main", "app.other"})
        self.assertEqual(out[0].verdict, "reachable")

    def test_no_loader_step_recorded_stays_reachable(self):
        graph = _graph_with_loader_edges()
        graph.loader_calls.clear()
        results = [Result("GHSA-1", "PyYAML", "yaml.load", "reachable", "high",
                          path=["app.main", "yaml.safe_load", "yaml.load"])]
        out = apply_loader_rule(graph, results, {"app.main"})
        self.assertEqual(out[0].verdict, "reachable")

    def test_construct_via_safe_loader_flips_too(self):
        graph = _graph_with_loader_edges()
        results = [Result("GHSA-1", "PyYAML",
                          "FullConstructor.construct_python_object",
                          "reachable", "medium",
                          path=["app.main", "yaml.safe_load", "yaml.load",
                                "FullConstructor.construct_python_object"])]
        out = apply_loader_rule(graph, results, {"app.main"})
        self.assertEqual(out[0].verdict, "not_reachable")

    def test_full_load_never_flips(self):
        graph = _graph_with_loader_edges()
        graph.loader_calls[("app.main", "yaml.full_load")] = {"FullLoader"}
        results = [Result("GHSA-1", "PyYAML", "yaml.full_load", "reachable", "high",
                          path=["app.main", "yaml.full_load"])]
        out = apply_loader_rule(graph, results, {"app.main"})
        self.assertEqual(out[0].verdict, "reachable")

    def test_uncertain_and_not_reachable_are_untouched(self):
        graph = _graph_with_loader_edges()
        results = [
            Result("GHSA-1", "PyYAML", "yaml.load", "uncertain", "low"),
            Result("GHSA-1", "PyYAML", "yaml.full_load",
                   "not_reachable", "high"),
        ]
        out = apply_loader_rule(graph, results, {"app.main"})
        self.assertEqual([r.verdict for r in out],
                         ["uncertain", "not_reachable"])


class TestResolverReorder(unittest.TestCase):
    # getattr(rule, 'CONF') / getattr(rule, 'DEFAULT') in yamllint and
    # getattr(stream, 'name') in PyYAML's reader: the NAME is a literal
    # that can never be the vulnerable function, so the site is safe
    # whatever the receiver is. The old gate-first order returned None
    # for the unknown receiver before constants ran.
    def test_literal_safe_name_beats_unknown_receiver(self):
        src = ("def validate(rule):\n"
               "    options = getattr(rule, 'CONF', {})\n"
               "    return options\n")
        out = resolve_getattr_case(src, 2, ["yaml.load"], set(),
                                   allow_llm=False)
        self.assertIsNotNone(out)
        self.assertEqual(out["verdict"], "not_reachable")

    def test_setattr_site_cannot_call_anything(self):
        src = ("def build(cls, file):\n"
               "    setattr(cls, 'test_' + file, lambda: None)\n")
        out = resolve_getattr_case(src, 2, ["yaml.load"], set(),
                                   allow_llm=False)
        self.assertIsNotNone(out)
        self.assertEqual(out["verdict"], "not_reachable")

    def test_globals_site_cannot_call_anything(self):
        src = ("def reg(rank):\n"
               "    globals()[rank] = rank\n")
        out = resolve_getattr_case(src, 2, ["yaml.load"], set(),
                                   allow_llm=False)
        self.assertIsNotNone(out)
        self.assertEqual(out["verdict"], "not_reachable")

    def test_vulnerable_name_with_unknown_receiver_stays_uncertain(self):
        src = ("def f(x):\n"
               "    return getattr(x, 'load')\n")
        out = resolve_getattr_case(src, 2, ["yaml.load"], set(),
                                   allow_llm=False, imports={})
        self.assertIsNone(out)

    def test_vulnerable_name_with_json_receiver_stays_safe(self):
        src = ("import json\n\n\n"
               "def f():\n"
               "    return getattr(json, 'load')\n")
        out = resolve_getattr_case(src, 5, ["yaml.load"], set(),
                                   allow_llm=False,
                                   imports={"json": "json"})
        self.assertIsNotNone(out)
        self.assertEqual(out["verdict"], "not_reachable")


if __name__ == "__main__":
    unittest.main()
