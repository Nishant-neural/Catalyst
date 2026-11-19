"""Phase 12 tests (19 Nov 2026): the second ChatGPT review, of Phase 9.

Only the claims that reproduced against Phase 11 and genuinely help
the demo were fixed — see PHASES.md. Already-fixed claims are
regression-tested here too, so a reviewer re-running them gets the
same answer: relative imports (Phase 10) and dependency-source
parsing (Phase 11, --with-deps).

No network in any test.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pyreach.advisory import Advisory, VulnerableFunction, load_advisories
from pyreach.callgraph import build_graph
from pyreach.cli import main as cli_main
from pyreach.dotenv import find_dotenv_file
from pyreach.entrypoints import find_entrypoints
from pyreach.reach import analyze, dep_entry_call
from pyreach.resolver import getattr_receiver, resolve_getattr_case
from pyreach.vex import build_openvex

BASE = Path(__file__).resolve().parent.parent
ADV = load_advisories(str(BASE / "examples" / "advisory-sample.json"))

JSON_SRC = 'import json\n\n\ndef main():\n    name = "load"\n    func = getattr(json, name)\n    return func("{}")\n'
YAML_SRC = 'import yaml\n\n\ndef main():\n    name = "load"\n    func = getattr(yaml, name)\n    return func("{}")\n'
UNKNOWN_SRC = 'import yaml\n\n\ndef main():\n    func = getattr(self.option, key)\n    return func("{}")\n'


class TestReceiverGate(unittest.TestCase):
    def test_json_load_is_not_yaml_load(self):
        # ChatGPT Issue 3, reproduced: getattr(json, "load") was
        # REACHABLE high for yaml.load. Now the site is safe.
        out = resolve_getattr_case(JSON_SRC, 6, ["yaml.load"], {"yaml.load"},
                                   imports={"json": "json"})
        self.assertEqual(out["verdict"], "not_reachable")
        self.assertEqual(out["confidence"], "high")
        self.assertIn("json", out["reason"])

    def test_yaml_load_still_reachable(self):
        out = resolve_getattr_case(YAML_SRC, 6, ["yaml.load"], {"yaml.load"},
                                   imports={"yaml": "yaml"})
        self.assertEqual(out["verdict"], "reachable")
        self.assertEqual(out["confidence"], "high")

    def test_unknown_receiver_stays_uncertain(self):
        # getattr(self.option, key): the receiver's type is unknown, so
        # no module identity can be checked — never guess by name.
        self.assertIsNone(getattr_receiver(UNKNOWN_SRC, 5, {"yaml": "yaml"}))
        out = resolve_getattr_case(UNKNOWN_SRC, 5, ["yaml.load"], {"yaml.load"},
                                   imports={"yaml": "yaml"}, allow_llm=False)
        self.assertIsNone(out)

    def test_aliased_import_resolves(self):
        src = 'import yaml as y\n\n\ndef main():\n    name = "load"\n    func = getattr(y, name)\n    return func("{}")\n'
        out = resolve_getattr_case(src, 6, ["yaml.load"], {"yaml.load"},
                                   imports={"y": "yaml"})
        self.assertEqual(out["verdict"], "reachable")

    def test_llm_false_never_certifies_absence(self):
        # ChatGPT Issue 4, mocked: the model lists ["safe_load"] while
        # config can supply "load". The verifier passes that answer,
        # but the policy layer must not turn it into not_reachable —
        # only deterministic constant propagation may certify absence.
        ans = {"can_reach": False, "possible_values": ["safe_load"],
               "vulnerable_hit": None, "reason": "only safe_load is used",
               "evidence_lines": [1], "confidence": 0.99}
        src = 'fallback = "safe_load"\n\n\ndef main(config, data):\n    name = config.get("func", fallback)\n    func = getattr(yaml, name)\n    return func(data)\n'
        with mock.patch("pyreach.resolver.resolve_with_llm",
                        return_value=ans):
            out = resolve_getattr_case(src, 6, ["yaml.load"], {"yaml.load"},
                                       imports={"yaml": "yaml"})
        self.assertIsNone(out)


class TestDepWrapper(unittest.TestCase):
    def _adv(self):
        return [Advisory(
            id="OSV-TEST-1", package="thirdparty",
            vulnerable_functions=[VulnerableFunction(
                qualified="thirdparty.vulnerable",
                file="thirdparty/__init__.py",
                confidence="high", evidence="fix commit")])]

    def test_wrapper_call_blocks_not_reachable(self):
        # ChatGPT Issue 2, reproduced: app calls thirdparty.safe_api(),
        # dep source 0 parsed, old code said not_reachable + 1 VEX.
        root = BASE / "fixtures" / "app_dep_wrapper"
        graph = build_graph(root)
        entries, _ = find_entrypoints(root, graph)
        self.assertEqual(dep_entry_call(graph, entries,
                                        "thirdparty.vulnerable"),
                         "thirdparty.safe_api")
        results = analyze(self._adv(), graph, entries)
        self.assertEqual(results[0].verdict, "uncertain")
        self.assertIn("safe_api", results[0].reason)
        vex = build_openvex(results, "app_dep_wrapper", graph_clean=True)
        self.assertEqual(vex["statements"], [])

    def test_safe_load_entry_blocks_not_reachable(self):
        # The same rule, on the old all-clear fixture: app_safe calls
        # yaml.safe_load() while yaml source is unparsed, so yaml.load
        # is uncertain without --with-deps (with --with-deps it is
        # reachable via safe_load, verify.py section K).
        root = BASE / "fixtures" / "app_safe"
        graph = build_graph(root)
        entries, _ = find_entrypoints(root, graph)
        self.assertEqual(dep_entry_call(graph, entries, "yaml.load"),
                         "yaml.safe_load")
        results = analyze(ADV, graph, entries)
        self.assertEqual(results[0].verdict, "uncertain")

    def test_dead_code_still_not_reachable(self):
        # No reachable call enters the yaml package at all, so the
        # dep-entry rule does not fire: app_dead stays not_reachable.
        root = BASE / "fixtures" / "app_dead"
        graph = build_graph(root)
        entries, _ = find_entrypoints(root, graph)
        self.assertIsNone(dep_entry_call(graph, entries, "yaml.load"))
        results = analyze(ADV, graph, entries)
        self.assertEqual(results[0].verdict, "not_reachable")


class TestNestedCli(unittest.TestCase):
    def test_unimported_nested_cli_is_not_an_entry(self):
        # ChatGPT section 4B, reproduced: pkg/cli.py top-level
        # yaml.load() was REACHABLE via pkg.cli.<module>.
        root = BASE / "fixtures" / "app_nested_cli"
        graph = build_graph(root)
        entries, _ = find_entrypoints(root, graph)
        self.assertNotIn("pkg.cli.<module>", entries)
        results = analyze(ADV, graph, entries)
        self.assertEqual(results[0].verdict, "not_reachable")


class TestDynamicPath(unittest.TestCase):
    def test_phase4_reachable_has_a_call_path(self):
        # ChatGPT section 4A, reproduced: a Phase 4 reachable had
        # path []. Now the path is entry -> ... -> caller -> target.
        out = Path(tempfile.mkdtemp()) / "report.json"
        code = cli_main(["scan", str(BASE / "fixtures" / "app_getattr_load"),
                         "--advisory",
                         str(BASE / "examples" / "advisory-sample.json"),
                         "--no-llm", "--no-html", "--out", str(out),
                         "--cache-dir", str(Path(tempfile.mkdtemp()))])
        self.assertEqual(code, 2)
        rep = json.loads(out.read_text())
        r = rep["results"][0]
        self.assertEqual(r["verdict"], "reachable")
        self.assertTrue(r["path"], "reachable must carry a call path")
        self.assertEqual(r["path"][0], "app.main")
        self.assertEqual(r["path"][-1], "yaml.load")


class TestNestedAllIgnored(unittest.TestCase):
    def test_subpackage_all_is_not_the_library_surface(self):
        # 19 Nov 2026: _dunder_all took the first __all__ found by
        # rglob anywhere, which for MkDocs was mkdocs/config/__init__.py
        # (['load_config', 'Config']) — entries collapsed 1,092 -> 72.
        # Only the top-level package's __init__ counts.
        from pyreach.entrypoints import _dunder_all
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pkg").mkdir()
            (root / "pkg" / "__init__.py").write_text("__version__ = '1'\n")
            (root / "pkg" / "sub").mkdir()
            (root / "pkg" / "sub" / "__init__.py").write_text(
                "__all__ = ['helper']\n\ndef helper():\n    pass\n")
            self.assertIsNone(_dunder_all(root))
            (root / "pkg" / "__init__.py").write_text(
                "__all__ = ['top_fn']\n\ndef top_fn():\n    pass\n")
            self.assertEqual(_dunder_all(root), ["top_fn"])

    def test_src_layout_all_is_found(self):
        from pyreach.entrypoints import _dunder_all
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src" / "pkg").mkdir(parents=True)
            (root / "src" / "pkg" / "__init__.py").write_text(
                "__all__ = ['Widget']\n")
            self.assertEqual(_dunder_all(root), ["Widget"])


class TestDotenvProjectIgnored(unittest.TestCase):
    def test_project_env_is_not_loaded(self):
        # ChatGPT section 4C, reproduced: a scanned project's .env
        # with LLM_BASE_URL was loaded into the process. Now only the
        # caller's own .env (cwd walk-up) or an explicit file counts.
        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp) / "proj"
            proj.mkdir()
            (proj / ".env").write_text(
                "LLM_BASE_URL=http://127.0.0.1:9/evil\n")
            cwd = Path(tmp) / "elsewhere"
            cwd.mkdir()
            old = os.getcwd()
            try:
                os.chdir(cwd)
                self.assertIsNone(find_dotenv_file(project=proj))
            finally:
                os.chdir(old)


if __name__ == "__main__":
    unittest.main()
