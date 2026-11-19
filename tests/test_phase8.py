"""Phase 8 tests (19 Nov 2026): the ChatGPT review fixes.

Unresolved-attr calls -> uncertain (Critical 1), OpenVEX aggregated
at the advisory level (Critical 2), the completeness gate (Critical 5),
entry-point reachability incl. the @mock.patch phantom (Critical 4),
phase1 b/ prefix + old_sources (Critical 6), deps transitive +
direct-URL/editable skipped (scan-all, §4).

No network in any test. The phase1 tests mock the fetch functions.
"""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from pyreach.advisory import Advisory, load_advisories
from pyreach.cache import Cache
from pyreach.callgraph import build_graph
from pyreach.cli import _run_scan
from pyreach.deps import (
    read_pyproject_deps,
    read_requirements_file,
    resolve_dependencies,
)
from pyreach.entrypoints import _is_route_decorator, find_entrypoints
from pyreach import phase1
from pyreach.reach import Result, analyze
from pyreach.vex import build_openvex

BASE = Path(__file__).resolve().parent.parent
ADV = load_advisories(str(BASE / "examples" / "advisory-sample.json"))
REAL_ADV = load_advisories(str(BASE / "examples" / "advisory-real-pyyaml.json"))


def scan(fixture: str, advisories=ADV):
    root = BASE / "fixtures" / fixture
    graph = build_graph(root)
    entries, note = find_entrypoints(root, graph)
    results = analyze(advisories, graph, entries)
    return graph, entries, note, {r.vulnerable_function: r for r in results}


def run_scan(fixture: str, advisories=ADV):
    """Full CLI scan (ledger, gate, VEX wiring) into a temp dir."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        args = SimpleNamespace(
            out=str(tmp / "report.json"), vex=str(tmp / "openvex.json"),
            with_proof=False, proof_timeout=10, explain=False,
            verbose=False, no_html=True, llm_debug=False, print_prompt=False,
        )
        report, code = _run_scan(BASE / "fixtures" / fixture, advisories,
                                 cache=Cache(tmp / ".reachcache"),
                                 use_llm=False, model=None,
                                 allow_fallback=False, args=args)
        vex = json.loads((tmp / "openvex.json").read_text(encoding="utf-8"))
        return report, code, vex


def _result(fn, adv="GHSA-test", verdict="not_reachable", conf="high"):
    return Result(advisory_id=adv, package="yaml", vulnerable_function=fn,
                  verdict=verdict, confidence=conf, reason="test reason")


class TestUnresolvedAttr(unittest.TestCase):
    def test_attr_unresolved_is_uncertain_not_not_reachable(self):
        _, _, _, res = scan("app_unresolved_attr")
        r = res["yaml.load"]
        self.assertEqual(r.verdict, "uncertain")
        self.assertEqual(r.confidence, "low")
        # The reason must name the exact site — this is the evidence
        # a judge checks, and it is what the old code silently dropped.
        self.assertIn("app.py:11", r.reason)

    def test_unresolved_attr_recorded_in_graph(self):
        graph, _, _, _ = scan("app_unresolved_attr")
        self.assertEqual(len(graph.unresolved_attrs), 1)
        self.assertEqual(graph.unresolved_attrs[0]["attr"], "load")
        self.assertEqual(graph.unresolved_attrs[0]["line"], 11)

    def test_no_vex_for_unresolved_attr(self):
        _, _, _, res = scan("app_unresolved_attr")
        vex = build_openvex(list(res.values()), "app_unresolved_attr",
                            graph_clean=True)
        self.assertEqual(vex["statements"], [])


class TestDunderSite(unittest.TestCase):
    def test_getattr_inside_dunder_blocks_not_reachable(self):
        # Nothing calls __getattr__ by name, so BFS alone never reaches
        # it — but attribute access invokes it at runtime. The MkDocs
        # config_options.py:549 site was dropped exactly this way.
        _, _, _, res = scan("app_dunder")
        r = res["yaml.load"]
        self.assertEqual(r.verdict, "uncertain")
        self.assertIn("dynamic trigger", r.reason)

    def test_site_can_run_covers_dunder_in_reachable_module(self):
        from pyreach.reach import (
            _has_dynamic_near,
            reachable_functions,
            reachable_modules,
            site_can_run,
        )
        graph, entries, _, _ = scan("app_dunder")
        reached = reachable_functions(graph, entries)
        modules = reachable_modules(graph, entries)
        self.assertIn("app", modules)
        dunder_sites = [d for d in graph.dynamic
                        if d["caller"].endswith(".__getattr__")]
        self.assertEqual(len(dunder_sites), 1)
        self.assertTrue(site_can_run(graph, entries, reached, modules,
                                     dunder_sites[0]))
        self.assertTrue(_has_dynamic_near(graph, entries))


class TestVexAggregation(unittest.TestCase):
    def test_all_clear_advisory_gets_one_statement(self):
        vex = build_openvex([_result("yaml.load"), _result("yaml.full_load")],
                            "app", graph_clean=True)
        self.assertEqual(len(vex["statements"]), 1)
        self.assertEqual(vex["statements"][0]["status"], "not_affected")
        self.assertIn("yaml.load", vex["statements"][0]["status_notes"])
        self.assertIn("yaml.full_load", vex["statements"][0]["status_notes"])

    def test_one_reachable_blocks_the_whole_advisory(self):
        vex = build_openvex([_result("yaml.load", verdict="reachable"),
                             _result("yaml.full_load")],
                            "app", graph_clean=True)
        self.assertEqual(vex["statements"], [])

    def test_one_uncertain_blocks_the_whole_advisory(self):
        vex = build_openvex([_result("yaml.load", verdict="uncertain", conf="low"),
                             _result("yaml.full_load")],
                            "app", graph_clean=True)
        self.assertEqual(vex["statements"], [])

    def test_low_confidence_not_reachable_blocks_vex(self):
        vex = build_openvex([_result("yaml.load", conf="low")],
                            "app", graph_clean=True)
        self.assertEqual(vex["statements"], [])

    def test_dirty_graph_blocks_vex(self):
        vex = build_openvex([_result("yaml.load")], "app", graph_clean=False)
        self.assertEqual(vex["statements"], [])

    def test_mixed_advisories_only_clear_one_gets_a_statement(self):
        vex = build_openvex([_result("yaml.load", adv="GHSA-1"),
                             _result("yaml.load", adv="GHSA-2", verdict="reachable")],
                            "app", graph_clean=True)
        self.assertEqual(len(vex["statements"]), 1)
        self.assertEqual(vex["statements"][0]["vulnerability"]["@id"], "GHSA-1")

    def test_vex_full_fixture_real_advisory_zero_statements(self):
        report, code, vex = run_scan("app_vex_full", REAL_ADV)
        by_fn = {r["vulnerable_function"]: r for r in report["results"]}
        self.assertEqual(by_fn["yaml.load"]["verdict"], "reachable")
        self.assertEqual(by_fn["FullLoader"]["verdict"], "uncertain")
        self.assertEqual(by_fn["full_load"]["verdict"], "not_reachable")
        # Phase 12: yaml.full_load is uncertain without --with-deps —
        # reachable code calls yaml.load and yaml source is unparsed.
        self.assertEqual(by_fn["yaml.full_load"]["verdict"], "uncertain")
        self.assertEqual(vex["statements"], [])
        self.assertEqual(code, 2)


class TestEntryReachability(unittest.TestCase):
    def test_never_imported_module_is_not_an_entry(self):
        _, entries, _, res = scan("app_never_imported")
        self.assertIn("app.main", entries)
        self.assertNotIn("never_imported.<module>", entries)
        self.assertEqual(res["yaml.load"].verdict, "not_reachable")

    def test_never_imported_gets_vex(self):
        _, code, vex = run_scan("app_never_imported")
        self.assertEqual(code, 0)
        self.assertEqual(len(vex["statements"]), 1)

    def test_mock_patch_is_not_a_route_decorator(self):
        self.assertFalse(_is_route_decorator("mock.patch"))
        self.assertFalse(_is_route_decorator("mock.patch.object"))
        self.assertTrue(_is_route_decorator("app.route"))

    def test_mockpatch_fixture_no_phantom_entry(self):
        _, entries, _, res = scan("app_mockpatch")
        self.assertNotIn("test_app.test_something", entries)
        self.assertEqual(res["yaml.load"].verdict, "not_reachable")


class TestLedgerGate(unittest.TestCase):
    def test_unparsed_file_flips_not_reachable_to_uncertain(self):
        report, code, vex = run_scan("app_unparsed")
        r = report["results"][0]
        self.assertEqual(r["verdict"], "uncertain")
        self.assertEqual(r["confidence"], "low")
        self.assertIn("Completeness gate", r["reason"])
        ledger = report["completeness_ledger"]
        self.assertEqual(ledger["project_source"], "1/2 parsed")
        self.assertEqual(vex["statements"], [])
        self.assertEqual(code, 0)

    def test_clean_app_stays_not_reachable_and_gets_vex(self):
        # Phase 12: app_safe is uncertain now (it calls yaml.safe_load
        # with yaml source unparsed), so the all-clear case is app_dead,
        # which calls no yaml function at all.
        report, code, vex = run_scan("app_dead")
        r = report["results"][0]
        self.assertEqual(r["verdict"], "not_reachable")
        self.assertEqual(len(vex["statements"]), 1)
        self.assertEqual(code, 0)


class TestPhase1Fixes(unittest.TestCase):
    DIFF = (
        "diff --git a/lib/yaml/constructor.py b/lib/yaml/constructor.py\n"
        "--- a/lib/yaml/constructor.py\n"
        "+++ b/lib/yaml/constructor.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-def load_old(stream):\n"
        "-    return old_thing()\n"
        "+def load_new(stream):\n"
        "+    return new_thing()\n"
    )
    OLD_SRC = "def load_old(stream):\n    return old_thing()\n"
    NEW_SRC = "def load_new(stream):\n    return new_thing()\n"
    SHA = "a" * 40
    PARENT = "p" * 40

    def test_diff_files_strip_b_prefix_and_old_sources_fetched(self):
        adv = Advisory(id="GHSA-test", package="yaml", fixed_version="2.0",
                       references=[f"https://github.com/yaml/pyyaml/commit/{self.SHA}"],
                       summary="test")
        calls = []

        def fake_fetch_file(repo, sha, path):
            calls.append((repo, sha, path))
            return self.OLD_SRC if sha == self.PARENT else self.NEW_SRC

        with mock.patch.object(phase1, "fetch_osv", return_value=[adv]), \
             mock.patch.object(phase1, "fetch_github_diff", return_value=self.DIFF), \
             mock.patch.object(phase1, "fetch_github_parent_sha", return_value=self.PARENT), \
             mock.patch.object(phase1, "fetch_github_file", side_effect=fake_fetch_file):
            entries = phase1.analyse_advisory_live("yaml", "1.0")
        self.assertEqual(len(entries), 1)
        # b/ stripped: the file fetch used the clean path for both shas.
        self.assertEqual(entries[0]["diff_files"], ["lib/yaml/constructor.py"])
        self.assertIn(("yaml/pyyaml", self.SHA, "lib/yaml/constructor.py"), calls)
        self.assertIn(("yaml/pyyaml", self.PARENT, "lib/yaml/constructor.py"), calls)
        # The old-side mapping actually ran: a candidate whose evidence
        # cites the old version exists.
        cands = entries[0]["candidates"]
        self.assertTrue(any("old:" in c.get("evidence", "") for c in cands), cands)

    def test_fetch_github_file_strips_b_prefix(self):
        seen = []

        class FakeResp:
            status_code = 200
            text = "x"

        class FakeRequests:
            def get(self, url, headers=None, timeout=None):
                seen.append(url)
                return FakeResp()

        with mock.patch.object(phase1, "_get_requests", return_value=FakeRequests()):
            self.assertEqual(phase1.fetch_github_file("yaml/pyyaml", self.SHA,
                                                      "b/lib/yaml/constructor.py"), "x")
        self.assertEqual(seen, [f"https://raw.githubusercontent.com/yaml/pyyaml/{self.SHA}/lib/yaml/constructor.py"])

    def test_parent_sha_failure_is_best_effort(self):
        with mock.patch.object(phase1, "_get_requests", side_effect=RuntimeError("no requests")):
            self.assertIsNone(phase1.fetch_github_parent_sha("yaml/pyyaml", self.SHA))


class TestDepsPhase8(unittest.TestCase):
    def test_transitive_lockfile_packages_are_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                '[project]\ndependencies = ["requests==2.31.0"]\n', encoding="utf-8")
            (root / "poetry.lock").write_text(
                '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
                '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n',
                encoding="utf-8")
            with mock.patch("pyreach.deps.installed_version", return_value=None):
                deps, notes = resolve_dependencies(root)
        by_key = {d.key: d for d in deps}
        self.assertIn("urllib3", by_key)
        u = by_key["urllib3"]
        self.assertEqual(u.version, "2.0.0")
        self.assertEqual(u.version_source, "lockfile")
        self.assertEqual(u.status, "pinned")
        self.assertIn("transitive", u.declared_in)
        self.assertTrue(any("transitive" in n for n in notes))

    def test_direct_url_and_editable_are_skipped_not_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            req = Path(tmp) / "requirements.txt"
            req.write_text(
                "foo @ https://example.com/foo.tar.gz\n"
                "-e git+https://github.com/x/bar.git#egg=bar\n"
                "PyYAML==5.3.1\n", encoding="utf-8")
            deps = read_requirements_file(req)
        by_key = {d.key: d for d in deps}
        self.assertEqual(len(deps), 3)
        self.assertEqual(by_key["foo"].status, "skipped")
        self.assertIn("direct URL", by_key["foo"].reason)
        self.assertEqual(by_key["bar"].status, "skipped")
        self.assertIn("editable", by_key["bar"].reason)
        self.assertEqual(by_key["pyyaml"].status, "pinned")
        self.assertEqual(by_key["pyyaml"].spec, "==5.3.1")

    def test_poetry_git_dep_is_skipped_with_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                '[tool.poetry.dependencies]\n'
                'python = "^3.11"\n'
                'foo = {git = "https://github.com/x/foo.git"}\n',
                encoding="utf-8")
            deps = read_pyproject_deps(root)
        by_key = {d.key: d for d in deps}
        self.assertEqual(by_key["foo"].status, "skipped")
        self.assertIn("git", by_key["foo"].reason)


if __name__ == "__main__":
    unittest.main()


class TestPerAdvisoryVexGate(unittest.TestCase):
    # Phase 13, 19 Nov 2026: the VEX gate is per-advisory, not the
    # whole-run ledger. A global ambiguous count (PyYAML's own 64
    # ambiguous edges inside the parsed dependency) must not block a
    # statement for targets none of them can be.
    def _results(self, adv, verdicts):
        from pyreach.reach import Result
        return [Result(adv, "PyYAML", fn, v, "high")
                for fn, v in verdicts]

    def test_dict_clean_emits_only_for_the_clean_advisory(self):
        from pyreach.vex import build_openvex
        results = (self._results("GHSA-CLEAN", [
                        ("yaml.load", "not_reachable"),
                        ("yaml.full_load", "not_reachable")])
                   + self._results("GHSA-DIRTY", [
                        ("yaml.load", "not_reachable"),
                        ("yaml.full_load", "uncertain")]))
        vex = build_openvex(results, "proj",
                            graph_clean={"GHSA-CLEAN": True,
                                         "GHSA-DIRTY": False})
        self.assertEqual(
            [s["vulnerability"]["@id"] for s in vex["statements"]],
            ["GHSA-CLEAN"])

    def test_bool_clean_keeps_old_behaviour(self):
        from pyreach.vex import build_openvex
        results = self._results("GHSA-1", [("yaml.load", "not_reachable")])
        self.assertEqual(
            len(build_openvex(results, "proj", graph_clean=True)
                ["statements"]), 1)
        self.assertEqual(
            len(build_openvex(results, "proj", graph_clean=False)
                ["statements"]), 0)
