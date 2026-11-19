"""Evaluation fixes (19 Nov 2026): two bugs the real-project evaluation
found, with regression tests.

1. Console-script module (entrypoints.py): the part before ":" in a
   console-script target IS the module ("pkg.mod:func"). The old code
   stripped its last segment, so "yamllint.cli:run" resolved with
   prefer_module "yamllint", matched two `def run` (cli.run and
   linter.run), and was reported unsupported. The entry itself survived
   only because yamllint scans in library mode; in app mode the entry
   would have been lost.
2. Stdlib collision (callgraph.py _record_import): a repo directory
   named like a stdlib module (ansible-lint's collections/ fixture
   dir) made every `from collections.abc import ...` an "unresolved
   import" in the ledger (~100 false entries). Stdlib imports are
   never unresolved project imports.
"""

import tempfile
import unittest
from pathlib import Path

from pyreach.callgraph import build_graph
from pyreach.entrypoints import (
    find_entrypoints,
    find_entrypoints_with_evidence,
    find_unsupported_entrypoints,
)


class TestConsoleScriptAmbiguous(unittest.TestCase):
    """Two `def run` in different modules; the script names app.cli:run."""

    FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "app_console_ambig"

    def test_script_resolves_to_cli_run(self):
        graph = build_graph(self.FIXTURE)
        entries, _note = find_entrypoints(self.FIXTURE, graph)
        self.assertIn("pkg.cli.run", entries)
        self.assertNotIn("pkg.linter.run", entries)

    def test_evidence_names_console_script(self):
        graph = build_graph(self.FIXTURE)
        ev = find_entrypoints_with_evidence(self.FIXTURE, graph)
        self.assertIn("pkg.cli.run", ev)
        self.assertIn("console_scripts", ev["pkg.cli.run"])

    def test_no_unsupported_console_script(self):
        graph = build_graph(self.FIXTURE)
        unsupported = find_unsupported_entrypoints(self.FIXTURE, graph)
        self.assertEqual(
            [u for u in unsupported if u.startswith("console_scripts")], []
        )


class TestConsoleScriptReexport(unittest.TestCase):
    """19 Nov 2026 evaluation find: cookiecutter's console script
    points at `cookiecutter.__main__:main`, but main is imported
    there (`from cookiecutter.cli import main`), not defined. Same
    for kedro (`kedro.framework.cli:main`, re-exported from .cli).
    The resolver must follow the script module's imports one level."""

    FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "app_console_reexport"

    def test_script_resolves_through_reexport(self):
        graph = build_graph(self.FIXTURE)
        entries, _note = find_entrypoints(self.FIXTURE, graph)
        self.assertEqual(entries, {"pkg.cli.main"})

    def test_no_unsupported_console_script(self):
        graph = build_graph(self.FIXTURE)
        self.assertEqual(find_unsupported_entrypoints(self.FIXTURE, graph), [])

    def test_evidence_names_console_script(self):
        graph = build_graph(self.FIXTURE)
        ev = find_entrypoints_with_evidence(self.FIXTURE, graph)
        self.assertIn("console_scripts", ev["pkg.cli.main"])


class TestLibraryAllKeepsConsoleScript(unittest.TestCase):
    """19 Nov 2026 evaluation find: in library mode with a root
    __all__, find_entrypoints returned ONLY the __all__ names,
    discarding the console-script entry — kedro's `kedro` script
    (its real entry point) never became a BFS start."""

    FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "app_library_all"

    def test_all_and_console_script_are_both_entries(self):
        graph = build_graph(self.FIXTURE)
        entries, _note = find_entrypoints(self.FIXTURE, graph)
        self.assertIn("pkg.public_fn", entries)
        self.assertIn("pkg.cli.main", entries)


class TestStdlibImportNotUnresolved(unittest.TestCase):
    """A repo dir named like a stdlib module must not poison the ledger."""

    def _project(self, tmp: str) -> Path:
        root = Path(tmp)
        (root / "collections").mkdir()
        (root / "collections" / "fixture.py").write_text(
            "VALUE = 1\n", encoding="utf-8"
        )
        # myapp/ has NO __init__.py: "myapp" is a project top (via
        # myapp/core.py) but not itself a project module, so importing
        # a non-existent myapp.* submodule is genuinely unresolved.
        (root / "myapp").mkdir()
        (root / "myapp" / "core.py").write_text(
            "VALUE = 2\n", encoding="utf-8"
        )
        (root / "app.py").write_text(
            "from collections.abc import Mapping\n"
            "from collections import defaultdict\n"
            "\n"
            "def check(x):\n"
            "    return isinstance(x, Mapping)\n",
            encoding="utf-8",
        )
        return root

    def test_stdlib_imports_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            graph = build_graph(root)
            self.assertEqual(graph.unresolved_imports, [])

    def test_real_unresolved_project_import_still_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            # myapp/ IS a project top and is not stdlib, so importing
            # a non-existent submodule of it is genuinely unresolved.
            # (Both the module and the imported name are recorded.)
            (root / "app.py").write_text(
                "from myapp.nosuch import thing\n",
                encoding="utf-8",
            )
            graph = build_graph(root)
            self.assertEqual(len(graph.unresolved_imports), 2)
            self.assertTrue(
                all("myapp.nosuch" in u for u in graph.unresolved_imports)
            )


if __name__ == "__main__":
    unittest.main()
