"""Tests for Phase 7 dependency resolution (pyreach/deps.py).

No network in any test. installed_version is patched to None unless a
test says otherwise, so the tests do not depend on what happens to be
installed in the machine running them.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pyreach.deps import (
    advisory_file_for,
    exact_pin,
    normalize_name,
    parse_requirement,
    read_lockfile_versions,
    read_pyproject_deps,
    read_requirements_file,
    resolve_dependencies,
)


class TestNamesAndSpecs(unittest.TestCase):
    def test_normalize_name(self):
        self.assertEqual(normalize_name("PyYAML"), "pyyaml")
        self.assertEqual(normalize_name("foo_Bar.baz"), "foo-bar-baz")
        self.assertEqual(normalize_name("a--b"), "a-b")

    def test_parse_requirement(self):
        self.assertEqual(parse_requirement("PyYAML==5.3.1"), ("PyYAML", "==5.3.1"))
        self.assertEqual(parse_requirement("requests[security]>=2.31"),
                         ("requests", ">=2.31"))
        self.assertEqual(parse_requirement("click>=8.0; python_version>'3.8'"),
                         ("click", ">=8.0"))
        self.assertEqual(parse_requirement("flask  # web"), ("flask", ""))
        self.assertIsNone(parse_requirement("# comment"))
        self.assertIsNone(parse_requirement("-r other.txt"))
        self.assertIsNone(parse_requirement("pkg @ https://example.com/pkg.tar.gz"))

    def test_exact_pin(self):
        self.assertEqual(exact_pin("==5.3.1"), "5.3.1")
        self.assertEqual(exact_pin(">=5.1,==5.3.1"), "5.3.1")
        self.assertIsNone(exact_pin(">=5.1"))
        self.assertIsNone(exact_pin(""))


class TestPyprojectAndRequirements(unittest.TestCase):
    def test_pyproject_project_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                '[project]\ndependencies = ["PyYAML>=5.1", "requests==2.31.0"]\n',
                encoding="utf-8")
            deps = read_pyproject_deps(root)
            by_key = {d.key: d for d in deps}
            self.assertEqual(by_key["pyyaml"].spec, ">=5.1")
            self.assertEqual(by_key["requests"].spec, "==2.31.0")

    def test_pyproject_poetry_dependencies_skip_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                '[tool.poetry.dependencies]\npython = "^3.11"\npyyaml = ">=5.1"\n',
                encoding="utf-8")
            deps = read_pyproject_deps(root)
            self.assertEqual([d.key for d in deps], ["pyyaml"])

    def test_requirements_follows_includes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "base.txt").write_text("requests==2.31.0\n", encoding="utf-8")
            (root / "requirements.txt").write_text(
                "-r base.txt\nPyYAML==5.3.1\n", encoding="utf-8")
            deps = read_requirements_file(root / "requirements.txt")
            self.assertEqual({d.key for d in deps}, {"requests", "pyyaml"})

    def test_lockfiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "poetry.lock").write_text(
                '[[package]]\nname = "pyyaml"\nversion = "5.3.1"\n',
                encoding="utf-8")
            (root / "Pipfile.lock").write_text(
                json.dumps({"default": {"requests": {"version": "==2.31.0"}}}),
                encoding="utf-8")
            found = read_lockfile_versions(root)
            self.assertEqual(found["pyyaml"], ("5.3.1", "poetry.lock"))
            self.assertEqual(found["requests"], ("2.31.0", "Pipfile.lock"))


class TestResolve(unittest.TestCase):
    def _project(self, tmp, pyproject="", requirements=""):
        root = Path(tmp)
        if pyproject:
            (root / "pyproject.toml").write_text(pyproject, encoding="utf-8")
        if requirements is not None:
            (root / "requirements.txt").write_text(requirements, encoding="utf-8")
        return root

    def test_requirements_pin_beats_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(
                tmp,
                pyproject='[project]\ndependencies = ["PyYAML>=5.1"]\n',
                requirements="PyYAML==5.3.1\n")
            with mock.patch("pyreach.deps.installed_version", return_value=None):
                deps, _ = resolve_dependencies(root)
            dep = next(d for d in deps if d.key == "pyyaml")
            self.assertEqual((dep.version, dep.version_source, dep.status),
                             ("5.3.1", "requirements", "pinned"))

    def test_requirements_pin_labelled_even_with_odd_filename(self):
        # Regression: the old code judged the pin's source by whether
        # the filename contained "requirements" — a --requirements
        # /tmp/demo-reqs.txt pin was mislabelled "pyproject" in the
        # live MkDocs scan-all run (19 Nov 2026).
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(
                tmp,
                pyproject='[project]\ndependencies = ["PyYAML>=5.1"]\n',
                requirements="")
            req = Path(tmp) / "demo-reqs.txt"
            req.write_text("PyYAML==5.3.1\n", encoding="utf-8")
            with mock.patch("pyreach.deps.installed_version", return_value=None):
                deps, _ = resolve_dependencies(root, requirements=str(req))
            dep = next(d for d in deps if d.key == "pyyaml")
            self.assertEqual((dep.version, dep.version_source),
                             ("5.3.1", "requirements"))

    def test_lockfile_resolves_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(
                tmp,
                pyproject='[project]\ndependencies = ["PyYAML>=5.1"]\n',
                requirements="")
            (root / "poetry.lock").write_text(
                '[[package]]\nname = "pyyaml"\nversion = "5.3.1"\n',
                encoding="utf-8")
            with mock.patch("pyreach.deps.installed_version", return_value=None):
                deps, _ = resolve_dependencies(root)
            dep = next(d for d in deps if d.key == "pyyaml")
            self.assertEqual((dep.version, dep.version_source),
                             ("5.3.1", "lockfile"))

    def test_installed_is_last_resort(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(
                tmp,
                pyproject='[project]\ndependencies = ["PyYAML>=5.1"]\n',
                requirements="")
            with mock.patch("pyreach.deps.installed_version",
                           return_value="6.0.2"):
                deps, _ = resolve_dependencies(root)
            dep = next(d for d in deps if d.key == "pyyaml")
            self.assertEqual((dep.version, dep.version_source),
                             ("6.0.2", "installed"))

    def test_range_only_is_skipped_never_guessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(
                tmp,
                pyproject='[project]\ndependencies = ["click>=8.0"]\n',
                requirements="")
            with mock.patch("pyreach.deps.installed_version", return_value=None):
                deps, notes = resolve_dependencies(root)
            dep = deps[0]
            self.assertEqual(dep.status, "skipped")
            self.assertIsNone(dep.version)
            self.assertIn("no exact version", dep.reason)
            self.assertIn("pin it", dep.reason)

    def test_no_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp, requirements="")
            deps, notes = resolve_dependencies(root)
            self.assertEqual(deps, [])
            self.assertTrue(any("no dependencies" in n for n in notes))

    def test_advisory_file_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            adv = Path(tmp)
            (adv / "pyyaml.json").write_text("[]", encoding="utf-8")
            self.assertEqual(advisory_file_for("PyYAML", adv), adv / "pyyaml.json")
            self.assertIsNone(advisory_file_for("requests", adv))


if __name__ == "__main__":
    unittest.main()
