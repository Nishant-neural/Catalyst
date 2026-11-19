"""Tests for pyreach/dotenv.py — the .env loader (19 Nov 2026).

All keys here are fake (sk-or-test-...). No real key is ever in a test.
The loader must never print a value; these tests assert on the summary
dict (path / loaded / skipped), never on os.environ values beyond
checking the key was set to the fake test value.
"""
import os
import unittest
from pathlib import Path
from unittest import mock

from pyreach.dotenv import (find_dotenv_file, load_dotenv_file,
                            parse_dotenv_text)


class TestParseDotenvText(unittest.TestCase):
    def test_plain_quoted_export_and_comment(self):
        text = (
            "# a comment\n"
            "OPENROUTER_API_KEY=sk-or-test-plain\n"
            "GROQ_API_KEY=\"gsk-test-quoted\"\n"
            "export LLM_BASE_URL='https://example.test/v1'\n"
            "\n"
            "OPENROUTER_API_KEY=sk-or-test-second-should-not-win\n"
        )
        # Duplicate key: last one wins in parsing (dict), the loader's
        # no-override rule is about env vars, not duplicate lines.
        parsed = parse_dotenv_text(text)
        self.assertEqual(parsed["OPENROUTER_API_KEY"], "sk-or-test-second-should-not-win")
        self.assertEqual(parsed["GROQ_API_KEY"], "gsk-test-quoted")
        self.assertEqual(parsed["LLM_BASE_URL"], "https://example.test/v1")

    def test_unquoted_inline_comment_stripped_quoted_kept(self):
        parsed = parse_dotenv_text(
            "OPENROUTER_API_KEY=sk-or-test-x # my key\n"
            "GROQ_API_KEY=\"gsk-a # b\"\n"
        )
        self.assertEqual(parsed["OPENROUTER_API_KEY"], "sk-or-test-x")
        self.assertEqual(parsed["GROQ_API_KEY"], "gsk-a # b")

    def test_unknown_keys_and_bad_lines_ignored(self):
        parsed = parse_dotenv_text(
            "PATH=/usr/bin:/bin\n"
            "PYTHONPATH=/tmp/evil\n"
            "this line has no equals\n"
            "OPENROUTER_API_KEY=sk-or-test-ok\n"
        )
        self.assertEqual(parsed, {"OPENROUTER_API_KEY": "sk-or-test-ok"})

    def test_empty_text(self):
        self.assertEqual(parse_dotenv_text(""), {})
        self.assertEqual(parse_dotenv_text("# only comments\n\n"), {})


class TestLoadDotenvFile(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(__import__("tempfile").mkdtemp(prefix="pyreach-dotenv-"))
        # Keep the real environment out of the way for these tests.
        self._patcher = mock.patch.dict(os.environ, {}, clear=False)
        self._patcher.start()
        for k in ("OPENROUTER_API_KEY", "GROQ_API_KEY", "LLM_BASE_URL"):
            os.environ.pop(k, None)

    def tearDown(self):
        self._patcher.stop()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name=".env", text="OPENROUTER_API_KEY=sk-or-test-abc\n"):
        p = self.tmp / name
        p.write_text(text, encoding="utf-8")
        return p

    def test_loads_key_from_file(self):
        p = self._write()
        summary = load_dotenv_file(path=p)
        self.assertEqual(summary["loaded"], ["OPENROUTER_API_KEY"])
        self.assertEqual(os.environ["OPENROUTER_API_KEY"], "sk-or-test-abc")
        self.assertEqual(summary["path"], str(p))

    def test_real_env_var_wins_no_override(self):
        os.environ["OPENROUTER_API_KEY"] = "sk-or-test-from-env"
        p = self._write()
        summary = load_dotenv_file(path=p)
        self.assertEqual(summary["loaded"], [])
        self.assertEqual(summary["skipped"], ["OPENROUTER_API_KEY"])
        self.assertEqual(os.environ["OPENROUTER_API_KEY"], "sk-or-test-from-env")

    def test_missing_explicit_file_reports_error_not_crash(self):
        # An explicitly named file that does not exist IS worth a
        # warning (the user asked for that file); it must still not
        # crash the scan — loaded is empty and there is no exception.
        summary = load_dotenv_file(path=self.tmp / ".env")
        self.assertEqual(summary["path"], str(self.tmp / ".env"))
        self.assertEqual(summary["loaded"], [])
        self.assertIn("error", summary)

    def test_no_dotenv_anywhere_is_silent(self):
        # Auto-discovery with no .env anywhere: no error, no path.
        # chdir into the fresh tmp dir so the walk-up finds nothing.
        import os as _os
        old = _os.getcwd()
        try:
            _os.chdir(self.tmp)
            summary = load_dotenv_file()
        finally:
            _os.chdir(old)
        self.assertEqual(summary, {"path": None, "loaded": [], "skipped": []})

    def test_find_in_project_dir(self):
        # A .env in the scanned project is deliberately NOT trusted
        # (19 Nov 2026, ChatGPT Phase 9 review §4C): it could redirect
        # LLM requests carrying the user's key. Only the caller's own
        # .env (cwd walk-up) or an explicit file counts. The cwd here
        # is a different tree from the project, so the walk-up finds
        # nothing and the project .env must not be returned.
        import tempfile as _tf
        with _tf.TemporaryDirectory() as other:
            proj = Path(other) / "proj"
            proj.mkdir()
            (proj / ".env").write_text(
                "LLM_BASE_URL=http://127.0.0.1:9/evil\n")
            cwd = Path(other) / "elsewhere"
            cwd.mkdir()
            old = os.getcwd()
            try:
                os.chdir(cwd)
                self.assertIsNone(find_dotenv_file(project=proj))
            finally:
                os.chdir(old)

    def test_explicit_env_file_var(self):
        p = self._write()
        with mock.patch.dict(os.environ, {"PYREACH_ENV_FILE": str(p)}):
            self.assertEqual(find_dotenv_file(start=self.tmp), p)


if __name__ == "__main__":
    unittest.main()
