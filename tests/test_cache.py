"""Tests for the Windows LLM-cache fix (19 Nov 2026, mkdocs-llm-2.json).

The LLM cache key is "llm:<model>:<sha16>" and the model slug contains
":" (cohere/north-mini-code:free). ":" is illegal in a Windows filename,
so every LLM cache put on Nishant's machine raised OSError Errno 22 —
and the resolver's generic except then reported that local error as
"network_error", so the LLM looked dead-network when it had never even
been reached (the failure happens when SAVING the model's answer, after
a successful POST). Linux allows ":" in filenames, so the VM never
caught it. These tests pin the fix: no Windows-illegal character may
survive in a cache filename, and a cache failure must never fail a
call — a cache is best-effort, not storage.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pyreach.cache import Cache
from pyreach.resolver import _attempt_llm_call, _cached_answer

WINDOWS_ILLEGAL = set('<>:"/\\|?*')


class TestCachePathSanitisation(unittest.TestCase):
    def test_llm_key_has_no_windows_illegal_chars(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = Cache(tmp)
            name = c._path("llm:cohere/north-mini-code:free:56f5314bee70d936").name
            self.assertFalse(set(name) & WINDOWS_ILLEGAL,
                             f"illegal chars left in cache filename: {name}")
            self.assertFalse(name.endswith("."))
            self.assertFalse(name.endswith(" "))

    def test_package_key_still_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = Cache(tmp)
            name = c._path("PyYAML@5.3.1-abc-def-pyreach-ast-0.1.0").name
            self.assertFalse(set(name) & WINDOWS_ILLEGAL)

    def test_round_trip_with_colon_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = Cache(tmp)
            key = "llm:cohere/north-mini-code:free:56f5314bee70d936"
            c.put(key, {"answer": {"can_reach": False}})
            self.assertEqual(c.get(key), {"answer": {"can_reach": False}})

    def test_get_missing_key_is_a_miss_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = Cache(tmp)
            self.assertIsNone(c.get("llm:nope:0000000000000000"))

    def test_get_corrupt_file_is_a_miss_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = Cache(tmp)
            c._path("llm:cohere/north-mini-code:free:deadbeef").write_text(
                "{not json", encoding="utf-8")
            self.assertIsNone(c.get("llm:cohere/north-mini-code:free:deadbeef"))


class _FailingCache:
    """A cache whose every operation raises OSError, as the Windows
    filename bug did. Nothing using it may ever report a network error."""

    def get(self, key):
        raise OSError(22, "Invalid argument")

    def put(self, key, data):
        raise OSError(22, "Invalid argument")


class TestCacheFailureNeverLooksLikeNetwork(unittest.TestCase):
    def test_cached_answer_tolerates_failing_cache(self):
        self.assertIsNone(_cached_answer("prompt", "m", _FailingCache()))

    def test_attempt_still_returns_answer_when_cache_put_fails(self):
        class Resp:
            status_code = 200
            text = '{"choices": [{"message": {"content": "{\\"can_reach\\": false}"}}]}'

            def raise_for_status(self):
                return None

            def json(self):
                return json.loads(self.text)

        with mock.patch("requests.post", return_value=Resp()):
            ans, status, delisted = _attempt_llm_call(
                "prompt", "cohere/north-mini-code:free", "sk-or-test-key",
                cache=_FailingCache())
        self.assertEqual(ans, {"can_reach": False})
        self.assertEqual(status["kind"], "ok")
        self.assertFalse(delisted)


if __name__ == "__main__":
    unittest.main()
