"""LLM status diagnosis: WHY a call returned nothing, not just that it did.

No network in any test — requests.post is mocked, and the no-key test
runs with a scrubbed environment. The old resolve_with_llm swallowed
every failure as None (no key / timeout / 429 / bad JSON all identical);
resolve_with_llm_status must distinguish them, and the explainer must
record the kind on every explanation.
"""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests

import pyreach.cli as cli_mod
import pyreach.resolver as res
from pyreach.resolver import _safe_detail, resolve_with_llm, resolve_with_llm_status

BASE = Path(__file__).resolve().parent.parent


class _FakeResp:
    """A requests.Response stand-in: status, json body, text."""

    def __init__(self, status=200, body=None, text="", json_raises=False):
        self.status_code = status
        self._body = body
        self.text = text
        self._json_raises = json_raises

    def raise_for_status(self):
        if self.status_code >= 400:
            err = requests.exceptions.HTTPError(f"{self.status_code} error")
            err.response = self
            raise err

    def json(self):
        if self._json_raises:
            raise json.JSONDecodeError("Expecting value", "", 0)
        return self._body


def _ok_body(content='{"ok": true}'):
    return {"choices": [{"message": {"content": content}}]}


class _DictCache:
    """Minimal stand-in for pyreach.cache.Cache (get/put only)."""

    def __init__(self):
        self.store = {}
        self.hits = self.misses = 0

    def get(self, key):
        if key in self.store:
            self.hits += 1
            return self.store[key]
        self.misses += 1
        return None

    def put(self, key, value):
        self.store[key] = value


class TestResolveStatus(unittest.TestCase):
    def setUp(self):
        # Every test here supplies its own key via the env, except the
        # no-key test, which scrubs it. A real key must never leak in.
        self._env = mock.patch.dict(
            os.environ, {"OPENROUTER_API_KEY": "sk-test-key"}, clear=True)
        self._env.start()

    def tearDown(self):
        self._env.stop()

    def test_no_key(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("pyreach.dotenv.load_dotenv_file", return_value={}):
            ans, status = resolve_with_llm_status("hi")
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "no_key")
        self.assertIn(".env", status["detail"])

    def test_no_requests(self):
        with mock.patch.dict(sys.modules, {"requests": None}):
            ans, status = resolve_with_llm_status("hi")
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "no_requests")
        self.assertIn("pip install requests", status["detail"])

    def test_timeout(self):
        with mock.patch("requests.post",
                        side_effect=requests.exceptions.Timeout("timed out")):
            ans, status = resolve_with_llm_status("hi")
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "timeout")
        self.assertIn("60s", status["detail"])

    def test_http_429_is_rate_limited_not_http_error(self):
        with mock.patch("requests.post",
                        return_value=_FakeResp(status=429, text="slow down")):
            ans, status = resolve_with_llm_status("hi")
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "rate_limited")
        self.assertIn("429", status["detail"])

    def test_http_500_is_http_error(self):
        with mock.patch("requests.post",
                        return_value=_FakeResp(status=500, text="boom")):
            ans, status = resolve_with_llm_status("hi")
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "http_error")
        self.assertIn("HTTP 500", status["detail"])

    def test_bad_json_prose_reply(self):
        with mock.patch("requests.post", return_value=_FakeResp(
                body=_ok_body("hello, I am an LLM, not JSON"))):
            ans, status = resolve_with_llm_status("hi")
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "bad_json")

    def test_bad_json_wrong_shape(self):
        with mock.patch("requests.post",
                        return_value=_FakeResp(body={"nope": 1})):
            ans, status = resolve_with_llm_status("hi")
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "bad_json")

    def test_bad_json_unparseable_body(self):
        with mock.patch("requests.post",
                        return_value=_FakeResp(json_raises=True)):
            ans, status = resolve_with_llm_status("hi")
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "bad_json")

    def test_network_error(self):
        with mock.patch(
                "requests.post",
                side_effect=requests.exceptions.ConnectionError("dns fail")):
            ans, status = resolve_with_llm_status("hi")
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "network_error")

    def test_ok_answer_and_cache_hit_makes_no_second_call(self):
        cache = _DictCache()
        with mock.patch("requests.post", return_value=_FakeResp(
                body=_ok_body('{"can_reach": "unknown"}'))) as post:
            ans1, s1 = resolve_with_llm_status("hi", cache=cache)
            ans2, s2 = resolve_with_llm_status("hi", cache=cache)
        self.assertEqual(ans1, {"can_reach": "unknown"})
        self.assertEqual(s1["kind"], "ok")
        self.assertEqual(ans2, ans1)
        self.assertEqual(s2["detail"], "cached answer")
        self.assertEqual(post.call_count, 1)
        # Temperature 0, and the key goes in the header, not the body.
        _, kwargs = post.call_args
        self.assertEqual(kwargs["json"]["temperature"], 0)
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer sk-test-key")

    def test_wrapper_still_returns_none_on_failure(self):
        # Backwards compatibility: existing callers of resolve_with_llm
        # see exactly the old behaviour (None on any failure).
        with mock.patch("requests.post",
                        side_effect=requests.exceptions.Timeout("timed out")):
            self.assertIsNone(resolve_with_llm("hi"))

    def test_safe_detail_redacts_keys_and_truncates(self):
        detail = _safe_detail("boom sk-or-v1-abcdef1234567890 " + "x" * 200)
        self.assertNotIn("sk-or-v1-abcdef1234567890", detail)
        self.assertIn("[REDACTED]", detail)
        self.assertLessEqual(len(detail), 120)
        self.assertNotIn("\n", _safe_detail("a\nb\nc"))


def _delisted_404(slug="openai/gpt-oss-20b"):
    """The exact OpenRouter 404 from 19 Nov 2026: the :free slug is gone,
    only the paid slug remains. This is the one 404 that may trigger a
    fallback; any other 404 must not."""
    return _FakeResp(
        status=404,
        text='{"error":{"message":"This model is unavailable for free. '
             f'The paid version is available now - use this slug instead: {slug}"}}')


class TestFreeModelFallback(unittest.TestCase):
    def setUp(self):
        self._env = mock.patch.dict(
            os.environ, {"OPENROUTER_API_KEY": "sk-test-key"}, clear=True)
        self._env.start()

    def tearDown(self):
        self._env.stop()

    def test_delisted_default_falls_back_to_second_model(self):
        with mock.patch("requests.post", side_effect=[
                _delisted_404(), _FakeResp(body=_ok_body('{"can_reach": "unknown"}')),
        ]) as post:
            ans, status = resolve_with_llm_status("hi")
        self.assertEqual(ans, {"can_reach": "unknown"})
        self.assertEqual(status["kind"], "ok")
        self.assertEqual(status["model"], "google/gemma-4-31b-it:free")
        self.assertEqual(post.call_count, 2)
        self.assertEqual(post.call_args_list[0][1]["json"]["model"],
                         "cohere/north-mini-code:free")
        self.assertEqual(post.call_args_list[1][1]["json"]["model"],
                         "google/gemma-4-31b-it:free")

    def test_all_fallbacks_delisted_returns_last_model(self):
        with mock.patch("requests.post", side_effect=[
                _delisted_404("cohere/north-mini-code"),
                _delisted_404("google/gemma-4-31b-it"),
                _delisted_404("nvidia/nemotron-3.5-lightning"),
        ]) as post:
            ans, status = resolve_with_llm_status("hi")
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "http_error")
        self.assertIn("404", status["detail"])
        self.assertEqual(status["model"], "nvidia/nemotron-3.5-lightning:free")
        self.assertEqual(post.call_count, 3)

    def test_429_does_not_trigger_fallback(self):
        with mock.patch("requests.post",
                        return_value=_FakeResp(status=429, text="slow down")) as post:
            ans, status = resolve_with_llm_status("hi")
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "rate_limited")
        self.assertEqual(post.call_count, 1)

    def test_other_404_does_not_trigger_fallback(self):
        with mock.patch("requests.post",
                        return_value=_FakeResp(status=404, text="not found")) as post:
            ans, status = resolve_with_llm_status("hi")
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "http_error")
        self.assertEqual(post.call_count, 1)

    def test_explicit_model_never_falls_back(self):
        # An explicit --model is the user's choice, not ours to override:
        # even a delisted 404 on it ends the call after one attempt.
        with mock.patch("requests.post",
                        side_effect=[_delisted_404()]) as post:
            ans, status = resolve_with_llm_status(
                "hi", model="openai/gpt-oss-20b:free")
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "http_error")
        self.assertEqual(status["model"], "openai/gpt-oss-20b:free")
        self.assertEqual(post.call_count, 1)

    def test_allow_fallback_false_never_falls_back(self):
        with mock.patch("requests.post",
                        side_effect=[_delisted_404()]) as post:
            ans, status = resolve_with_llm_status("hi", allow_fallback=False)
        self.assertIsNone(ans)
        self.assertEqual(status["kind"], "http_error")
        self.assertEqual(post.call_count, 1)

    def test_fallback_does_not_poison_default_cache_entry(self):
        # The fallback hit is cached under the fallback model's key
        # only; a later call for the default model must not return it.
        cache = _DictCache()
        with mock.patch("requests.post", side_effect=[
                _delisted_404(), _FakeResp(body=_ok_body('{"can_reach": "unknown"}')),
        ]) as post:
            ans, status = resolve_with_llm_status("hi", cache=cache)
        self.assertEqual(status["model"], "google/gemma-4-31b-it:free")
        import hashlib
        default_key = ("llm:cohere/north-mini-code:free:"
                       + hashlib.sha256(b"hi").hexdigest()[:16])
        self.assertNotIn(default_key, cache.store)
        # And a repeat call re-uses the fallback model's cached answer
        # with no new network call.
        with mock.patch("requests.post") as post2:
            ans2, status2 = resolve_with_llm_status("hi", cache=cache)
        self.assertEqual(ans2, ans)
        self.assertEqual(status2["model"], "google/gemma-4-31b-it:free")
        self.assertEqual(post2.call_count, 0)


class TestExplainerSummary(unittest.TestCase):
    def test_mixed_counts(self):
        exps = [
            {"vulnerable_function": "a", "llm_status": "ok",
             "llm_explanation": "[llm-explainer] x", "llm_rejected": False},
            {"vulnerable_function": "b", "llm_status": "rejected",
             "llm_explanation": None, "llm_rejected": True},
            {"vulnerable_function": "c", "llm_status": "timeout",
             "llm_explanation": None, "llm_rejected": False},
            {"vulnerable_function": "d", "llm_status": "not_called",
             "llm_explanation": None, "llm_rejected": False},
        ]
        self.assertEqual(
            cli_mod.llm_explainer_summary(exps),
            "LLM explainer: 3 called, 1 accepted, 1 rejected, 1 unavailable (timeout)")

    def test_all_not_called(self):
        exps = [{"vulnerable_function": "a", "llm_status": "not_called",
                 "llm_explanation": None, "llm_rejected": False}]
        self.assertEqual(
            cli_mod.llm_explainer_summary(exps),
            "LLM explainer: 0 called, 0 accepted, 0 rejected, 0 unavailable")


class TestLlmTestCommand(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_mod.main(argv)
        return code, buf.getvalue()

    def test_no_key_exit_1_names_the_kind_and_prints_no_key(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("pyreach.cli.load_dotenv_file", return_value={}):
            code, out = self._run(["llm-test"])
        self.assertEqual(code, 1)
        self.assertIn("no_key", out)
        self.assertIn("LLM key: missing", out)
        self.assertNotIn("sk-", out)

    def test_ok_exit_0(self):
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-key"},
                             clear=True), \
                mock.patch("pyreach.cli.resolve_with_llm_status",
                           return_value=({"ok": True}, {"kind": "ok", "detail": ""})):
            code, out = self._run(["llm-test"])
        self.assertEqual(code, 0)
        self.assertIn("LLM test: ok in", out)

    def test_wrong_shape_answer_is_bad_json(self):
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-key"},
                             clear=True), \
                mock.patch("pyreach.cli.resolve_with_llm_status",
                           return_value=({"something": "else"},
                                         {"kind": "ok", "detail": ""})):
            code, out = self._run(["llm-test"])
        self.assertEqual(code, 1)
        self.assertIn("bad_json", out)

    def test_no_model_flag_uses_default_with_fallback(self):
        # CLI-level: no --model -> default model, fallback allowed.
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-key"},
                             clear=True), \
                mock.patch("pyreach.cli.resolve_with_llm_status",
                           return_value=({"ok": True},
                                         {"kind": "ok", "detail": "",
                                          "model": "cohere/north-mini-code:free"})) as call:
            code, out = self._run(["llm-test"])
        self.assertEqual(code, 0)
        _, kwargs = call.call_args
        self.assertEqual(kwargs["model"], res.DEFAULT_MODEL)
        self.assertTrue(kwargs["allow_fallback"])
        self.assertIn("model cohere/north-mini-code:free", out)

    def test_explicit_model_flag_disables_fallback(self):
        # CLI-level: explicit --model -> exactly that model, no fallback,
        # even if it is delisted. The choice is the user's, not ours.
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-key"},
                             clear=True), \
                mock.patch("pyreach.cli.resolve_with_llm_status",
                           return_value=(None, {"kind": "http_error",
                                                "detail": "HTTP 404",
                                                "model": "openai/gpt-oss-20b:free"})) as call:
            code, out = self._run(["llm-test", "--model",
                                   "openai/gpt-oss-20b:free"])
        self.assertEqual(code, 1)
        _, kwargs = call.call_args
        self.assertEqual(kwargs["model"], "openai/gpt-oss-20b:free")
        self.assertFalse(kwargs["allow_fallback"])
        self.assertIn("http_error", out)


if __name__ == "__main__":
    unittest.main()
