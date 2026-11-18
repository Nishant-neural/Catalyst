"""Tests for the .env auto-enable rule (19 Nov 2026).

Putting a key in .env IS asking for the LLM, so a plain `scan` must
use it — no --with-llm flag needed. --no-llm always wins.
"""
import unittest

from pyreach.cli import should_use_llm


class TestShouldUseLlm(unittest.TestCase):
    def test_no_key_no_flag_stays_off(self):
        self.assertFalse(should_use_llm(False, False, False))

    def test_key_in_dotenv_auto_enables_plain_scan(self):
        # This is the case the user asked for: .env present, no flag.
        self.assertTrue(should_use_llm(False, False, True))

    def test_with_llm_flag_enables_even_without_key(self):
        # Flag on, key missing: resolver is allowed to try (it will
        # find no key and stay uncertain — see the CLI warning).
        self.assertTrue(should_use_llm(True, False, False))

    def test_no_llm_always_wins(self):
        self.assertFalse(should_use_llm(True, True, True))
        self.assertFalse(should_use_llm(False, True, True))
        self.assertFalse(should_use_llm(True, True, False))


if __name__ == "__main__":
    unittest.main()
