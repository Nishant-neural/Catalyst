import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pyreach.advisory import diff_to_functions, parse_unified_diff

DIFF = """--- a/yaml/__init__.py
+++ b/yaml/__init__.py
@@ -1,3 +1,5 @@
 def load(stream):
+    # fixed: check loader
+    return safe_load(stream)
"""

SRC = {"yaml/__init__.py": "def load(stream):\n    return safe_load(stream)\n\ndef safe_load(stream):\n    return {}\n"}


class TestAdvisory(unittest.TestCase):
    # Plain functions, not TestCase methods, so `python -m unittest`
    # skipped these 2 tests while pytest ran them. Fixed 19 Nov 2026.
    def test_diff_to_functions(self):
        fns = diff_to_functions(DIFF, SRC, commit="abc123")
        self.assertTrue(any(f.qualified.endswith("load") for f in fns), fns)
        self.assertIn(fns[0].confidence, ("high", "medium"))

    def test_parse_diff(self):
        changed = parse_unified_diff(DIFF)
        self.assertIn("yaml/__init__.py", changed)


if __name__ == "__main__":
    unittest.main()
