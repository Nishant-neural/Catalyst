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

    def test_src_prefix_stripped_from_qualified_names(self):
        # 19 Nov 2026: repos keep code under src/ (jinja2, werkzeug,
        # anyio) or lib/ (PyYAML); the installed package has no such
        # prefix. A src.-prefixed candidate never matched an imported
        # module, so src.werkzeug.security.safe_join was classified
        # library-internal even though Flask imports werkzeug.
        diff = """--- a/src/jinja2/filters.py
+++ b/src/jinja2/filters.py
@@ -1,3 +1,5 @@
 def do_attr():
+    # fixed: block format
+    return None
"""
        src = {"src/jinja2/filters.py": "def do_attr():\n    return None\n"}
        fns = diff_to_functions(diff, src, commit="abc123")
        self.assertTrue(any(f.qualified == "jinja2.filters.do_attr" for f in fns), fns)
        self.assertFalse(any(f.qualified.startswith("src.") for f in fns), fns)
        src_lib = {"lib/yaml/__init__.py": "def load(s):\n    return None\n"}
        diff_lib2 = """--- a/lib/yaml/__init__.py
+++ b/lib/yaml/__init__.py
@@ -1,3 +1,5 @@
 def load(s):
+    # fixed
+    return None
"""
        fns2 = diff_to_functions(diff_lib2, src_lib, commit="abc123")
        self.assertTrue(any(f.qualified == "yaml.load" for f in fns2), fns2)


if __name__ == "__main__":
    unittest.main()
