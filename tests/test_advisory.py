import sys
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

def test_diff_to_functions():
    fns = diff_to_functions(DIFF, SRC, commit="abc123")
    assert any(f.qualified.endswith("load") for f in fns), fns
    assert fns[0].confidence in ("high", "medium")

def test_parse_diff():
    changed = parse_unified_diff(DIFF)
    assert "yaml/__init__.py" in changed
