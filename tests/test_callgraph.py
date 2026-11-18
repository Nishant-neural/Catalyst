import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pyreach.callgraph import build_graph
from pyreach.entrypoints import find_entrypoints
from pyreach.reach import analyze
from pyreach.advisory import load_advisories

ROOT = Path(__file__).resolve().parents[1]

def test_vuln_is_reachable():
    g = build_graph(ROOT / "fixtures" / "app_vuln")
    entries, _ = find_entrypoints(ROOT / "fixtures" / "app_vuln", g)
    advs = load_advisories(str(ROOT / "examples" / "advisory-sample.json"))
    results = analyze(advs, g, entries)
    assert results[0].verdict == "reachable", results

def test_safe_is_not_reachable():
    g = build_graph(ROOT / "fixtures" / "app_safe")
    entries, _ = find_entrypoints(ROOT / "fixtures" / "app_safe", g)
    advs = load_advisories(str(ROOT / "examples" / "advisory-sample.json"))
    results = analyze(advs, g, entries)
    assert results[0].verdict == "not_reachable", results

def test_dead_code_is_not_reachable():
    g = build_graph(ROOT / "fixtures" / "app_dead")
    entries, _ = find_entrypoints(ROOT / "fixtures" / "app_dead", g)
    advs = load_advisories(str(ROOT / "examples" / "advisory-sample.json"))
    results = analyze(advs, g, entries)
    assert results[0].verdict == "not_reachable", results

def test_getattr_is_uncertain():
    g = build_graph(ROOT / "fixtures" / "app_getattr")
    entries, _ = find_entrypoints(ROOT / "fixtures" / "app_getattr", g)
    advs = load_advisories(str(ROOT / "examples" / "advisory-sample.json"))
    results = analyze(advs, g, entries)
    assert results[0].verdict == "uncertain", results
