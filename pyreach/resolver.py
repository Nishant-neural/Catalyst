"""Phase 4: LLM resolver for UNCERTAIN dynamic cases only.

Deterministic core first. The LLM only sees one uncertain call site
at a time, with grounded context. It proposes, the verifier decides.
If verification fails, stay UNCERTAIN. Never downgrade a deterministic
REACHABLE verdict.

Model: small open-weight, gpt-oss 20B or Llama 3.1 8B, via a free provider
(OpenRouter / Groq). Temperature 0. No API key -> resolver is skipped,
verdicts stay uncertain. That is safe.
"""
from __future__ import annotations

import json
import os
import re

DEFAULT_MODEL = "openai/gpt-oss-20b"
CONFIDENCE_THRESHOLD = 0.8  # starting value, tune on organisers' fixtures


def build_prompt(call_site_source: str, candidates: list[str],
                 string_literals: list[str], vulnerable: list[str],
                 file: str, line: int) -> str:
    """Copy-pasteable prompt. One call site, 30-50 lines, strict JSON out."""
    return f"""You are a Python static-analysis helper. Answer ONLY with JSON.

Task: can this dynamic call resolve to a vulnerable function?
File: {file}:{line}
Code:
```
{call_site_source}
```

Functions that actually exist in this module (from AST, pick ONLY from this list):
{json.dumps(candidates, indent=2)}

String literals in this file:
{json.dumps(string_literals, indent=2)}

Vulnerable functions for this advisory:
{json.dumps(vulnerable, indent=2)}

Rules:
- Trace where the name / module string comes from. Literal? Loop over literals? Config / user input / env?
- If the value is a literal or a loop over literals, list the exact possible values.
- If the value comes from config, user input, env, or an unknown source, answer can_reach: "unknown".
- Cite line numbers that actually exist in the code above.

Return strict JSON only:
{{"can_reach": true|false|"unknown", "possible_values": ["..."], "vulnerable_hit": "qualified.name or null", "reason": "one sentence", "evidence_lines": [12, 13], "confidence": 0.0}}
Temperature 0. No extra text.
"""


def verify_answer(answer: dict, symbol_table: set[str], source_text: str,
                  deterministic_verdict: str,
                  vulnerable: list[str] | None = None) -> tuple[bool, list[str]]:
    """10-rule deterministic verifier. Returns (ok, failures).

    1. answer is a dict with required keys
    2. can_reach in {true, false, "unknown"}
    3. vulnerable_hit, if set, is in symbol_table or in vulnerable list
    4. possible_values are all strings, and every value that is a function
       name must be in symbol_table
    5. evidence_lines are ints inside the source file line range
    6. every cited line, when read from source_text, contains a string
       or name mentioned in possible_values (byte-match check)
    7. confidence is a number 0..1, and >= 0.8 to upgrade from uncertain
    8. never downgrade a deterministic reachable verdict
    9. if can_reach is true, vulnerable_hit must be non-null
    10. if can_reach is false, possible_values must be non-empty and none
        of them may be a vulnerable function
    """
    failures: list[str] = []
    if not isinstance(answer, dict):
        return False, ["answer is not a JSON object"]
    for k in ("can_reach", "possible_values", "vulnerable_hit", "reason", "evidence_lines", "confidence"):
        if k not in answer:
            failures.append(f"missing key: {k}")
    if failures:
        return False, failures
    cr = answer["can_reach"]
    # A real bool, not 1/0: in Python 1 == True, so `can_reach: 1` used
    # to pass as true. That is a verifier hole, not a quirk.
    if not (isinstance(cr, bool) or cr == "unknown"):
        failures.append("can_reach must be true, false, or 'unknown' (a bool, not 1/0)")
    if deterministic_verdict == "reachable" and cr is False:
        failures.append("never downgrade a deterministic reachable verdict")
    conf = answer.get("confidence")
    if not isinstance(conf, (int, float)) or isinstance(conf, bool) or not 0 <= conf <= 1:
        failures.append("confidence must be a number 0..1")
    elif conf < CONFIDENCE_THRESHOLD and answer["can_reach"] in (True, False):
        failures.append(f"confidence {conf} below threshold {CONFIDENCE_THRESHOLD}, stay uncertain")
    hit = answer.get("vulnerable_hit")
    if answer["can_reach"] is True and not hit:
        failures.append("can_reach true but vulnerable_hit is null")
    if hit and hit not in symbol_table:
        failures.append(f"vulnerable_hit {hit} not in AST symbol table")
    vals = answer.get("possible_values", [])
    if not isinstance(vals, list) or not all(isinstance(v, str) for v in vals):
        failures.append("possible_values must be a list of strings")
    ev = answer.get("evidence_lines", [])
    # A true/false verdict with no cited line is not a verdict.
    if cr in (True, False) and not ev:
        failures.append("a true/false verdict needs at least one evidence line")
    lines = source_text.splitlines()
    for ln in ev:
        if not isinstance(ln, int) or isinstance(ln, bool) or not 1 <= ln <= len(lines):
            failures.append(f"evidence line {ln} out of range")
        else:
            text = lines[ln - 1]
            if vals and not any(v in text for v in vals):
                failures.append(f"evidence line {ln} does not contain any possible value")
    if cr is False:
        if not vals:
            failures.append("can_reach false needs non-empty possible_values")
        # Phase 4 fix: the second half of rule 10 was NOT checked before.
        # An LLM could answer can_reach false with possible_values
        # ["load"] and pass. Now it fails.
        if vulnerable:
            vuln_simple = {v.split(".")[-1] for v in vulnerable}
            bad = [v for v in vals if v in vuln_simple or v in vulnerable]
            if bad:
                failures.append(f"can_reach false but possible_values contain vulnerable {bad}")
    return (len(failures) == 0), failures


def extract_string_literals(source: str) -> list[str]:
    """All string literals in a file, for grounding the LLM."""
    return sorted(set(re.findall(r"""['\"]([^'\"\n]{1,64})['\"]""", source)))


def constant_propagate_getattr(source: str, call_line: int) -> list[str] | None:
    """Deterministic constant propagation — ChatGPT fix, run BEFORE any LLM.

    Track, in the same function as the getattr call, assignments like:
      name = "load"                    -> ["load"]
      for name in ["safe_load", "dump"]: -> ["safe_load", "dump"]
    Return None (unknown) if the value comes from config / input / env /
    a function call / any non-literal source. The LLM is only needed
    for cases this cannot resolve. LLM confidence must never
    independently upgrade a verdict — see verify_answer().

    Phase 4 fixes over the base version:
    - Source order, not ast.walk order. ast.walk is breadth-first, so
      `name = "load"` followed by `name = "safe_load"` was resolved
      in random order. Now assignments are processed by lineno.
    - Branches union, sequential assignments overwrite. `if x: name =
      "load" else: name = "safe_load"` gives ["load", "safe_load"]
      (either branch can run, so fail-closed keeps both). But a plain
      later assignment `name = "safe_load"` overwrites the earlier one.
    - String concat: name = "safe_" + "load" -> ["safe_load"].
    - Variable to variable: other = name copies name's values.
    - importlib.import_module("yaml") as the first arg is also resolved:
      the call site's module string is what the LLM prompt needs.
    """
    import ast as _ast
    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return None
    # Innermost function containing call_line (not the first in walk order)
    target_fn = None
    best_span = None
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if node.lineno <= call_line <= end:
                span = end - node.lineno
                if best_span is None or span < best_span:
                    best_span, target_fn = span, node
    if target_fn is None:
        return None

    def eval_str(node, values):
        """Possible string values of an expression, or None if unknown."""
        if isinstance(node, _ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, _ast.Name):
            v = values.get(node.id)
            return list(v) if v is not None else None
        if isinstance(node, _ast.BinOp) and isinstance(node.op, _ast.Add):
            left, right = eval_str(node.left, values), eval_str(node.right, values)
            if left is None or right is None:
                return None
            return [a + b for a in left for b in right]
        if isinstance(node, _ast.List):
            vals = []
            for e in node.elts:
                one = eval_str(e, values)
                if one is None:
                    return None
                vals.extend(one)
            return vals
        return None  # config / input / call / subscript / unknown

    # Collect assignments before the call, in source order. Each entry is
    # (lineno, var, expression, conditional). Conditional means the
    # assignment sits inside an If/For/While/Try — it may or may not run.
    # Values are evaluated while replaying in lineno order, so a later
    # assignment can use an earlier variable's values.
    raw_events: list[tuple[int, str, _ast.AST, bool]] = []

    def collect_raw(node, conditional: bool):
        for child in _ast.iter_child_nodes(node):
            if isinstance(child, (_ast.If, _ast.For, _ast.While, _ast.Try,
                                 _ast.AsyncFor, _ast.With, _ast.AsyncWith)):
                # The loop variable itself is an assignment: for name in
                # ["safe_load", "dump"] gives name those values.
                if isinstance(child, (_ast.For, _ast.AsyncFor)) and child.lineno < call_line:
                    if isinstance(child.target, _ast.Name) and isinstance(child.iter, _ast.List):
                        raw_events.append((child.lineno, child.target.id, child.iter, True))
                collect_raw(child, True)
            elif isinstance(child, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
                continue
            else:
                if isinstance(child, _ast.Assign) and child.lineno < call_line:
                    if len(child.targets) == 1 and isinstance(child.targets[0], _ast.Name):
                        raw_events.append((child.lineno, child.targets[0].id, child.value, conditional))
                collect_raw(child, conditional)

    collect_raw(target_fn, False)
    values: dict[str, list[str] | None] = {}
    for _ln, var, expr, conditional in sorted(raw_events, key=lambda e: e[0]):
        vals = eval_str(expr, values)
        if conditional:
            if var in values and values[var] is not None and vals is not None:
                values[var] = sorted(set(values[var]) | set(vals))
            elif vals is None:
                values[var] = None
            else:
                values[var] = vals
        else:
            values[var] = vals  # unconditional: last one wins

    # Find the dynamic call on call_line: getattr(obj, name) or
    # importlib.import_module(name). Return the possible values of the
    # name/module argument, or None if it cannot be determined.
    for node in _ast.walk(target_fn):
        if isinstance(node, _ast.Call) and node.lineno == call_line:
            func = node.func
            if isinstance(func, _ast.Name) and func.id == "getattr" and len(node.args) >= 2:
                return eval_str(node.args[1], values)
            if isinstance(func, _ast.Attribute) and func.attr == "import_module" and node.args:
                return eval_str(node.args[0], values)
    return None


def resolve_with_llm(prompt: str, api_key: str | None = None,
                     model: str = DEFAULT_MODEL, cache=None) -> dict | None:
    """Call a free OpenRouter-compatible endpoint. Returns parsed JSON or None.

    Set OPENROUTER_API_KEY or GROQ_API_KEY. No key -> None (stay uncertain).
    This function is intentionally small; swap the endpoint in one place.
    Phase 4: answers are cached by (model, sha256(prompt)) in the same
    .reachcache as Phase 3, so a re-scan does not re-spend an LLM call.
    The cache key includes the model, so a model change is a miss.
    """
    import hashlib
    if cache is not None:
        key = f"llm:{model}:{hashlib.sha256(prompt.encode()).hexdigest()[:16]}"
        hit = cache.get(key)
        if hit is not None:
            return hit.get("answer")
    key = api_key or os.environ.get("OPENROUTER_API_KEY") or os.environ.get("GROQ_API_KEY")
    if not key:
        return None
    try:
        import requests
    except ImportError:
        return None
    base = os.environ.get("LLM_BASE_URL", "https://openrouter.ai/api/v1/chat/completions")
    try:
        r = requests.post(base, headers={"Authorization": f"Bearer {key}"},
                          json={"model": model, "temperature": 0,
                                "messages": [{"role": "user", "content": prompt}]},
                          timeout=60)
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
        # Strip code fences if present
        content = re.sub(r"^```(?:json)?\s*", "", content.strip())
        content = re.sub(r"\s*```$", "", content.strip())
        ans = json.loads(content)
        if cache is not None:
            cache.put(f"llm:{model}:{hashlib.sha256(prompt.encode()).hexdigest()[:16]}",
                      {"answer": ans})
        return ans
    except Exception:
        return None


def resolve_getattr_case(source: str, call_line: int, vulnerable: list[str],
                         symbol_table: set[str], cache=None,
                         model: str = DEFAULT_MODEL) -> dict | None:
    """One uncertain dynamic call site, deterministic first, LLM second.

    Returns {"verdict", "confidence", "reason"} or None to stay uncertain.
    1. Constant propagation: if the name is a literal / loop over literals
       / concat / var-to-var, decide without any LLM.
    2. Otherwise build the grounded prompt (same-file functions only,
       string literals, vulnerable list) and ask the LLM once. The
       10-rule verifier decides; a failed verification stays uncertain.
    Never returns a verdict that downgrades a deterministic reachable —
    the caller only feeds it uncertain results.
    """
    vuln_simple = {v.split(".")[-1] for v in vulnerable}
    vals = constant_propagate_getattr(source, call_line)
    if vals is not None:
        if not vals:
            return {"verdict": "not_reachable", "confidence": "high",
                    "reason": "constant propagation: loop over an empty list, the dynamic call never runs"}
        if vals and any(v in vuln_simple for v in vals):
            hit = next(v for v in vals if v in vuln_simple)
            return {"verdict": "reachable", "confidence": "high",
                    "reason": f"constant propagation: dynamic name can be {vals}, including vulnerable {hit} (line {call_line})"}
        return {"verdict": "not_reachable", "confidence": "high",
                "reason": f"constant propagation: dynamic name can only be {vals}, none vulnerable (line {call_line})"}
    # LLM, only because the deterministic step could not decide.
    lines = source.splitlines()
    lo, hi = max(0, call_line - 25), min(len(lines), call_line + 25)
    snippet = "\n".join(f"{i+1}: {lines[i]}" for i in range(lo, hi))
    candidates = sorted(q for q in symbol_table if q.split(".")[-1] in
                        {n for n in re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", source)})
    prompt = build_prompt(snippet, candidates, extract_string_literals(source),
                          vulnerable, "<dynamic-call-site>", call_line)
    ans = resolve_with_llm(prompt, model=model, cache=cache)
    if ans is None:
        return None
    ok, failures = verify_answer(ans, symbol_table, source, "uncertain", vulnerable=vulnerable)
    if not ok:
        return {"verdict": "uncertain", "confidence": "low",
                "reason": f"LLM answer failed verification ({'; '.join(failures)}), staying uncertain",
                "_verification_failed": True}
    if ans["can_reach"] is True:
        return {"verdict": "reachable", "confidence": "medium",
                "reason": f"LLM resolver (verified, lines {ans['evidence_lines']}): {ans['reason']}"}
    if ans["can_reach"] is False:
        return {"verdict": "not_reachable", "confidence": "medium",
                "reason": f"LLM resolver (verified, lines {ans['evidence_lines']}): {ans['reason']}"}
    return None  # "unknown": stay uncertain
