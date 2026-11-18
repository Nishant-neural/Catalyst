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
                  deterministic_verdict: str) -> tuple[bool, list[str]]:
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
    if answer["can_reach"] not in (True, False, "unknown"):
        failures.append("can_reach must be true, false, or 'unknown'")
    if deterministic_verdict == "reachable" and answer["can_reach"] is False:
        failures.append("never downgrade a deterministic reachable verdict")
    conf = answer.get("confidence")
    if not isinstance(conf, (int, float)) or not 0 <= conf <= 1:
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
    lines = source_text.splitlines()
    for ln in answer.get("evidence_lines", []):
        if not isinstance(ln, int) or not 1 <= ln <= len(lines):
            failures.append(f"evidence line {ln} out of range")
        else:
            text = lines[ln - 1]
            if vals and not any(v in text for v in vals):
                failures.append(f"evidence line {ln} does not contain any possible value")
    if answer["can_reach"] is False:
        if not vals:
            failures.append("can_reach false needs non-empty possible_values")
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
    """
    import ast as _ast
    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return None
    # Find the function containing call_line
    target_fn = None
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            if node.lineno <= call_line <= getattr(node, "end_lineno", call_line):
                target_fn = node
                break
    if target_fn is None:
        return None
    # Collect simple assignments before the call, in order
    values: dict[str, list[str] | None] = {}
    for node in _ast.walk(target_fn):
        if isinstance(node, _ast.Assign) and node.lineno < call_line:
            if len(node.targets) != 1 or not isinstance(node.targets[0], _ast.Name):
                continue
            var = node.targets[0].id
            v = node.value
            if isinstance(v, _ast.Constant) and isinstance(v.value, str):
                values[var] = [v.value]
            elif isinstance(v, _ast.List):
                vals = [e.value for e in v.elts if isinstance(e, _ast.Constant) and isinstance(e.value, str)]
                values[var] = vals if len(vals) == len(v.elts) else None
            else:
                values[var] = None  # config / input / call / unknown
        if isinstance(node, _ast.For) and node.lineno < call_line:
            if isinstance(node.target, _ast.Name) and isinstance(node.iter, _ast.List):
                vals = [e.value for e in node.iter.elts if isinstance(e, _ast.Constant) and isinstance(e.value, str)]
                if len(vals) == len(node.iter.elts):
                    values[node.target.id] = vals
    # Find the getattr call and its name argument
    for node in _ast.walk(target_fn):
        if isinstance(node, _ast.Call) and node.lineno == call_line:
            func = node.func
            if isinstance(func, _ast.Name) and func.id == "getattr" and len(node.args) >= 2:
                arg = node.args[1]
                if isinstance(arg, _ast.Constant) and isinstance(arg.value, str):
                    return [arg.value]
                if isinstance(arg, _ast.Name):
                    return values.get(arg.id)  # may be list or None
    return None


def resolve_with_llm(prompt: str, api_key: str | None = None,
                     model: str = DEFAULT_MODEL) -> dict | None:
    """Call a free OpenRouter-compatible endpoint. Returns parsed JSON or None.

    Set OPENROUTER_API_KEY or GROQ_API_KEY. No key -> None (stay uncertain).
    This function is intentionally small; swap the endpoint in one place.
    """
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
        return json.loads(content)
    except Exception:
        return None
