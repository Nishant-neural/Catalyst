"""Phase 4: LLM resolver for UNCERTAIN dynamic cases only.

Deterministic core first. The LLM only sees one uncertain call site
at a time, with grounded context. It proposes, the verifier decides.
If verification fails, stay UNCERTAIN. Never downgrade a deterministic
REACHABLE verdict.

Model: small open-weight, via a free provider (OpenRouter / Groq).
Temperature 0. No API key -> resolver is skipped, verdicts stay
uncertain. That is safe.
"""
from __future__ import annotations

import json
import os
import re

# Default model, verified 19 Nov 2026 against the live OpenRouter
# catalog (GET /api/v1/models, 0/0 pricing). The previous default,
# openai/gpt-oss-20b:free, was DELISTED: on 19 Nov 2026 a real
# `pyreach llm-test` on the user's machine got HTTP 404 "This model
# is unavailable for free. The paid version is available now - use
# this slug instead: openai/gpt-oss-20b". The live catalog that day
# had NO gpt-oss :free slug at all — only the paid ones. Do NOT switch
# the default to the paid slug openai/gpt-oss-20b: that would bill the
# user for every scan. The :free suffix matters: without it, the model
# id is the paid variant. Free slugs churn every few weeks — re-check
# this default against GET /api/v1/models before trusting it, and see
# FREE_MODEL_FALLBACKS below for what happens when one disappears.
# Why cohere/north-mini-code:free: a code-focused model (best fit for
# pyreach's small JSON code-reasoning prompts), it answered all 3
# passes in a 3 Nov 2026 probe of free models, and it was in the live
# 0/0-pricing catalog on 19 Nov 2026.
DEFAULT_MODEL = "cohere/north-mini-code:free"
# Free-model fallback chain, default first. Hard-pinning ONE free slug
# is what broke on 19 Nov 2026 (see DEFAULT_MODEL above), so when the
# default 404s as "unavailable for free" the call tries the next model
# instead of failing the whole scan. Only that specific 404 triggers a
# switch — 429 / timeout / bad JSON / network errors do not. An
# explicitly passed --model is never overridden: see allow_fallback.
FREE_MODEL_FALLBACKS = ["cohere/north-mini-code:free",
                        "google/gemma-4-31b-it:free",
                        "nvidia/nemotron-3.5-lightning:free"]
CONFIDENCE_THRESHOLD = 0.8  # starting value, tune on organisers' fixtures
LLM_TIMEOUT = 60  # seconds per LLM call

# Kinds an LLM call can end in. "ok" means a parsed JSON answer came
# back (it may still fail the verifier downstream — that is "rejected",
# recorded by the explainer, not here). Every other kind means no
# answer at all, and the detail says why in one safe line.
LLM_STATUS_KINDS = ("ok", "no_key", "no_requests", "timeout", "http_error",
                    "rate_limited", "bad_json", "network_error")

# The one-call diagnosis prompt for `pyreach llm-test`: the model must
# reply with exactly this JSON and nothing else.
LLM_TEST_PROMPT = 'Reply with exactly this JSON and nothing else: {"ok": true}'


def _safe_detail(text: str) -> str:
    """One safe line for a status detail: never a key, never a body.

    Redacts anything shaped like an API key or a Bearer token, collapses
    whitespace, and truncates to ~120 characters. Use for every detail
    that could carry provider text — an error message, a status line.
    """
    if not text:
        return ""
    text = re.sub(r"sk-or-v1-[A-Za-z0-9_\-]{4,}", "[REDACTED]", text)
    text = re.sub(r"sk-[A-Za-z0-9]{8,}", "[REDACTED]", text)
    text = re.sub(r"Bearer\s+\S+", "Bearer [REDACTED]", text)
    text = re.sub(r"(?i)(api[_-]?key\s*[:=]\s*)\S+", r"\1[REDACTED]", text)
    return " ".join(str(text).split())[:120] or ""


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
- If you answer can_reach false, possible_values MUST list every value the name can take — an empty list is not an answer.
- If the value comes from config, user input, env, or an unknown source, answer can_reach: "unknown".
- Cite line numbers that actually exist in the code above.

Return strict JSON only:
{{"can_reach": true|false|"unknown", "possible_values": ["..."], "vulnerable_hit": "qualified.name or null", "reason": "one sentence", "evidence_lines": [12, 13], "confidence": 0.9}}
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


def _cache_key(prompt: str, model: str) -> str:
    """One cache key per (model, prompt): a fallback hit is stored under
    the fallback model's key, never under the default's."""
    import hashlib
    return f"llm:{model}:{hashlib.sha256(prompt.encode()).hexdigest()[:16]}"


def _cached_answer(prompt: str, model: str, cache):
    """Cached answer for one model, or None. No network, no key needed."""
    if cache is None:
        return None
    try:
        hit = cache.get(_cache_key(prompt, model))
    except Exception:
        # A cache failure is a miss, never a call failure: on 19 Nov 2026
        # a Windows-illegal ":" in the cache filename raised OSError here
        # and the caller reported it as a network error.
        return None
    return hit.get("answer") if hit is not None else None


def _attempt_llm_call(prompt: str, model: str, key: str, cache=None,
                      base: str | None = None) -> tuple[dict | None, dict, bool]:
    """One model, one POST. Returns (answer_or_None, status, delisted).

    status is {"kind", "detail", "model"}: "model" is the model that
    produced the answer, or the model that was tried on failure.
    "delisted" is True only for the specific OpenRouter 404 whose body
    says the model is "unavailable for free" — the 19 Nov 2026
    gpt-oss-20b:free case. Only a delisted 404 may trigger a fallback
    to the next model; every other failure ends the call here.
    The cache key includes the model, so a fallback hit never poisons
    the default model's cache entry (and vice versa).
    """
    # No cache lookup here: resolve_with_llm_status already checked
    # the whole chain's cache before the network loop, so re-checking
    # would double-count misses in the cache stats. This function only
    # POSTs, and stores a fresh answer under this model's key.
    cache_key = _cache_key(prompt, model) if cache is not None else None
    if base is None:
        base = os.environ.get("LLM_BASE_URL",
                              "https://openrouter.ai/api/v1/chat/completions")
    import requests
    try:
        r = requests.post(base, headers={"Authorization": f"Bearer {key}"},
                          json={"model": model, "temperature": 0,
                                "messages": [{"role": "user", "content": prompt}]},
                          timeout=LLM_TIMEOUT)
        r.raise_for_status()
        try:
            body = r.json()
            content = body["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as e:
            return None, {"kind": "bad_json",
                          "detail": "response was not the expected JSON "
                                    f"shape ({_safe_detail(str(e))})",
                          "model": model}, False
        if not isinstance(content, str):
            return None, {"kind": "bad_json",
                          "detail": "response content was not text",
                          "model": model}, False
        # Strip code fences if present
        content = re.sub(r"^```(?:json)?\s*", "", content.strip())
        content = re.sub(r"\s*```$", "", content.strip())
        try:
            ans = json.loads(content)
        except ValueError as e:
            return None, {"kind": "bad_json",
                          "detail": "model reply was not JSON "
                                    f"({_safe_detail(str(e))})",
                          "model": model}, False
        if cache is not None and cache_key is not None:
            try:
                cache.put(cache_key, {"answer": ans})
            except Exception:
                # Best-effort: a cache write must never turn a good
                # answer into a failure. (Before this fix the put sat
                # inside the network try below, so a Windows OSError
                # from the ":" in the cache filename was reported as
                # "network_error" — the 19 Nov 2026 MkDocs run.)
                pass
        return ans, {"kind": "ok", "detail": "", "model": model}, False
    except Exception as e:
        # Classify by exception type/name, not by message text: the
        # requests classes may be absent, and a message could in
        # principle echo a header. Order matters: HTTPError is also a
        # RequestException, and Timeout must be checked before the
        # generic network bucket. Anything that is not a requests error
        # (e.g. an OSError from local code) is reported as-is under
        # network_error only as a last resort — cache errors are kept
        # out of this block by the try/except around cache.put above
        # and around cache.get in _cached_answer.
        name = type(e).__name__
        status_code = getattr(getattr(e, "response", None), "status_code", None)
        if name == "Timeout" or "Timeout" in name:
            return None, {"kind": "timeout",
                          "detail": f"request timed out after {LLM_TIMEOUT}s",
                          "model": model}, False
        if name == "HTTPError" or status_code is not None:
            if status_code == 429:
                return None, {"kind": "rate_limited",
                              "detail": "HTTP 429: free-tier rate limit "
                                        "reached — wait and retry",
                              "model": model}, False
            body = ""
            try:
                body = getattr(e.response, "text", "") or ""
            except Exception:
                body = ""
            detail = f"HTTP {status_code}" if status_code else "HTTP error"
            if body:
                detail += f": {_safe_detail(body)}"
            # The delisting signal, and only this one, authorises a
            # fallback: OpenRouter 404 + "unavailable for free" in the
            # body. Any other 404 (wrong endpoint, bad path) is not a
            # delisting and must not switch models.
            delisted = (status_code == 404
                        and "unavailable for free" in body.lower())
            return None, {"kind": "http_error", "detail": detail,
                          "model": model}, delisted
        if name in ("ConnectionError", "ConnectTimeout", "ReadTimeout") \
                or "Connection" in name:
            return None, {"kind": "network_error",
                          "detail": "could not reach the LLM endpoint "
                                    f"({_safe_detail(str(e))})",
                          "model": model}, False
        return None, {"kind": "network_error",
                      "detail": _safe_detail(f"{name}: {e}") or name,
                      "model": model}, False


def resolve_with_llm_status(prompt: str, api_key: str | None = None,
                            model: str = DEFAULT_MODEL, cache=None,
                            allow_fallback: bool = True
                            ) -> tuple[dict | None, dict]:
    """Call a free OpenRouter-compatible endpoint, reporting WHY.

    Returns (answer_or_None, status) where status is
    {"kind": one of LLM_STATUS_KINDS, "detail": safe one-line string
    or "", "model": the model that produced the answer, or the last
    model tried on failure}. This is the one place that talks to the
    endpoint — resolve_with_llm below is a thin wrapper over it, so
    the two cannot drift apart.

    Free-model fallback: when allow_fallback is True and the model is
    the default, a 404 that says the model is "unavailable for free"
    tries the next model in FREE_MODEL_FALLBACKS (delisted slugs are
    how free models die — 19 Nov 2026). No other failure triggers a
    switch. When the caller passed a model explicitly (allow_fallback
    False), exactly that model is used, delisted or not: an explicit
    choice is the user's, not ours to override.
    Set OPENROUTER_API_KEY or GROQ_API_KEY — as a real env var, or in a
    .env file in the current directory (see pyreach/dotenv.py). No key
    -> (None, no_key). A cache hit returns the stored answer with kind
    "ok" and detail "cached answer", and makes no network call.
    Phase 4: answers are cached by (model, sha256(prompt)) in the same
    .reachcache as Phase 3, so a re-scan does not re-spend an LLM call.
    The cache key includes the model, so a model change is a miss.
    The detail never contains the key or a response body: at most the
    HTTP status code plus ~120 chars of an error message, key redacted.
    """
    if allow_fallback and model == DEFAULT_MODEL:
        chain = list(FREE_MODEL_FALLBACKS)
    else:
        chain = [model]
    # Cache first, across the whole chain, before any key check or
    # network call: a previous run may have fallen back, and its answer
    # is cached under the fallback model's key. Without this pre-check
    # a repeat call would 404 on the (delisted) default before ever
    # reaching the cached fallback answer — spending a call to learn
    # what the cache already knows. A cache hit needs no key at all,
    # exactly as before.
    if cache is not None:
        for cached_model in chain:
            cached = _cached_answer(prompt, cached_model, cache)
            if cached is not None:
                return cached, {"kind": "ok", "detail": "cached answer",
                                "model": cached_model}
    key = api_key or os.environ.get("OPENROUTER_API_KEY") or os.environ.get("GROQ_API_KEY")
    if not key:
        # Library callers bypass cli.py, so try ./.env here too. This is
        # a no-op when there is no .env file, and it never overrides a
        # real env var. The CLI already loaded it; loading twice is safe.
        from .dotenv import load_dotenv_file
        load_dotenv_file()
        key = os.environ.get("OPENROUTER_API_KEY") or os.environ.get("GROQ_API_KEY")
    if not key:
        return None, {"kind": "no_key",
                      "detail": "no OPENROUTER_API_KEY or GROQ_API_KEY "
                                "in the environment or .env",
                      "model": chain[0]}
    try:
        import requests  # noqa: F401  (presence check only)
    except ImportError:
        return None, {"kind": "no_requests",
                      "detail": "requests is not installed "
                                "(pip install requests)",
                      "model": chain[0]}
    base = os.environ.get("LLM_BASE_URL", "https://openrouter.ai/api/v1/chat/completions")
    last_status: dict | None = None
    for tried in chain:
        ans, status, delisted = _attempt_llm_call(prompt, tried, key,
                                                  cache=cache, base=base)
        if ans is not None:
            return ans, status
        last_status = status
        if not delisted:
            return None, status
        # Delisted 404: try the next model in the chain, if any.
    assert last_status is not None
    return None, last_status


def resolve_with_llm(prompt: str, api_key: str | None = None,
                     model: str = DEFAULT_MODEL, cache=None,
                     allow_fallback: bool = True) -> dict | None:
    """Call a free OpenRouter-compatible endpoint. Returns parsed JSON or None.

    Kept exactly as before for existing callers: None means "no answer"
    — no key, timeout, HTTP error, bad JSON, or network error all look
    identical here. Callers that need to know WHY must use
    resolve_with_llm_status instead. allow_fallback works as there:
    the default model falls back to FREE_MODEL_FALLBACKS on a delisted
    404, an explicit model never does.
    """
    ans, _status = resolve_with_llm_status(prompt, api_key=api_key,
                                           model=model, cache=cache,
                                           allow_fallback=allow_fallback)
    return ans


_NOT_GETATTR = object()  # sentinel: the call at a line is not getattr()


def getattr_receiver(source: str, call_line: int,
                     imports: dict[str, str] | None = None):
    """Module identity of the receiver of the getattr() call at call_line.

    Returns the resolved module name (e.g. "yaml"), None when the
    receiver cannot be determined (a variable, an attribute such as
    self.option, a call), or _NOT_GETATTR when the call at that line is
    not getattr() at all (eval, import_module, ...), for which this
    gate does not apply.

    19 Nov 2026 (ChatGPT Phase 9 review, Issue 3, reproduced against
    Phase 11): the resolver matched only the attribute's simple name,
    so getattr(json, "load") was reported REACHABLE for yaml.load with
    high confidence — json.load is not yaml.load. The receiver's module
    identity is part of the target; a known receiver from another
    module cannot reach this target, and an unknown receiver must stay
    uncertain, never be guessed by name alone.
    """
    import ast as _ast
    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return None
    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Call) or node.lineno != call_line:
            continue
        func = node.func
        is_getattr = ((isinstance(func, _ast.Name) and func.id == "getattr")
                      or (isinstance(func, _ast.Attribute)
                          and func.attr == "getattr"))
        if not is_getattr:
            continue
        if not node.args:
            return None
        recv = node.args[0]
        if isinstance(recv, _ast.Constant) and isinstance(recv.value, str):
            return recv.value
        if isinstance(recv, _ast.Name):
            if imports is None:
                return recv.id
            # Only a name the file actually imports is a known module;
            # a plain variable holding a module (mod = yaml) is unknown.
            return imports.get(recv.id)
        # Attribute / Subscript / Call receiver: object type unknown.
        return None
    return _NOT_GETATTR


def _dynamic_call_kind(source: str, call_line: int) -> str | None:
    """Callee name of the dynamic call at call_line, or None.

    Used to tell apart dynamic sites that can invoke a function
    (getattr, import_module, eval, exec) from ones that cannot
    (setattr only sets an attribute; globals/locals/vars only return
    a namespace dict). A setattr/globals site can never call the
    vulnerable function, so it resolves safe immediately instead of
    staying unresolved and blocking every not_reachable verdict.
    """
    import ast as _ast
    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return None
    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Call) or node.lineno != call_line:
            continue
        func = node.func
        if isinstance(func, _ast.Name):
            return func.id
        if isinstance(func, _ast.Attribute):
            return func.attr
        return None
    return None


def resolve_getattr_case(source: str, call_line: int, vulnerable: list[str],
                         symbol_table: set[str], cache=None,
                         model: str = DEFAULT_MODEL,
                         allow_llm: bool = True,
                         allow_fallback: bool = True,
                         imports: dict[str, str] | None = None) -> dict | None:
    """One uncertain dynamic call site, deterministic first, LLM second.

    Returns {"verdict", "confidence", "reason"} or None to stay uncertain.
    1. Constant propagation: if the name is a literal / loop over literals
       / concat / var-to-var, decide without any LLM.
    2. Otherwise build the grounded prompt (same-file functions only,
       string literals, vulnerable list) and ask the LLM once — only if
       allow_llm is True. The caller passes False when the user did not
       ask for the LLM, even if a key happens to be set in the environment.
       The 10-rule verifier decides; a failed verification stays uncertain.
    Never returns a verdict that downgrades a deterministic reachable —
    the caller only feeds it uncertain results.

    One site's answer decides ONE site, not the whole result. The caller
    (cli.py) must aggregate across all dynamic sites: a single safe site
    does not make the target not_reachable — see the 19 Nov 2026 fix.

    Receiver gate (19 Nov 2026, ChatGPT Phase 9 review Issue 3): the
    getattr receiver's module must be able to be the vulnerable
    function — a known receiver from another module makes this site
    safe, and an unknown receiver stays uncertain without any LLM
    call. Bare vulnerable names (no module) skip the gate: there is no
    module identity to check against.

    Order (19 Nov 2026, Phase 13): constant propagation runs FIRST,
    because the NAME is what decides whether the vulnerable function
    can be called at all — getattr(rule, 'CONF') can never be
    yaml.load, whatever rule is. The receiver only disambiguates
    when the name IS vulnerable: getattr(json, 'load') is safe
    because the receiver is json, while getattr(x, 'load') with x
    unknown stays uncertain. The old gate-first order returned
    None for every unknown receiver before constants ran, so three
    literal-name sites in yamllint ('CONF', 'DEFAULT', 'name')
    blocked every not_reachable verdict in the project.
    """
    kind = _dynamic_call_kind(source, call_line)
    if kind in ("setattr", "globals", "locals", "vars"):
        return {"verdict": "not_reachable", "confidence": "high",
                "reason": f"dynamic site is {kind}(), which cannot call "
                          f"a function (line {call_line})"}
    if kind in ("eval", "exec", "__import__"):
        return None  # can invoke anything, name unknown
    vuln_simple = {v.split(".")[-1] for v in vulnerable}
    vals = constant_propagate_getattr(source, call_line)
    if vals is not None:
        if not vals:
            return {"verdict": "not_reachable", "confidence": "high",
                    "reason": "constant propagation: loop over an empty list, the dynamic call never runs"}
        if vals and any(v in vuln_simple for v in vals):
            # The name could be the vulnerable function — only the
            # receiver can clear it now.
            receiver = getattr_receiver(source, call_line, imports)
            if receiver is _NOT_GETATTR or receiver is None:
                return None  # unknown receiver: could be the vulnerable module
            dotted = [v for v in vulnerable if "." in v]
            if dotted and any(v == receiver or v.startswith(receiver + ".")
                              for v in dotted):
                hit = next(v for v in vals if v in vuln_simple)
                return {"verdict": "reachable", "confidence": "high",
                        "reason": f"constant propagation: dynamic name can be {vals}, including vulnerable {hit} (line {call_line})"}
            return {"verdict": "not_reachable", "confidence": "high",
                    "reason": f"getattr receiver is module '{receiver}', "
                              f"not the vulnerable module for "
                              f"{vulnerable[0]} (line {call_line})"}
        return {"verdict": "not_reachable", "confidence": "high",
                "reason": f"constant propagation: dynamic name can only be {vals}, none vulnerable (line {call_line})"}
    receiver = getattr_receiver(source, call_line, imports)
    if receiver is not _NOT_GETATTR:
        dotted = [v for v in vulnerable if "." in v]
        if dotted:
            if receiver is None:
                return None  # unknown receiver: cannot match any module
            if not any(v == receiver or v.startswith(receiver + ".")
                       for v in dotted):
                return {"verdict": "not_reachable", "confidence": "high",
                        "reason": f"getattr receiver is module '{receiver}', "
                                  f"not the vulnerable module for "
                                  f"{vulnerable[0]} (line {call_line})"}
    # LLM, only because the deterministic step could not decide, and
    # only if the caller allowed it.
    if not allow_llm:
        return None
    lines = source.splitlines()
    lo, hi = max(0, call_line - 25), min(len(lines), call_line + 25)
    snippet = "\n".join(f"{i+1}: {lines[i]}" for i in range(lo, hi))
    candidates = sorted(q for q in symbol_table if q.split(".")[-1] in
                        {n for n in re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", source)})
    prompt = build_prompt(snippet, candidates, extract_string_literals(source),
                          vulnerable, "<dynamic-call-site>", call_line)
    ans = resolve_with_llm(prompt, model=model, cache=cache,
                           allow_fallback=allow_fallback)
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
    # can_reach False from the LLM never certifies absence (19 Nov 2026,
    # ChatGPT Phase 9 review Issue 4): the model can list
    # ["safe_load"] while a config value can supply "load", and the
    # verifier cannot prove the list is exhaustive. The LLM may propose
    # a reachable target, but only deterministic constant propagation
    # (above) may return not_reachable. A verified false answer is
    # therefore treated exactly like "unknown": stay uncertain.
    return None  # "unknown" or LLM-claimed false: stay uncertain
