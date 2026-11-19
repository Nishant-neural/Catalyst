"""Minimal .env loader — stdlib only, no python-dotenv dependency.

Why a hand-rolled loader: pyreach is meant to stay lean (one command,
no GPU, no LLM by default). A .env file is just KEY=VALUE lines; pulling
in a dependency for that would be the wrong weight.

What it does:
  - Reads a .env file next to where you run pyreach (see
    find_dotenv_file). It NEVER reads a .env from the project being
    scanned: a scanned repo is untrusted input, and its .env could
    redirect LLM requests carrying your key (19 Nov 2026).
  - Sets keys into os.environ ONLY if they are not already set. A real
    environment variable always wins over .env — so CI / PowerShell
    `$env:OPENROUTER_API_KEY=...` is never silently overridden.
  - Never prints, logs, or returns a secret value. Callers only learn
    how many keys were loaded and from which file, never the values.

What it deliberately does NOT do:
  - No variable expansion ($OTHER inside a value stays literal).
  - No multiline values. An API key is one line; if you need more,
    use a real env var.
  - No override flag. If you want a different key, change the env var
    or the .env file — do not ask the loader to silently win.

Format it understands (one per line):
    OPENROUTER_API_KEY=sk-or-v1-...
    OPENROUTER_API_KEY="sk-or-v1-..."   # quotes stripped
    export OPENROUTER_API_KEY=sk-or-v1-...
    # a comment line
    LLM_BASE_URL=https://api.groq.com/openai/v1/chat/completions
"""
from __future__ import annotations

import os
from pathlib import Path

# Only these keys are ever read from a .env file. Anything else in the
# file is ignored — a stray line cannot inject an unrelated env var
# (e.g. PATH, PYTHONPATH) into the process.
ALLOWED_KEYS = frozenset({
    "OPENROUTER_API_KEY",
    "GROQ_API_KEY",
    "LLM_BASE_URL",
    "PYREACH_ENV_FILE",
})


def parse_dotenv_text(text: str) -> dict[str, str]:
    """Parse .env text into {key: value}. No side effects, no env writes.

    Rules: blank lines and `#` comments skipped; optional `export `
    prefix; KEY=VALUE with optional single/double quotes around the
    value; an inline ` # comment` is stripped only for unquoted values
    (a quoted value keeps its spaces). Keys outside ALLOWED_KEYS are
    dropped. A line with no `=` is ignored, never an error — a malformed
    line must not break a scan.
    """
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key or key not in ALLOWED_KEYS:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        elif " #" in value:
            # Unquoted value with a trailing comment: keep the value.
            value = value.split(" #", 1)[0].strip()
        out[key] = value
    return out


def find_dotenv_file(start: Path | None = None,
                     project: Path | None = None) -> Path | None:
    """Find the .env file to load, first match wins.

    Order (explicit beats implicit, current dir beats scanned project):
      1. PYREACH_ENV_FILE env var, if it points at an existing file.
      2. .env in the current working directory, then walking up from it
         (so running from a subfolder of the repo still finds the repo .env).
    The scanned project directory is deliberately NOT a source
    (19 Nov 2026, ChatGPT Phase 9 review §4C, reproduced): a malicious
    project could ship a .env with LLM_BASE_URL pointing at an
    attacker server, and the scan would send the user's API key there.
    The `project` argument is kept for call compatibility and ignored.
    Returns None when there is no .env file — that is normal, not an error.
    """
    explicit = os.environ.get("PYREACH_ENV_FILE")
    if explicit:
        p = Path(explicit).expanduser()
        if p.is_file():
            return p
    cwd = Path(start) if start is not None else Path.cwd()
    for parent in [cwd, *cwd.parents]:
        cand = parent / ".env"
        if cand.is_file():
            return cand
    return None


def load_dotenv_file(path: Path | str | None = None,
                     project: Path | None = None,
                     override: bool = False) -> dict:
    """Load a .env file into os.environ. Returns a summary, never values.

    Returns {"path": str | None, "loaded": [key, ...], "skipped": [key, ...]}
    where `loaded` are keys newly set from the file and `skipped` are keys
    already present in the environment (env wins, unless override=True,
    which pyreach never passes — it exists only so tests can prove the
    no-override rule both ways). Missing file -> {"path": None, ...}.
    A malformed or unreadable file is also not an error: it returns
    {"path": ..., "loaded": [], "skipped": [], "error": "..."} and the
    scan continues with whatever env vars it already had.
    """
    if path is None:
        found = find_dotenv_file(project=project)
        if found is None:
            return {"path": None, "loaded": [], "skipped": []}
        path = found
    path = Path(path)
    try:
        values = parse_dotenv_text(path.read_text(encoding="utf-8"))
    except OSError as e:
        return {"path": str(path), "loaded": [], "skipped": [],
                "error": f"cannot read .env: {e}"}
    loaded, skipped = [], []
    for key, value in values.items():
        if key in os.environ and not override:
            skipped.append(key)
        else:
            os.environ[key] = value
            loaded.append(key)
    return {"path": str(path), "loaded": loaded, "skipped": skipped}
