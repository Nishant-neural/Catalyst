"""Phase 5 (part 2): PR debate agent. Concede-or-cite.

The agent posts a verdict with evidence and confidence. If a maintainer
challenges it, it must either cite a NEW line from the code that supports
its verdict, or flip to UNCERTAIN. It may never defend itself without
a citation. This is the fail-closed debate rule, written up in PHASES.md
even if the live bot in the hackathon is simple.
"""
from __future__ import annotations


def format_pr_comment(result, entry_note: str = "") -> str:
    path = " -> ".join(result.path) if result.path else "(no path)"
    return (
        f"## pyreach: {result.advisory_id} — {result.verdict.upper()}\n\n"
        f"- **Package:** {result.package}\n"
        f"- **Vulnerable function:** `{result.vulnerable_function or 'unknown'}`\n"
        f"- **Confidence:** {result.confidence} (function confidence: {result.function_confidence})\n"
        f"- **Call path:** `{path}`\n"
        f"- **Reason:** {result.reason}\n"
        f"{entry_note}\n\n"
        f"Challenge me: reply with a line number or a call you think I missed. "
        f"If I cannot cite it, I will flip this to uncertain.\n"
    )


def answer_challenge(verdict: str, evidence_lines: list[int],
                     new_citation: int | None, source_lines: list[str],
                     support_tokens: list[str] | None = None) -> str:
    """Concede-or-cite. Returns the new verdict.

    Phase 5 fix: the base version recorded any in-range citation and
    kept the verdict — it never checked the cited line supports
    anything. Now the cited line must contain one of the support
    tokens (the vulnerable function's name, or a caller on the call
    path). A citation to an unrelated line, or no citation at all,
    flips the verdict to UNCERTAIN. That is the whole rule: defend
    with a citation, or concede.
    """
    if new_citation is None:
        return "uncertain"
    if not 1 <= new_citation <= len(source_lines):
        return "uncertain"
    if new_citation in evidence_lines:
        # Not a NEW line: citing the same evidence again is not a defence.
        return "uncertain"
    line = source_lines[new_citation - 1]
    if support_tokens:
        if not any(tok in line for tok in support_tokens):
            return "uncertain"
    evidence_lines.append(new_citation)
    return verdict
