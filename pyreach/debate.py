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
                     new_citation: int | None, source_lines: list[str]) -> str:
    """Concede-or-cite. Returns the new verdict."""
    if new_citation is None:
        return "uncertain"
    if not 1 <= new_citation <= len(source_lines):
        return "uncertain"
    # A citation only helps if it is a real line; the caller must verify
    # that the line actually supports the challenge. If it does not,
    # the caller flips to uncertain. Here we record the citation.
    evidence_lines.append(new_citation)
    return verdict
