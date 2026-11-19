"""Readable HTML report for a pyreach scan — the interface the terminal
is not.

The terminal prints a short summary only (see cli.py, quiet by
default). Full detail lives in report.json, and this module renders
that same report.json as one self-contained HTML file: inline CSS,
no external assets, no JavaScript beyond nothing at all — open it in
a browser and read it.

Stdlib only. Every string that comes from the scanned project (file
paths, reasons, explanations) is passed through html.escape, so
scanned code can never break the page or inject markup.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path

CSS = """
body { font-family: system-ui, -apple-system, sans-serif; max-width: 960px;
  margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; line-height: 1.5; }
h1 { font-size: 1.5rem; } h2 { font-size: 1.2rem; margin-top: 2rem;
  border-bottom: 1px solid #ddd; padding-bottom: .25rem; }
.cards { display: flex; flex-wrap: wrap; gap: .75rem; }
.card { border: 1px solid #ddd; border-radius: 8px; padding: .75rem 1rem;
  min-width: 8rem; }
.card b { font-size: 1.6rem; display: block; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 999px;
  font-weight: 700; font-size: .85rem; color: #fff; }
.reachable { background: #b3261e; } .uncertain { background: #8a6d00; }
.not_reachable { background: #1e7d32; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: .4rem .6rem; text-align: left;
  vertical-align: top; }
th { background: #f2f2f2; }
.path { font-family: monospace; font-size: .85rem; word-break: break-all; }
code { background: #f2f2f2; padding: .1rem .35rem; border-radius: 4px;
  word-break: break-all; }
pre.check { background: #f2f2f2; padding: .6rem; border-radius: 6px;
  white-space: pre-wrap; word-break: break-word; }
.expl { border: 1px solid #ddd; border-radius: 8px; padding: .75rem 1rem;
  margin-bottom: 1rem; }
.tag { font-size: .75rem; font-weight: 700; border: 1px solid #999;
  border-radius: 4px; padding: 0 .35rem; margin-right: .35rem; }
.note { background: #f7f7f7; border-left: 4px solid #888; padding: .6rem 1rem; }
.muted { color: #555; font-size: .9rem; }
details { margin-top: .35rem; } summary { cursor: pointer; color: #555; }
"""

_BLOCKED_RE = re.compile(r"Blocked at (.+?):(\d+)")

def blocked_location(deterministic_text: str) -> str:
    """'file:line' of the blocked edge, parsed from the deterministic
    explanation text (which is where it is recorded). '' if absent."""
    m = _BLOCKED_RE.search(deterministic_text or "")
    return f"{m.group(1)}:{m.group(2)}" if m else ""


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _labelled_lines(text: str) -> str:
    """Render [deterministic]/[llm-explainer] lines as paragraphs,
    keeping the label as a visible tag."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        for label in ("[deterministic]", "[llm-explainer]"):
            if line.startswith(label):
                out.append(f'<p><span class="tag">{_esc(label)}</span>'
                           f'{_esc(line[len(label):].strip())}</p>')
                break
        else:
            out.append(f"<p>{_esc(line)}</p>")
    return "\n".join(out)


def _verdict_badge(verdict: str) -> str:
    cls = verdict if verdict in ("reachable", "uncertain", "not_reachable") else "uncertain"
    return f'<span class="badge {cls}">{_esc(verdict)}</span>'


def render_html(report: dict) -> str:
    """Render a report.json dict (as loaded from disk) to HTML."""
    results = report.get("results") or []
    explanations = report.get("explanations") or []
    proofs = report.get("proofs") or {}
    ledger = report.get("completeness_ledger") or {}
    advisories = report.get("advisories") or []
    counts = {v: sum(1 for r in results if r.get("verdict") == v)
              for v in ("reachable", "uncertain", "not_reachable")}
    total = len(results) or 1
    rate = report.get("uncertain_rate")
    rate_txt = (f"{rate:.0%}" if isinstance(rate, (int, float))
                else f"{counts['uncertain']}/{len(results)}")
    project = _esc(report.get("project", ""))
    adv_txt = ", ".join(_esc(a.get("id", "")) for a in advisories) or "—"

    def ledger_row(key: str, label: str) -> str:
        return (f"<tr><td>{_esc(label)}</td>"
                f"<td>{_esc(ledger.get(key, '—'))}</td></tr>")

    result_rows = []
    for r in results:
        # ChatGPT fix A (19 Nov 2026): show file:line per call-path step
        # when the report carries path_detail; old reports without it
        # fall back to bare function names.
        pd = r.get("path_detail")
        if pd:
            def _step(d):
                loc = (f"{d.get('file', 'external')}:"
                       f"{d.get('line') if d.get('line') is not None else '?'}")
                return f"{d.get('function', '?')} ({loc})"
            path = " -&gt; ".join(_esc(_step(d)) for d in pd) or "—"
        else:
            path = " -&gt; ".join(_esc(p) for p in (r.get("path") or [])) or "—"
        reason = r.get("reason", "") or ""
        short = reason[:160] + ("…" if len(reason) > 160 else "")
        result_rows.append(
            "<tr>"
            f"<td>{_verdict_badge(r.get('verdict', ''))}</td>"
            f"<td><code>{_esc(r.get('vulnerable_function', ''))}</code></td>"
            f"<td>{_esc(r.get('confidence', ''))}</td>"
            f"<td class=\"path\">{path}</td>"
            f"<td>{_esc(short)}"
            + (f"<details><summary>full reason</summary>{_esc(reason)}</details>"
               if len(reason) > 160 else "")
            + "</td></tr>")
    results_table = ("\n".join(result_rows) if result_rows
                     else "<p>No results.</p>")

    expl_cards = []
    for e in explanations:
        det = e.get("deterministic_explanation", "") or ""
        loc = blocked_location(det)
        llm = e.get("llm_explanation")
        check = e.get("discriminating_check") or {}
        dnk = e.get("does_not_know") or []
        body = [_labelled_lines(det)]
        if llm:
            body.append(_labelled_lines(llm))
        elif e.get("llm_rejected"):
            body.append('<p><span class="tag">[llm-explainer]</span>'
                        'The LLM explanation was rejected by the citation '
                        'verifier — deterministic result unchanged.</p>')
        else:
            status = e.get("llm_status")
            if status and status != "not_called":
                err = e.get("llm_error")
                text = f'unavailable ({_esc(status)})'
                if err:
                    text += f' — {_esc(err)}'
                text += ' — deterministic result unchanged.'
            else:
                text = 'unavailable — deterministic result unchanged.'
            if e.get("llm_model"):
                text += f' (model {_esc(e["llm_model"])})'
            body.append('<p><span class="tag">[llm-explainer]</span>'
                        + text + '</p>')
        expl_cards.append(
            '<div class="expl">'
            f"<h3><code>{_esc(e.get('vulnerable_function', ''))}</code> — "
            f"blocker: <code>{_esc(e.get('blocker', ''))}</code>"
            + (f" — blocked at <code>{_esc(loc)}</code>" if loc else "")
            + "</h3>"
            + "\n".join(body)
            + ("<p><b>Does not know:</b></p><ul>"
               + "".join(f"<li>{_esc(x)}</li>" for x in dnk) + "</ul>"
               if dnk else "")
            + (f"<p><b>Discriminating check:</b> {_esc(check.get('check', ''))}</p>"
               f"<pre class=\"check\">{_esc(check.get('command', ''))}</pre>"
               if check.get("command") else "")
            + "</div>")
    expl_section = ("\n".join(expl_cards) if expl_cards
                    else "<p>No uncertain results to explain.</p>")

    proof_rows = []
    for adv_id, p in proofs.items():
        trace = " -&gt; ".join(_esc(t) for t in (p.get("trace") or [])) or "—"
        proof_rows.append(
            "<tr>"
            f"<td><code>{_esc(adv_id)}</code></td>"
            f"<td>{_esc(p.get('vulnerable_hit'))}</td>"
            f"<td class=\"path\">{trace}</td>"
            f"<td>{_esc(p.get('error') or '')}</td>"
            "</tr>")
    proof_section = (f"<h2>Execution proofs</h2><table><tr><th>Advisory</th>"
                     f"<th>Hit</th><th>Trace</th><th>Error</th></tr>"
                     + "\n".join(proof_rows) + "</table>") if proof_rows else ""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>pyreach report — {_esc(report.get('project', ''))}</title>
<style>{CSS}</style></head><body>
<h1>pyreach report</h1>
<p class="muted">Project: <code>{project}</code><br>
Advisories: {adv_txt}</p>
<div class="cards">
<div class="card"><b>{counts['reachable']}</b>reachable</div>
<div class="card"><b>{counts['uncertain']}</b>uncertain</div>
<div class="card"><b>{counts['not_reachable']}</b>not_reachable</div>
<div class="card"><b>{rate_txt}</b>uncertain rate</div>
</div>
<h2>Completeness ledger</h2>
<table>
{ledger_row('project_source', 'Project source parsed')}
{ledger_row('dependency_source', 'Dependency source parsed')}
{ledger_row('dynamic_unresolved', 'Dynamic sites unresolved')}
{ledger_row('ambiguous_edges', 'Ambiguous edges')}
{ledger_row('entry_points_identified', 'Entry points identified')}
</table>
<h2>Results ({len(results)})</h2>
<table><tr><th>Verdict</th><th>Vulnerable function</th><th>Confidence</th>
<th>Call path</th><th>Reason</th></tr>
{results_table}
</table>
<h2>Explanations ({len(explanations)})</h2>
{expl_section}
{proof_section}
<div class="note"><p><b>How to read this:</b> verdicts are deterministic —
computed from the call graph, never from the LLM. The LLM only explains
uncertain results, and its output is checked against the code before it
is shown; a rejected explanation never changes a verdict. An uncertain
verdict means “cannot be proved either way from the evidence above”,
not “probably vulnerable”.</p></div>
</body></html>
"""


def html_path_for(json_path: str | Path) -> Path:
    """mkdocs-base.json -> mkdocs-base.html, in the same directory."""
    p = Path(json_path)
    return p.with_suffix(".html") if p.suffix == ".json" else p.with_name(p.name + ".html")


def write_html_report(report: dict, json_path: str | Path) -> Path:
    """Render `report` and write it next to the JSON report. Returns the
    HTML path."""
    out = html_path_for(json_path)
    out.write_text(render_html(report), encoding="utf-8")
    return out


def render_report_file(report_path: str | Path, out_path: str | Path | None = None) -> Path:
    """Render an existing report.json to HTML without re-scanning.
    Raises FileNotFoundError / json.JSONDecodeError for a missing or
    invalid report — the caller turns those into a clean CLI error."""
    report_path = Path(report_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    out = Path(out_path) if out_path else html_path_for(report_path)
    out.write_text(render_html(report), encoding="utf-8")
    return out
