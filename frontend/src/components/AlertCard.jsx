import { useState } from "react";
import { runDebate } from "../api";

const VERDICT_STYLE = {
  reachable: "bg-[#E60023] text-white",
  not_reachable: "bg-[#008A2E] text-white",
  uncertain: "bg-[#D97706] text-white",
};

export default function AlertCard({
  result,
  proof,
  explanation,
  prComment,
  openvex,
  entryEvidence,
  project,
}) {
  const [open, setOpen] = useState(false);
  const [citation, setCitation] = useState("");
  const [debateVerdict, setDebateVerdict] = useState(result.verdict);
  const [evidenceLines, setEvidenceLines] = useState([]);
  const [debateLoading, setDebateLoading] = useState(false);

  const badgeCls = VERDICT_STYLE[result.verdict] || VERDICT_STYLE.uncertain;
  const hasVex =
    result.verdict === "not_reachable" &&
    (openvex?.statements || []).some(
      (s) => s.vulnerability?.["@id"] === result.advisory_id
    );

  const handleChallenge = async (e) => {
    e.preventDefault();
    setDebateLoading(true);
    try {
      const lineNum = citation.trim() ? parseInt(citation.trim(), 10) : null;
      const tokens = [
        result.vulnerable_function?.split(".").pop(),
        ...(result.path || []).map((p) => p.split(".").pop()),
      ].filter(Boolean);

      const res = await runDebate({
        verdict: debateVerdict,
        evidence_lines: evidenceLines,
        new_citation: Number.isNaN(lineNum) ? null : lineNum,
        file_path: result.entry_file || "",
        support_tokens: tokens,
        project: project || "",
      });
      setDebateVerdict(res.new_verdict);
      setEvidenceLines(res.evidence_lines || []);
      setCitation("");
    } catch (err) {
      alert(err.message);
    } finally {
      setDebateLoading(false);
    }
  };

  const copyVex = () => {
    navigator.clipboard.writeText(JSON.stringify(openvex, null, 2));
  };

  return (
    <div className="bg-white border-2 border-black shadow-pixel">
      {/* Header Row */}
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full px-4 py-3 flex flex-wrap items-center justify-between gap-3 text-left hover:bg-neutral-50"
      >
        <div className="flex flex-wrap items-center gap-2.5">
          <span
            className={`px-2 py-0.5 font-pixel text-[10px] uppercase border border-black ${badgeCls}`}
          >
            {result.verdict}
          </span>
          {proof?.vulnerable_hit && (
            <span className="px-2 py-0.5 font-pixel text-[10px] bg-cobalt text-white border border-black">
              WITNESSED
            </span>
          )}
          {hasVex && (
            <span className="px-2 py-0.5 font-pixel text-[10px] bg-paper text-black border border-black">
              OPENVEX
            </span>
          )}
          <span className="font-bold text-xs">{result.advisory_id}</span>
          <code className="text-xs bg-paper px-1.5 py-0.5 border border-black/20">
            {result.vulnerable_function || "(unknown)"}
          </code>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <span className="text-neutral-600">
            conf: <b>{result.confidence}</b>
          </span>
          <span className="font-pixel text-xs">{open ? "[-]" : "[+]"}</span>
        </div>
      </button>

      {/* Expanded Inspector */}
      {open && (
        <div className="border-t-2 border-black p-4 space-y-4 bg-paper/50 text-xs">
          {/* Reason */}
          <div>
            <div className="font-pixel text-[10px] text-neutral-600 mb-1">
              REASON
            </div>
            <p className="bg-white border border-black p-2.5 leading-relaxed">
              {result.reason}
            </p>
          </div>

          {/* Call Path (ChatGPT fix A: file:line per step, definition lines) */}
          {((result.path_detail || result.path)?.length || 0) > 0 && (
            <div>
              <div className="font-pixel text-[10px] text-neutral-600 mb-1">
                CALL PATH (REAL ENTRY POINT -&gt; TARGET) // FILE:LINE IS
                WHERE EACH FUNCTION IS DEFINED
              </div>
              <div className="bg-white border border-black p-2.5 flex flex-wrap items-center gap-1.5">
                {(result.path_detail ||
                  result.path.map((p) => ({ function: p }))).map(
                  (node, i, steps) => (
                    <span key={i} className="flex items-center gap-1.5">
                      <span className="flex flex-col items-start">
                        <code
                          className={`px-1.5 py-0.5 border border-black ${
                            i === steps.length - 1
                              ? "bg-[#E60023] text-white"
                              : i === 0
                                ? "bg-cobalt text-white"
                                : "bg-paper"
                          }`}
                        >
                          {node.function || node}
                        </code>
                        {node.file && (
                          <span className="text-[10px] text-neutral-500 mt-0.5">
                            {node.file}:
                            {node.line != null ? node.line : "?"}
                          </span>
                        )}
                      </span>
                      {i < steps.length - 1 && (
                        <span className="font-pixel text-[10px]">-&gt;</span>
                      )}
                    </span>
                  )
                )}
              </div>
              {entryEvidence?.[result.path[0]] && (
                <div className="mt-1 text-[11px] text-neutral-700">
                  <b>Entry evidence:</b> {entryEvidence[result.path[0]]}
                </div>
              )}
            </div>
          )}

          {/* Execution Witness */}
          {proof && (
            <div>
              <div className="font-pixel text-[10px] text-neutral-600 mb-1">
                EXECUTION WITNESS (SUBPROCESS — NOT A SANDBOX)
              </div>
              <div className="bg-white border border-black p-2.5 space-y-1.5">
                <div className="flex flex-wrap gap-4">
                  <span>
                    executed: <b>{String(proof.executed)}</b>
                  </span>
                  <span>
                    vulnerable_hit:{" "}
                    <b className={proof.vulnerable_hit ? "text-[#E60023]" : ""}>
                      {String(proof.vulnerable_hit)}
                    </b>
                  </span>
                  {proof.error && (
                    <span className="text-[#D97706]">
                      error: <code>{proof.error}</code>
                    </span>
                  )}
                </div>
                {proof.trace?.length > 0 && (
                  <pre className="bg-paper border border-black/30 p-2 overflow-x-auto text-[11px]">
                    {proof.trace.join(" -> ")}
                  </pre>
                )}
              </div>
            </div>
          )}

          {/* Uncertain Explanation (explainer.py) */}
          {explanation && (
            <div>
              <div className="font-pixel text-[10px] text-neutral-600 mb-1">
                UNCERTAIN EXPLAINER // BLOCKER: {explanation.blocker}
              </div>
              <div className="bg-white border border-black p-2.5 space-y-2">
                <pre className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed">
                  {explanation.deterministic_explanation}
                </pre>
                {explanation.llm_explanation && (
                  <pre className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed border-t border-black/20 pt-2 text-cobalt">
                    {explanation.llm_explanation}
                  </pre>
                )}
                {explanation.discriminating_check?.command && (
                  <div className="bg-paper border border-black p-2">
                    <div className="font-pixel text-[10px] mb-1">
                      DISCRIMINATING CHECK
                    </div>
                    <code>{explanation.discriminating_check.command}</code>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* OpenVEX */}
          {hasVex && (
            <div className="flex items-center justify-between bg-white border border-black p-2.5">
              <span>
                <b>OpenVEX ready:</b> <code>status: not_affected</code>{" "}
                (100% clean graph)
              </span>
              <button
                onClick={copyVex}
                className="px-2.5 py-1 font-pixel text-[10px] bg-black text-white hover:bg-cobalt"
              >
                COPY OPENVEX JSON
              </button>
            </div>
          )}

          {/* PR Comment + Concede-or-Cite Debate */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <div className="font-pixel text-[10px] text-neutral-600 mb-1">
                PR COMMENT PREVIEW
              </div>
              <pre className="bg-white border border-black p-2.5 whitespace-pre-wrap text-[11px] max-h-40 overflow-y-auto">
                {prComment}
              </pre>
            </div>

            <div>
              <div className="font-pixel text-[10px] text-neutral-600 mb-1">
                CONCEDE-OR-CITE CHALLENGE
              </div>
              <form
                onSubmit={handleChallenge}
                className="bg-white border border-black p-2.5 space-y-2"
              >
                <div className="text-[11px]">
                  Current verdict:{" "}
                  <b className="uppercase">{debateVerdict}</b>
                </div>
                <div className="flex gap-2">
                  <input
                    type="number"
                    value={citation}
                    onChange={(e) => setCitation(e.target.value)}
                    placeholder="Line # (or blank to concede)"
                    className="flex-1 px-2 py-1 border border-black bg-paper text-xs"
                  />
                  <button
                    type="submit"
                    disabled={debateLoading}
                    className="px-3 py-1 bg-cobalt text-white font-pixel text-[10px] border border-black"
                  >
                    CHALLENGE
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}