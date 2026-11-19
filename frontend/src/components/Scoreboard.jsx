export default function Scoreboard({ report }) {
  if (!report) return null;

  const results = report.results || [];
  const reachable = results.filter((r) => r.verdict === "reachable").length;
  const notReachable = results.filter((r) => r.verdict === "not_reachable").length;
  const uncertain = results.filter((r) => r.verdict === "uncertain").length;
  const uncertainPct = Math.round((report.uncertain_rate || 0) * 100);
  const vexCount = report.openvex?.statements?.length || 0;
  const ledger = report.completeness_ledger || {};
  const cache = report.cache || { hits: 0, misses: 0 };

  const cards = [
    {
      label: "REACHABLE",
      value: reachable,
      sub: `${Object.values(report.proofs || {}).filter((p) => p.vulnerable_hit).length} witnessed`,
      accent: "text-[#E60023]",
    },
    {
      label: "NOT_REACHABLE",
      value: notReachable,
      sub: `${vexCount} OpenVEX stmt`,
      accent: "text-[#008A2E]",
    },
    {
      label: "UNCERTAIN",
      value: uncertain,
      sub: `${uncertainPct}% rate`,
      accent: "text-[#D97706]",
    },
    {
      label: "CACHE",
      value: `${cache.hits}/${cache.hits + cache.misses}`,
      sub: ledger.complete_for_not_reachable ? "LEDGER: 100%" : "LEDGER: PARTIAL",
      accent: "text-cobalt",
    },
  ];

  return (
    <section className="space-y-3">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {cards.map((c) => (
          <div
            key={c.label}
            className="bg-white border-2 border-black shadow-pixel p-3"
          >
            <div className="font-pixel text-[10px] text-neutral-600">
              {c.label}
            </div>
            <div className={`font-pixel text-2xl mt-1 ${c.accent}`}>
              {c.value}
            </div>
            <div className="text-[11px] text-neutral-700 mt-1">{c.sub}</div>
          </div>
        ))}
      </div>

      {/* Compact Completeness Ledger Strip */}
      <div className="bg-white border-2 border-black px-3 py-2 text-xs flex flex-wrap gap-x-5 gap-y-1">
        <span>
          <b className="font-pixel text-[10px]">SOURCE:</b>{" "}
          {ledger.project_source || "—"}
        </span>
        <span>
          <b className="font-pixel text-[10px]">ENTRIES:</b>{" "}
          {ledger.entry_points_identified ?? 0} ({report.entry_note || "—"})
        </span>
        <span>
          <b className="font-pixel text-[10px]">DYNAMIC UNRESOLVED:</b>{" "}
          {ledger.dynamic_unresolved ?? 0}
        </span>
        <span>
          <b className="font-pixel text-[10px]">AMBIGUOUS:</b>{" "}
          {ledger.ambiguous_edges ?? 0}
        </span>
      </div>
    </section>
  );
}