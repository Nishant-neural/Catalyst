import { useEffect, useState } from "react";
import { getFixtures, runScan } from "./api";
import Header from "./components/Header";
import ScanControls from "./components/ScanControls";
import Scoreboard from "./components/Scoreboard";
import AlertCard from "./components/AlertCard";
import VerifyGrid from "./components/VerifyGrid";

export default function App() {
  const [tab, setTab] = useState("scan");
  const [fixtures, setFixtures] = useState([]);
  const [form, setForm] = useState({
    project: "fixtures/app_vuln",
    advisory: "",
    package: "",
    version: "",
    with_proof: true,
    with_llm: false,
    no_llm: true,
    explain: true,
    with_deps: true,
  });
  const [report, setReport] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    getFixtures()
      .then(setFixtures)
      .catch(() => {
        // Backend may not be started yet; offline report.json upload still works
      });
  }, []);

  const handleRunScan = async (overrideProject) => {
    const projectPath =
      typeof overrideProject === "string" ? overrideProject : form.project;
    if (!projectPath) return;

    setTab("scan");
    setScanning(true);
    setError("");
    try {
      const payload = {
        project: projectPath,
        advisory: form.advisory.trim() || null,
        package: form.package.trim() || null,
        version: form.version.trim() || null,
        with_proof: form.with_proof,
        with_llm: form.with_llm,
        no_llm: form.no_llm,
        explain: form.explain,
        with_deps: form.with_deps,
      };
      const data = await runScan(payload);
      setReport(data);
      setFilter("all");
    } catch (err) {
      setError(err.message);
    } finally {
      setScanning(false);
    }
  };

  const handleSelectFixture = (fixturePath) => {
    setForm((f) => ({
      ...f,
      project: fixturePath,
      package: "",
      version: "",
    }));
    handleRunScan(fixturePath);
  };

  const results = report?.results || [];
  const filteredResults =
    filter === "all" ? results : results.filter((r) => r.verdict === filter);

  return (
    <div className="min-h-screen bg-graph-paper text-black flex flex-col">
      <Header
        tab={tab}
        setTab={setTab}
        onRunScan={() => handleRunScan()}
        scanning={scanning}
      />

      <main className="flex-1 max-w-5xl w-full mx-auto px-4 py-6 space-y-6">
        {/* Compact Pixel Hero Banner */}
        <section className="relative bg-white border-2 border-black shadow-pixel p-5 overflow-hidden">
          <div className="absolute right-0 top-0 bottom-0 w-28 bg-dither-cobalt opacity-25 pointer-events-none" />
          <div className="relative z-10 flex flex-wrap items-end justify-between gap-4">
            <div>
              <div className="font-pixel text-[10px] text-cobalt uppercase tracking-widest">
                DETERMINISTIC FIRST // FAIL-CLOSED REACHABILITY
              </div>
              <h1 className="font-pixel text-2xl md:text-3xl mt-1">
                pyreach
              </h1>
              <p className="text-xs text-neutral-700 mt-1 max-w-xl">
                AST call graph + real entry points + isolated execution witness
                + OpenVEX. Never marks a reachable vulnerability as
                not-reachable.
              </p>
            </div>
            {report && (
              <div className="text-right text-[11px] bg-paper border-2 border-black px-3 py-1.5">
                <div className="font-pixel text-[10px] text-neutral-500">
                  ACTIVE TARGET
                </div>
                <div className="font-bold truncate max-w-[240px]">
                  {report.project}
                </div>
              </div>
            )}
          </div>
        </section>

        {tab === "verify" ? (
          <VerifyGrid onSelectFixture={handleSelectFixture} />
        ) : (
          <>
            <ScanControls
              fixtures={fixtures}
              form={form}
              setForm={setForm}
              onRunScan={() => handleRunScan()}
              onUploadReport={(json) => {
                setReport(json);
                setError("");
                setFilter("all");
              }}
              scanning={scanning}
            />

            {error && (
              <div className="bg-[#E60023] text-white border-2 border-black shadow-pixel p-3 text-xs font-pixel">
                ERROR: {error}
              </div>
            )}

            {report && (
              <>
                <Scoreboard report={report} />

                {/* Alerts Section */}
                <section className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h2 className="font-pixel text-sm uppercase">
                      02 // Alerts ({filteredResults.length}/{results.length})
                    </h2>

                    <div className="flex border-2 border-black bg-white shadow-pixel-sm">
                      {["all", "reachable", "not_reachable", "uncertain"].map(
                        (v) => (
                          <button
                            key={v}
                            onClick={() => setFilter(v)}
                            className={`px-2.5 py-1 font-pixel text-[10px] uppercase border-r-2 last:border-r-0 border-black ${
                              filter === v
                                ? "bg-cobalt text-white"
                                : "bg-white text-black hover:bg-paper"
                            }`}
                          >
                            {v}
                          </button>
                        )
                      )}
                    </div>
                  </div>

                  {filteredResults.length === 0 ? (
                    <div className="bg-white border-2 border-black p-6 text-center text-xs text-neutral-600">
                      No alerts match this filter.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {filteredResults.map((res, idx) => {
                        const origIdx = results.indexOf(res);
                        const proof = report.proofs?.[res.advisory_id] || null;
                        const explanation = (report.explanations || []).find(
                          (e) =>
                            e.advisory_id === res.advisory_id &&
                            e.vulnerable_function === res.vulnerable_function
                        );
                        return (
                          <AlertCard
                            key={`${res.advisory_id}-${res.vulnerable_function}-${idx}`}
                            result={res}
                            proof={proof}
                            explanation={explanation}
                            prComment={report.pr_comments?.[origIdx] || ""}
                            openvex={report.openvex}
                            entryEvidence={report.entry_evidence}
                            project={report.project}
                          />
                        );
                      })}
                    </div>
                  )}
                </section>
              </>
            )}
          </>
        )}
      </main>
    </div>
  );
}