import { useState } from "react";
import { runVerifyMatrix } from "../api";

export default function VerifyGrid({ onSelectFixture }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleRun = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await runVerifyMatrix();
      setData(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="space-y-4">
      <div className="bg-white border-2 border-black shadow-pixel p-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="font-pixel text-sm uppercase">
            {data
              ? `${data.total}-Fixture Verification Matrix`
              : "Fixture Verification Matrix"}
          </h2>
          <p className="text-xs text-neutral-600 mt-1">
            Runs all offline fixtures from <code>verify.py</code> against the
            deterministic core (no LLM key required).
          </p>
        </div>

        <button
          onClick={handleRun}
          disabled={loading}
          className="px-4 py-2 bg-cobalt text-white font-pixel text-xs border-2 border-black shadow-pixel hover:translate-x-[1px] hover:translate-y-[1px] hover:shadow-pixel-sm disabled:opacity-50"
        >
          {loading ? "RUNNING FIXTURES..." : "RUN VERIFY SUITE ->"}
        </button>
      </div>

      {error && (
        <div className="bg-[#E60023] text-white border-2 border-black p-3 text-xs font-pixel">
          ERROR: {error}
        </div>
      )}

      {data && (
        <div className="space-y-3">
          {/* Summary Bar */}
          <div className="bg-white border-2 border-black shadow-pixel p-3 flex flex-wrap items-center justify-between gap-2">
            <div className="font-pixel text-sm">
              SCORE:{" "}
              <span
                className={
                  data.passed === data.total
                    ? "text-[#008A2E]"
                    : "text-[#E60023]"
                }
              >
                {data.passed}/{data.total} PASSED
              </span>
            </div>
            <div className="text-xs text-neutral-600">
              Click any row to open it in the Scan tab.
            </div>
          </div>

          {/* Matrix Table */}
          <div className="bg-white border-2 border-black shadow-pixel overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-black text-white font-pixel text-[10px]">
                  <th className="p-2.5 border-r border-white/20">STATUS</th>
                  <th className="p-2.5 border-r border-white/20">FIXTURE</th>
                  <th className="p-2.5 border-r border-white/20">EXPECTED</th>
                  <th className="p-2.5 border-r border-white/20">GOT</th>
                  <th className="p-2.5">EXIT</th>
                </tr>
              </thead>
              <tbody>
                {data.results.map((row) => (
                  <tr
                    key={row.fixture}
                    onClick={() => onSelectFixture(`fixtures/${row.fixture}`)}
                    className="border-t-2 border-black hover:bg-paper cursor-pointer"
                  >
                    <td className="p-2.5 border-r border-black/20">
                      <span
                        className={`px-2 py-0.5 font-pixel text-[10px] border border-black ${
                          row.passed
                            ? "bg-[#008A2E] text-white"
                            : "bg-[#E60023] text-white"
                        }`}
                      >
                        {row.passed ? "PASS" : "FAIL"}
                      </span>
                    </td>
                    <td className="p-2.5 border-r border-black/20 font-bold">
                      {row.fixture}
                    </td>
                    <td className="p-2.5 border-r border-black/20">
                      {row.expected}
                    </td>
                    <td className="p-2.5 border-r border-black/20">
                      {row.got}
                    </td>
                    <td className="p-2.5 font-pixel text-[10px]">
                      {row.exit_code}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  );
}