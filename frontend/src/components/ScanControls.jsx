export default function ScanControls({
  fixtures,
  form,
  setForm,
  onRunScan,
  onUploadReport,
  scanning,
}) {
  const handleFile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const json = JSON.parse(reader.result);
        onUploadReport(json);
      } catch {
        alert("Invalid report.json file");
      }
    };
    reader.readAsText(file);
  };

  return (
    <section className="bg-white border-2 border-black shadow-pixel p-4 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b-2 border-black pb-2">
        <h2 className="font-pixel text-sm uppercase">01 // Scan Target</h2>
        <label className="cursor-pointer px-2.5 py-1 text-xs font-pixel bg-paper border-2 border-black hover:bg-neutral-200 shadow-pixel-sm">
          LOAD REPORT.JSON
          <input
            type="file"
            accept=".json"
            onChange={handleFile}
            className="hidden"
          />
        </label>
      </div>

      {/* Fixture dropdown + Project path */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <label className="block font-pixel text-[11px] mb-1">
            DEMO FIXTURE ({fixtures.length})
          </label>
          <select
            value={
              fixtures.some((f) => f.path === form.project) ? form.project : ""
            }
            onChange={(e) => {
              if (e.target.value) {
                setForm((f) => ({
                  ...f,
                  project: e.target.value,
                  package: "",
                  version: "",
                }));
              }
            }}
            className="w-full px-2.5 py-2 text-xs bg-paper border-2 border-black focus:outline-none focus:border-cobalt"
          >
            <option value="">-- pick a fixture --</option>
            {fixtures.map((fx) => (
              <option key={fx.name} value={fx.path}>
                {fx.name} ({fx.expected_verdict})
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block font-pixel text-[11px] mb-1">
            PROJECT PATH
          </label>
          <input
            type="text"
            value={form.project}
            onChange={(e) =>
              setForm((f) => ({ ...f, project: e.target.value }))
            }
            placeholder="fixtures/app_vuln"
            className="w-full px-2.5 py-2 text-xs bg-paper border-2 border-black focus:outline-none focus:border-cobalt"
          />
        </div>
      </div>

      {/* Optional Live OSV fetch */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div>
          <label className="block font-pixel text-[11px] mb-1">
            LIVE PACKAGE (OPTIONAL)
          </label>
          <input
            type="text"
            value={form.package}
            onChange={(e) =>
              setForm((f) => ({ ...f, package: e.target.value }))
            }
            placeholder="e.g. PyYAML"
            className="w-full px-2.5 py-2 text-xs bg-paper border-2 border-black focus:outline-none focus:border-cobalt"
          />
        </div>
        <div>
          <label className="block font-pixel text-[11px] mb-1">
            PINNED VERSION
          </label>
          <input
            type="text"
            value={form.version}
            onChange={(e) =>
              setForm((f) => ({ ...f, version: e.target.value }))
            }
            placeholder="e.g. 5.3.1"
            className="w-full px-2.5 py-2 text-xs bg-paper border-2 border-black focus:outline-none focus:border-cobalt"
          />
        </div>
        <div>
          <label className="block font-pixel text-[11px] mb-1">
            ADVISORY JSON (OFFLINE)
          </label>
          <input
            type="text"
            value={form.advisory}
            onChange={(e) =>
              setForm((f) => ({ ...f, advisory: e.target.value }))
            }
            placeholder="examples/advisory-sample.json"
            className="w-full px-2.5 py-2 text-xs bg-paper border-2 border-black focus:outline-none focus:border-cobalt"
          />
        </div>
      </div>

      {/* Toggles + Submit */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
        <div className="flex flex-wrap items-center gap-4 text-xs">
          <label
            className="flex items-center gap-2 cursor-pointer select-none"
            title="Parses the dependency's own source from PyPI. Needs a pinned package + version; this is what lets a SafeLoader-only call prove not_reachable."
          >
            <input
              type="checkbox"
              checked={form.with_deps}
              onChange={(e) =>
                setForm((f) => ({ ...f, with_deps: e.target.checked }))
              }
              className="w-4 h-4 accent-cobalt border-2 border-black"
            />
            <span className="font-pixel text-[11px]">
              DEPENDENCY SOURCE (--with-deps)
            </span>
          </label>

          <label
            className="flex items-center gap-2 cursor-pointer select-none"
            title="Explains every uncertain result: blocker, deterministic reasoning, and the discriminating check."
          >
            <input
              type="checkbox"
              checked={form.explain}
              onChange={(e) =>
                setForm((f) => ({ ...f, explain: e.target.checked }))
              }
              className="w-4 h-4 accent-cobalt border-2 border-black"
            />
            <span className="font-pixel text-[11px]">
              UNCERTAIN EXPLAINER (--explain)
            </span>
          </label>

          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={form.with_proof}
              onChange={(e) =>
                setForm((f) => ({ ...f, with_proof: e.target.checked }))
              }
              className="w-4 h-4 accent-cobalt border-2 border-black"
            />
            <span className="font-pixel text-[11px]">
              EXECUTION WITNESS (--with-proof)
            </span>
          </label>

          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={form.with_llm}
              onChange={(e) =>
                setForm((f) => ({
                  ...f,
                  with_llm: e.target.checked,
                  no_llm: !e.target.checked,
                }))
              }
              className="w-4 h-4 accent-cobalt border-2 border-black"
            />
            <span className="font-pixel text-[11px]">
              LLM RESOLVER / EXPLAINER
            </span>
          </label>
        </div>

        <button
          onClick={onRunScan}
          disabled={scanning || !form.project}
          className="px-4 py-2 bg-cobalt text-white font-pixel text-xs border-2 border-black shadow-pixel hover:translate-x-[1px] hover:translate-y-[1px] hover:shadow-pixel-sm disabled:opacity-50"
        >
          {scanning ? "RUNNING..." : "SCAN PROJECT ->"}
        </button>
      </div>
    </section>
  );
}