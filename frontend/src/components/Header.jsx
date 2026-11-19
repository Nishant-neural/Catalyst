export default function Header({ tab, setTab, onRunScan, scanning }) {
  return (
    <header className="sticky top-0 z-20 bg-paper/95 border-b-2 border-black">
      <div className="max-w-5xl mx-auto px-4 py-3 flex flex-wrap items-center justify-between gap-3">
        {/* Brand */}
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 bg-cobalt border-2 border-black flex items-center justify-center text-white font-pixel text-xs shadow-pixel-sm">
            PY
          </div>
          <span className="font-pixel text-lg tracking-wider">pyreach</span>
        </div>

        {/* Boxed Center Nav */}
        <nav className="flex border-2 border-black bg-white shadow-pixel-sm">
          {[
            { id: "scan", label: "SCAN" },
            { id: "verify", label: "VERIFY" },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setTab(item.id)}
              className={`px-4 py-1.5 font-pixel text-xs transition-colors border-r-2 last:border-r-0 border-black ${
                tab === item.id
                  ? "bg-black text-white"
                  : "bg-white text-black hover:bg-neutral-100"
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>

        {/* Cobalt CTA */}
        <button
          onClick={onRunScan}
          disabled={scanning}
          className="px-4 py-1.5 bg-cobalt text-white font-pixel text-xs border-2 border-black shadow-pixel hover:translate-x-[1px] hover:translate-y-[1px] hover:shadow-pixel-sm active:translate-x-[2px] active:translate-y-[2px] active:shadow-none disabled:opacity-60 transition-all"
        >
          {scanning ? "SCANNING..." : "RUN SCAN ->"}
        </button>
      </div>
    </header>
  );
}