import { useState } from "react";
import { Terminal, Dice5 } from "lucide-react";
import { PAYLOAD_DATA, CATEGORIES, type Category, type Payload } from "./Payloads";
import Footer from "./components/Footer";

export default function PayloadDashboard() {
  const [activeCategory, setActiveCategory] = useState<Category>(CATEGORIES[0]);
  const [search, setSearch] = useState("");
  const [showAll, setShowAll] = useState(false);
  const [selectedPayload, setSelectedPayload] = useState<Payload | null>(null);
  const [randomPayload, setRandomPayload] = useState<Payload | null>(null);

  // Get payload list
  let payloadList: Payload[] = showAll
    ? Object.values(PAYLOAD_DATA).flat()
    : PAYLOAD_DATA[activeCategory];

  payloadList = payloadList.filter((p) =>
    p.payload.toLowerCase().includes(search.toLowerCase())
  );

  function generateRandomPayload() {
    const all = Object.values(PAYLOAD_DATA).flat();
    const random = all[Math.floor(Math.random() * all.length)];
    setRandomPayload(random);
  }

  function exportJSON() {
    const blob = new Blob([JSON.stringify(PAYLOAD_DATA, null, 2)], {
      type: "application/json",
    });
    downloadFile(blob, "payloads.json");
  }

  function exportTXT() {
    const text = Object.entries(PAYLOAD_DATA)
      .map(([cat, list]) =>
        `### ${cat}\n` + list.map((p) => p.payload).join("\n")
      )
      .join("\n\n");

    const blob = new Blob([text], { type: "text/plain" });
    downloadFile(blob, "payloads.txt");
  }

  function downloadFile(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="min-h-screen flex flex-col bg-zinc-950 text-zinc-100">

      {/* HEADER */}
      <header className="border-b border-zinc-800 bg-zinc-950 sticky top-0 z-10 px-4 h-16 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="w-5 h-5" />
          <span className="font-semibold">Payload UI Pro</span>
        </div>

        <div className="flex gap-2">
          <button
            onClick={generateRandomPayload}
            className="btn btn-light flex items-center gap-1 shadow-md hover:shadow-white/20"
          >
            <Dice5 className="w-3 h-3" />
            Random
          </button>

          <button onClick={exportJSON} className="btn btn-dark">
            JSON
          </button>

          <button onClick={exportTXT} className="btn btn-dark">
            TXT
          </button>
        </div>
      </header>

      <div className="flex-1 container mx-auto px-4 py-6 flex gap-6">

        {/* SIDEBAR */}
        <aside className="w-52 border-r border-zinc-800 pr-3">
          <h3 className="text-xs text-zinc-500 mb-2">Categories</h3>

          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              onClick={() => setActiveCategory(cat)}
              className={`block w-full text-left px-2 py-1 rounded text-sm transition-all 
                hover:scale-[1.02] active:scale-[0.97]
                ${
                  activeCategory === cat
                    ? "bg-zinc-800 text-white shadow-inner"
                    : "text-zinc-400 hover:bg-zinc-900 hover:text-white"
                }`}
            >
              {cat} ({PAYLOAD_DATA[cat].length})
            </button>
          ))}
        </aside>

        {/* MAIN GRID */}
        <main className="flex-1 grid grid-cols-1 md:grid-cols-2 gap-6">

          {/* PAYLOAD LIST */}
          <div>
            <h2 className="text-lg font-semibold mb-2">Payload Database</h2>

            <input
              placeholder="Search payload..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full px-2 py-1 bg-zinc-900 border border-zinc-800 rounded mb-2"
            />

            <label className="text-xs text-zinc-500">
              <input
                type="checkbox"
                checked={showAll}
                onChange={() => setShowAll(!showAll)}
                className="mr-1"
              />
              Show all categories
            </label>

            <div className="mt-3 border border-zinc-800 rounded max-h-[500px] overflow-y-auto">
              {payloadList.map((p, i) => (
                <div
                  key={i}
                  onClick={() => setSelectedPayload(p)}
                  className="p-2 border-b border-zinc-800 hover:bg-zinc-900 cursor-pointer 
                             transition active:bg-zinc-800 active:scale-[0.995]"
                >
                  <div className="text-xs font-mono break-all">
                    {p.payload}
                  </div>
                  <div className="text-[10px] text-zinc-500 mt-1">
                    {p.tags.map((t) => `#${t}`).join(" ")}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* RIGHT PANEL */}
          <div className="space-y-4">

            {/* EXPLANATION PANEL */}
            <div className="border border-zinc-800 rounded p-4 bg-zinc-900">
              <h2 className="text-lg font-semibold mb-2">
                Payload Explanation
              </h2>

              {selectedPayload ? (
                <>
                  <pre className="bg-black p-2 text-xs font-mono rounded break-all">
                    {selectedPayload.payload}
                  </pre>

                  <p className="mt-2 text-sm text-zinc-300">
                    {selectedPayload.description}
                  </p>

                  <div className="mt-2 text-xs text-zinc-400">
                    Tags: {selectedPayload.tags.map((t) => `#${t}`).join(" ")}
                  </div>

                  <button
                    onClick={() =>
                      navigator.clipboard.writeText(selectedPayload.payload)
                    }
                    className="btn btn-light shadow hover:shadow-white/20 mt-3"
                  >
                    Copy Payload
                  </button>
                </>
              ) : (
                <p className="text-zinc-500 text-sm">
                  Click a payload to see explanation.
                </p>
              )}
            </div>

            {/* RANDOM PAYLOAD PANEL */}
            {randomPayload && (
              <div className="border border-zinc-800 rounded p-4 bg-black">
                <h3 className="text-sm font-semibold mb-2">🎲 Random Payload</h3>

                <pre className="text-xs font-mono break-all">
                  {randomPayload.payload}
                </pre>

                <p className="text-xs text-zinc-400 mt-1">
                  {randomPayload.description}
                </p>

                <div className="text-[10px] text-zinc-500 mt-1">
                  {randomPayload.tags.map((t) => `#${t}`).join(" ")}
                </div>

                <button
                  onClick={() =>
                    navigator.clipboard.writeText(randomPayload.payload)
                  }
                  className="btn btn-light shadow hover:shadow-white/20 mt-2"
                >
                  Copy Random Payload
                </button>
              </div>
            )}

          </div>
        </main>
      </div>

      <Footer />
    </div>
  );
}
