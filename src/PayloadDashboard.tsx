import { useState, useEffect } from "react";
import { 
  Terminal, 
  Dice5, 
  Copy, 
  CheckCheck, 
  Download, 
  Search, 
  ShieldAlert, 
  ChevronRight,
  Database,
  Info,
  FileText
} from "lucide-react";
import { PAYLOAD_DATA, CATEGORIES, type Category, type Payload } from "./Payloads";
import Footer from "./components/Footer";

export default function PayloadDashboard() {
  const [activeCategory, setActiveCategory] = useState<Category>("XSS");
  const [search, setSearch] = useState("");
  const [showAll, setShowAll] = useState(false);
  const [selectedPayload, setSelectedPayload] = useState<Payload | null>(null);
  const [copied, setCopied] = useState(false);
  
  // Initialize selection
  useEffect(() => {
    if (!showAll && PAYLOAD_DATA[activeCategory].length > 0) {
      setSelectedPayload(PAYLOAD_DATA[activeCategory][0]);
    }
  }, [activeCategory, showAll]);

  let payloadList: Payload[] = showAll
    ? CATEGORIES.flatMap(cat => PAYLOAD_DATA[cat])
    : PAYLOAD_DATA[activeCategory];

  payloadList = payloadList.filter((p) =>
    p.payload.toLowerCase().includes(search.toLowerCase()) || 
    p.description.toLowerCase().includes(search.toLowerCase()) ||
    p.tags.some(t => t.toLowerCase().includes(search.toLowerCase()))
  );

  function handleCopy(text: string) {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function generateRandomPayload() {
    const all = CATEGORIES.flatMap(cat => PAYLOAD_DATA[cat]);
    const random = all[Math.floor(Math.random() * all.length)];
    setActiveCategory(CATEGORIES.find(c => PAYLOAD_DATA[c].includes(random)) || "XSS");
    setShowAll(false);
    setSearch("");
    setSelectedPayload(random);
  }

  function exportJSON() {
    const content = JSON.stringify(PAYLOAD_DATA, null, 2);
    const blob = new Blob([content], { type: "application/json" });
    downloadFile(blob, "payloads_db.json");
  }

  function exportTXT() {
    // Generate a Fuzzer-Ready wordlist (One payload per line, no comments)
    // This makes it genuinely useful for Burp Suite Intruder or FFUF
    const content = Object.values(PAYLOAD_DATA)
      .flat()
      .map(p => p.payload)
      .join("\n");
      
    const blob = new Blob([content], { type: "text/plain" });
    downloadFile(blob, "fuzz_wordlist.txt");
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
    <div className="min-h-screen flex flex-col bg-background text-foreground relative overflow-hidden font-sans">
      
      {/* Background FX */}
      <div className="absolute inset-0 cyber-grid opacity-20 pointer-events-none z-0"></div>
      
      {/* HEADER */}
      <header className="border-b border-white/10 bg-background/80 backdrop-blur-md sticky top-0 z-50 h-16">
        <div className="container mx-auto h-full px-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-zinc-900 border border-zinc-700 rounded-lg shadow-lg shadow-cyan-500/10">
              <Terminal className="w-5 h-5 text-cyan-500" />
            </div>
            <div>
              <h1 className="font-bold tracking-tight text-lg leading-none">Payload<span className="text-cyan-500">Gen</span></h1>
              <p className="text-[10px] text-muted-foreground font-mono">v2.5.0-ULTIMATE</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={generateRandomPayload}
              className="hidden md:flex items-center gap-2 px-3 py-1.5 text-xs font-mono border border-cyan-500/30 text-cyan-400 rounded hover:bg-cyan-500/10 hover:border-cyan-500 transition-all duration-300"
            >
              <Dice5 className="w-3.5 h-3.5" />
              <span>RND_INIT</span>
            </button>
            <div className="h-6 w-px bg-white/10 hidden md:block"></div>
            
            <button onClick={exportJSON} className="p-2 text-muted-foreground hover:text-foreground transition-colors group relative" title="Export JSON DB">
              <Database className="w-4 h-4" />
              <span className="absolute -bottom-8 left-1/2 -translate-x-1/2 text-[10px] bg-black border border-white/20 px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">Full DB (JSON)</span>
            </button>
            
            <button onClick={exportTXT} className="p-2 text-muted-foreground hover:text-foreground transition-colors group relative" title="Export Wordlist">
              <FileText className="w-4 h-4" />
               <span className="absolute -bottom-8 left-1/2 -translate-x-1/2 text-[10px] bg-black border border-white/20 px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">Fuzzer Wordlist (TXT)</span>
            </button>
          </div>
        </div>
      </header>

      <div className="flex-1 container mx-auto px-4 py-8 relative z-10 flex flex-col lg:flex-row gap-6">

        {/* SIDEBAR (Categories) */}
        <aside className="lg:w-64 flex-shrink-0 space-y-6">
          <div className="bg-card/30 border border-white/5 rounded-xl p-4 backdrop-blur-sm">
            <h3 className="text-xs font-mono text-muted-foreground mb-3 uppercase tracking-wider">Modules</h3>
            <div className="flex flex-wrap lg:flex-col gap-1">
              <button
                 onClick={() => { setShowAll(true); setSelectedPayload(null); }}
                 className={`w-full text-left px-3 py-2 rounded-md text-sm font-medium transition-all duration-200 flex items-center justify-between group
                  ${showAll 
                    ? "bg-primary text-primary-foreground shadow-[0_0_15px_rgba(255,255,255,0.1)]" 
                    : "text-muted-foreground hover:text-foreground hover:bg-white/5"}`}
              >
                <span>ALL_PAYLOADS</span>
                {showAll && <ChevronRight className="w-3 h-3" />}
              </button>
              
              <div className="h-px bg-white/5 my-2 lg:block hidden"></div>

              {CATEGORIES.map((cat) => (
                <button
                  key={cat}
                  onClick={() => { setActiveCategory(cat); setShowAll(false); }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm font-medium transition-all duration-200 flex items-center justify-between group
                    ${activeCategory === cat && !showAll
                      ? "bg-zinc-800 text-white border-l-2 border-cyan-500 pl-[10px]"
                      : "text-zinc-400 hover:text-white hover:bg-white/5"}`}
                >
                  <span className="flex items-center gap-2">
                    {cat}
                  </span>
                  <span className="text-[10px] font-mono opacity-50 bg-black/30 px-1.5 rounded">
                    {PAYLOAD_DATA[cat].length}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </aside>

        {/* MAIN CONTENT AREA */}
        <main className="flex-1 min-w-0 grid grid-cols-1 md:grid-cols-2 gap-6 h-[calc(100vh-10rem)]">
          
          {/* LEFT: LIST */}
          <div className="flex flex-col h-full bg-card/30 border border-white/5 rounded-xl backdrop-blur-sm overflow-hidden">
            <div className="p-4 border-b border-white/5 space-y-3">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Search payloads..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full bg-black/40 border border-white/10 rounded-lg pl-9 pr-4 py-2 text-sm text-foreground focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 font-mono transition-all"
                />
              </div>
              <div className="flex items-center justify-between text-xs text-muted-foreground font-mono">
                <span>{payloadList.length} results found</span>
                <span>{showAll ? "ALL DB" : activeCategory}</span>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-2 space-y-1 scrollbar-hide">
              {payloadList.map((p, i) => (
                <div
                  key={i}
                  onClick={() => setSelectedPayload(p)}
                  className={`p-3 rounded-lg cursor-pointer border transition-all duration-200 group
                    ${selectedPayload === p 
                      ? "bg-cyan-500/10 border-cyan-500/30 shadow-[inset_0_0_10px_rgba(0,255,255,0.05)]" 
                      : "bg-transparent border-transparent hover:bg-white/5 hover:border-white/5"}`}
                >
                  <div className="font-mono text-xs text-foreground truncate group-hover:text-cyan-400 transition-colors">
                    {p.payload}
                  </div>
                  <div className="flex items-center gap-2 mt-2">
                    {p.tags.slice(0, 3).map(tag => (
                      <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-muted-foreground border border-white/5">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
              
              {payloadList.length === 0 && (
                <div className="flex flex-col items-center justify-center h-40 text-muted-foreground">
                  <ShieldAlert className="w-8 h-8 mb-2 opacity-50" />
                  <span className="text-sm">No payloads found</span>
                </div>
              )}
            </div>
          </div>

          {/* RIGHT: DETAILS */}
          <div className="flex flex-col h-full bg-card/50 border border-white/10 rounded-xl backdrop-blur-md relative overflow-hidden">
            {selectedPayload ? (
              <div className="flex flex-col h-full">
                
                {/* Header (No Rainbow) */}
                <div className="p-6 border-b border-white/5">
                    <div className="flex justify-between items-start mb-2">
                        <h2 className="text-lg font-semibold text-white">Payload Inspector</h2>
                        <div className="flex gap-2">
                        {selectedPayload.tags.map(tag => (
                            <span key={tag} className="text-xs font-mono text-cyan-400 bg-cyan-900/20 px-2 py-0.5 rounded border border-cyan-900/50">#{tag}</span>
                        ))}
                        </div>
                    </div>
                </div>

                <div className="p-6 flex-1 overflow-y-auto space-y-6">
                  
                  {/* Code Block */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                        <label className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
                        Vector String
                        </label>
                        <span className="text-[10px] text-zinc-500 font-mono">Raw Text</span>
                    </div>
                    <div className="group relative">
                      <pre className="bg-black/80 border border-white/10 rounded-lg p-4 font-mono text-sm text-green-400 break-all whitespace-pre-wrap shadow-inner selection:bg-green-900 selection:text-white">
                        {selectedPayload.payload}
                      </pre>
                      <button
                        onClick={() => handleCopy(selectedPayload.payload)}
                        className="absolute right-2 top-2 p-1.5 rounded-md bg-white/10 text-white opacity-0 group-hover:opacity-100 transition-opacity hover:bg-white/20"
                      >
                        {copied ? <CheckCheck className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Description Block */}
                  <div>
                    <div className="flex items-center gap-2 mb-2 text-muted-foreground">
                        <Info className="w-3 h-3" />
                        <label className="text-xs font-mono uppercase tracking-wider">
                        Technical Analysis
                        </label>
                    </div>
                    <div className="text-sm text-zinc-300 leading-relaxed bg-white/5 p-4 rounded-lg border border-white/5">
                      {selectedPayload.description}
                    </div>
                  </div>
                </div>

                {/* Footer Action */}
                <div className="p-4 border-t border-white/5 bg-black/20">
                  <button
                    onClick={() => handleCopy(selectedPayload.payload)}
                    className="w-full py-3 rounded-lg font-mono text-sm font-medium bg-cyan-500 text-black hover:bg-cyan-400 hover:shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all duration-300 flex items-center justify-center gap-2"
                  >
                    {copied ? "COPIED TO CLIPBOARD" : "COPY PAYLOAD"}
                  </button>
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-muted-foreground p-6 text-center">
                <div className="w-16 h-16 rounded-full bg-white/5 flex items-center justify-center mb-4 animate-pulse-slow">
                  <Terminal className="w-8 h-8 opacity-50" />
                </div>
                <h3 className="text-lg font-medium text-white mb-2">Ready to Inject</h3>
                <p className="text-sm max-w-xs">Select a category from the sidebar or search for a specific vector to view details.</p>
              </div>
            )}
          </div>

        </main>
      </div>

      <Footer />
    </div>
  );
}