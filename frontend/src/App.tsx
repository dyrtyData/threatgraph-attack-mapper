import { useRef, useState } from "react";
import {
  streamThreatGraph,
  AGENT_URL,
  type ThreatGraphData,
} from "./api/stream";
import AttackGraph from "./components/AttackGraph";
import DefenseConfig from "./components/DefenseConfig";

const SAMPLE = `An adversary sent a spearphishing email with a macro-enabled Word attachment.
When opened, the macro launched PowerShell to download a second-stage payload.
The actor then dumped LSASS memory to harvest credentials and used those
credentials to move laterally over RDP before exfiltrating data to a cloud store.`;

export default function App() {
  const [text, setText] = useState<string>(SAMPLE);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ThreatGraphData | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  async function handleSubmit() {
    if (!text.trim() || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      await streamThreatGraph({
        message: text,
        streamTokens: false,
        signal: controller.signal,
        onThreatGraph: (data) => setResult(data),
        onError: (msg) => setError(msg),
      });
    } catch (e) {
      if ((e as Error).name !== "AbortError") {
        setError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      setLoading(false);
      abortRef.current = null;
    }
  }

  function handleCancel() {
    abortRef.current?.abort();
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <div className="mx-auto max-w-4xl px-4 py-8">
        <header className="mb-6">
          <h1 className="text-2xl font-bold tracking-tight">
            ThreatGraph — Attack-Graph Mapper
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            Paste unstructured threat-intel text; the agent extracts a MITRE
            ATT&CK kill-chain graph and a grounded defense configuration.
          </p>
          <p className="mt-1 text-xs text-slate-400">
            Backend: <code>{AGENT_URL}/threatgraph/stream</code>
          </p>
        </header>

        <section className="mb-6">
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={8}
            placeholder="Paste threat-intel text here…"
            className="w-full resize-y rounded-md border border-slate-300 bg-white p-3 font-mono text-sm shadow-sm focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500"
          />
          <div className="mt-3 flex items-center gap-3">
            <button
              onClick={handleSubmit}
              disabled={loading || !text.trim()}
              className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? "Analyzing…" : "Analyze"}
            </button>
            {loading && (
              <button
                onClick={handleCancel}
                className="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-100"
              >
                Cancel
              </button>
            )}
            {loading && (
              <span
                data-testid="spinner"
                className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-slate-800"
                aria-label="loading"
              />
            )}
          </div>
        </section>

        {error && (
          <div className="mb-6 rounded-md border border-red-300 bg-red-50 p-4 text-sm text-red-700">
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-6">
            <section>
              <h2 className="mb-2 text-lg font-semibold">🗺️ Attack graph</h2>
              {result.mermaid ? (
                <AttackGraph chart={result.mermaid} />
              ) : (
                <p className="text-sm text-slate-500">
                  No attack graph was produced for this submission.
                </p>
              )}
            </section>

            <section>
              <DefenseConfig
                defenses={result.defense_config ?? []}
                mechanics={result.mechanics ?? []}
                recalledMemories={result.recalled_memories ?? []}
              />
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
