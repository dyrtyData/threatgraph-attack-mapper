import { useEffect, useId, useRef, useState } from "react";
import mermaid from "mermaid";

// Initialize mermaid exactly once, at module load, with auto-render disabled —
// we drive rendering imperatively via `mermaid.render` (mirrors the reliable
// approach the Streamlit CDN fix used: no `startOnLoad`, explicit render call).
mermaid.initialize({ startOnLoad: false, theme: "default", securityLevel: "loose" });

interface AttackGraphProps {
  chart: string;
}

export default function AttackGraph({ chart }: AttackGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);
  // `useId()` yields values like ":r0:"; mermaid ids must be CSS-safe, so strip colons.
  const rawId = useId();
  const diagramId = `attackgraph-${rawId.replace(/:/g, "")}`;

  useEffect(() => {
    let cancelled = false;

    if (!chart?.trim()) {
      if (containerRef.current) containerRef.current.innerHTML = "";
      setError(null);
      return;
    }

    (async () => {
      try {
        await mermaid.parse(chart);
        const { svg } = await mermaid.render(diagramId, chart);
        if (!cancelled && containerRef.current) {
          containerRef.current.innerHTML = svg;
          setError(null);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
          if (containerRef.current) containerRef.current.innerHTML = "";
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [chart, diagramId]);

  if (error) {
    return (
      <div className="rounded-md border border-red-300 bg-red-50 p-4 text-sm text-red-700">
        <p className="font-semibold">Could not render attack graph</p>
        <pre className="mt-2 overflow-x-auto whitespace-pre-wrap text-xs">
          {error}
        </pre>
        <pre className="mt-2 overflow-x-auto rounded bg-white/60 p-2 text-xs text-slate-600">
          {chart}
        </pre>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      data-testid="attack-graph"
      className="flex w-full justify-center overflow-x-auto rounded-md border border-slate-200 bg-white p-4"
    />
  );
}
