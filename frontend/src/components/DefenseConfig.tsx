import type { Defense, Technique, RecalledMemory } from "../api/stream";

interface DefenseConfigProps {
  defenses: Defense[];
  mechanics?: Technique[];
  recalledMemories?: RecalledMemory[];
}

function memoryText(m: RecalledMemory): string {
  return (m.memory ?? m.text ?? "").trim() || "(empty memory)";
}

export default function DefenseConfig({
  defenses,
  mechanics = [],
  recalledMemories = [],
}: DefenseConfigProps) {
  return (
    <div className="space-y-6">
      {recalledMemories.length > 0 && (
        <section>
          <h3 className="mb-2 text-sm font-semibold text-slate-700">
            🧠 Recalled from prior analyses ({recalledMemories.length})
          </h3>
          <ul className="list-disc space-y-1 pl-5 text-sm text-slate-600">
            {recalledMemories.map((m, i) => (
              <li key={i}>
                {memoryText(m)}
                {typeof m.score === "number" && (
                  <span className="text-slate-400">
                    {" "}
                    — relevance {m.score.toFixed(3)}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      {mechanics.length > 0 && (
        <section>
          <h3 className="mb-2 text-sm font-semibold text-slate-700">
            Extracted mechanics
          </h3>
          <div className="overflow-x-auto rounded-md border border-slate-200">
            <table className="w-full border-collapse text-left text-sm">
              <thead className="bg-slate-50 text-slate-600">
                <tr>
                  <th className="px-3 py-2 font-medium">Tactic</th>
                  <th className="px-3 py-2 font-medium">Technique</th>
                  <th className="px-3 py-2 font-medium">Name</th>
                  <th className="px-3 py-2 font-medium">Evidence</th>
                </tr>
              </thead>
              <tbody>
                {mechanics.map((t, i) => (
                  <tr key={i} className="border-t border-slate-100">
                    <td className="px-3 py-2">{t.tactic}</td>
                    <td className="px-3 py-2 font-mono text-xs">
                      {t.technique_id}
                    </td>
                    <td className="px-3 py-2">{t.name}</td>
                    <td className="px-3 py-2 text-slate-500">{t.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <section>
        <h3 className="mb-2 text-sm font-semibold text-slate-700">
          🛡️ Defense configuration
        </h3>
        {defenses.length === 0 ? (
          <p className="text-sm text-slate-500">
            No defense configuration was produced for this submission.
          </p>
        ) : (
          <div className="overflow-x-auto rounded-md border border-slate-200">
            <table className="w-full border-collapse text-left text-sm">
              <thead className="bg-slate-50 text-slate-600">
                <tr>
                  <th className="px-3 py-2 font-medium">Technique</th>
                  <th className="px-3 py-2 font-medium">Mitigation</th>
                  <th className="px-3 py-2 font-medium">Action</th>
                  <th className="px-3 py-2 font-medium">Rationale</th>
                </tr>
              </thead>
              <tbody>
                {defenses.map((d, i) => (
                  <tr key={i} className="border-t border-slate-100">
                    <td className="px-3 py-2 font-mono text-xs">
                      {d.technique_id}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">
                      {d.mitigation_id}
                    </td>
                    <td className="px-3 py-2">{d.action}</td>
                    <td className="px-3 py-2 text-slate-500">{d.rationale}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
