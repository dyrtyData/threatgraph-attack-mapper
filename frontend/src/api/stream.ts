// POST-SSE reader for the FastAPI `/{agent}/stream` endpoint.
//
// Native `EventSource` is GET-only, so we drive the stream ourselves with
// `fetch` + `response.body.getReader()` + `TextDecoder`, buffering the byte
// stream and splitting SSE frames on the blank-line delimiter ("\n\n"). Each
// frame's `data:` line is parsed into the toolkit's line protocol:
//
//   data: {"type":"message","content": <ChatMessage>}\n\n
//   data: {"type":"token","content": "<str>"}\n\n
//   data: {"type":"error","content": "<str>"}\n\n
//   data: [DONE]\n\n   <- terminates the stream
//
// The terminal `threatgraph` output arrives as a `custom` ChatMessage whose
// `custom_data` carries { mechanics, mermaid, defense_config, recalled_memories }.

export interface Technique {
  tactic: string;
  technique_id: string;
  name: string;
  evidence: string;
}

export interface Defense {
  technique_id: string;
  mitigation_id: string;
  action: string;
  rationale: string;
}

export interface RecalledMemory {
  memory?: string;
  text?: string;
  score?: number;
  [key: string]: unknown;
}

export interface ThreatGraphData {
  mechanics?: Technique[];
  mermaid?: string;
  defense_config?: Defense[];
  recalled_memories?: RecalledMemory[];
}

export interface ChatMessage {
  type: "human" | "ai" | "tool" | "custom";
  content: string;
  tool_calls?: unknown[];
  tool_call_id?: string | null;
  run_id?: string | null;
  response_metadata?: Record<string, unknown>;
  custom_data?: Record<string, unknown>;
}

export interface StreamHandlers {
  /** A token chunk streamed from an LLM (only when stream_tokens=true). */
  onToken?: (token: string) => void;
  /** A complete intermediate/terminal ChatMessage. */
  onMessage?: (message: ChatMessage) => void;
  /** The terminal `custom` threatgraph payload (mermaid + defenses + memories). */
  onThreatGraph?: (data: ThreatGraphData) => void;
  /** A server-emitted error frame. */
  onError?: (error: string) => void;
}

export interface StreamOptions extends StreamHandlers {
  message: string;
  model?: string;
  threadId?: string;
  userId?: string;
  streamTokens?: boolean;
  agent?: string;
  signal?: AbortSignal;
}

const AGENT_URL: string =
  import.meta.env.VITE_AGENT_URL ?? "http://localhost:8081";
const AGENT_TOKEN: string | undefined = import.meta.env.VITE_AGENT_TOKEN;

/** Type guard for the terminal `custom` threatgraph message. */
export function isThreatGraphMessage(msg: ChatMessage): boolean {
  return (
    msg.type === "custom" &&
    !!msg.custom_data &&
    "mermaid" in (msg.custom_data as Record<string, unknown>)
  );
}

/** Extract the strongly-typed threatgraph payload from a custom message. */
export function extractThreatGraphData(msg: ChatMessage): ThreatGraphData {
  const d = (msg.custom_data ?? {}) as Record<string, unknown>;
  return {
    mechanics: (d.mechanics as Technique[]) ?? [],
    mermaid: (d.mermaid as string) ?? "",
    defense_config: (d.defense_config as Defense[]) ?? [],
    recalled_memories: (d.recalled_memories as RecalledMemory[]) ?? [],
  };
}

/** Parse one raw SSE `data:` payload; returns null on `[DONE]` / non-data. */
function parseFrame(frame: string):
  | { kind: "token"; content: string }
  | { kind: "message"; content: ChatMessage }
  | { kind: "error"; content: string }
  | { kind: "done" }
  | null {
  // A frame may contain multiple lines (e.g. `event:` + `data:`); we only care
  // about the `data:` line(s), per the toolkit protocol.
  for (const rawLine of frame.split("\n")) {
    const line = rawLine.trimStart();
    if (!line.startsWith("data:")) continue;
    const data = line.slice(5).trim();
    if (data === "[DONE]") return { kind: "done" };
    if (!data) continue;
    let parsed: { type: string; content: unknown };
    try {
      parsed = JSON.parse(data);
    } catch (e) {
      throw new Error(`Error JSON parsing message from server: ${String(e)}`);
    }
    switch (parsed.type) {
      case "token":
        return { kind: "token", content: String(parsed.content) };
      case "message":
        return { kind: "message", content: parsed.content as ChatMessage };
      case "error":
        return { kind: "error", content: String(parsed.content) };
      default:
        return null;
    }
  }
  return null;
}

/**
 * Stream a threat-intel analysis from the agent service.
 *
 * Resolves when the server sends `[DONE]` (or the body ends). Throws on
 * network / HTTP / abort errors so the caller can surface them.
 */
export async function streamThreatGraph(opts: StreamOptions): Promise<void> {
  const {
    message,
    model,
    threadId,
    userId,
    streamTokens = true,
    agent = "threatgraph",
    signal,
    onToken,
    onMessage,
    onThreatGraph,
    onError,
  } = opts;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (AGENT_TOKEN) headers["Authorization"] = `Bearer ${AGENT_TOKEN}`;

  const body: Record<string, unknown> = {
    message,
    stream_tokens: streamTokens,
    agent_config: {},
  };
  if (model) body.model = model;
  if (threadId) body.thread_id = threadId;
  if (userId) body.user_id = userId;

  const response = await fetch(`${AGENT_URL}/${agent}/stream`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    signal,
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `Agent service returned ${response.status} ${response.statusText}${
        text ? `: ${text}` : ""
      }`,
    );
  }
  if (!response.body) {
    throw new Error("Response has no readable body (SSE stream unavailable).");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      // Frame-split on the blank-line delimiter; keep the incomplete tail.
      let sep: number;
      while ((sep = buffer.indexOf("\n\n")) !== -1) {
        const frame = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        const parsed = parseFrame(frame);
        if (!parsed) continue;
        if (parsed.kind === "done") return;
        if (parsed.kind === "token") {
          onToken?.(parsed.content);
        } else if (parsed.kind === "error") {
          onError?.(parsed.content);
        } else if (parsed.kind === "message") {
          onMessage?.(parsed.content);
          if (isThreatGraphMessage(parsed.content)) {
            onThreatGraph?.(extractThreatGraphData(parsed.content));
          }
        }
      }
    }

    // Flush any trailing complete frame left in the buffer.
    const tail = buffer.trim();
    if (tail) {
      const parsed = parseFrame(tail);
      if (parsed && parsed.kind !== "done") {
        if (parsed.kind === "token") onToken?.(parsed.content);
        else if (parsed.kind === "error") onError?.(parsed.content);
        else if (parsed.kind === "message") {
          onMessage?.(parsed.content);
          if (isThreatGraphMessage(parsed.content)) {
            onThreatGraph?.(extractThreatGraphData(parsed.content));
          }
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}

export { AGENT_URL };
