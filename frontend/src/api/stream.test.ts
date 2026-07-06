import { describe, it, expect, vi, afterEach } from "vitest";
import { streamThreatGraph, type ChatMessage } from "./stream";

/** Build a fetch Response whose body streams the given chunks as SSE bytes. */
function sseResponse(chunks: string[]): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const c of chunks) controller.enqueue(encoder.encode(c));
      controller.close();
    },
  });
  return new Response(body, { status: 200 });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("streamThreatGraph", () => {
  it("parses tokens, the terminal custom message, and stops on [DONE]", async () => {
    const custom: ChatMessage = {
      type: "custom",
      content: "",
      custom_data: {
        mermaid: "graph TD; A-->B;",
        mechanics: [
          { tactic: "Execution", technique_id: "T1059.001", name: "PowerShell", evidence: "ran ps" },
        ],
        defense_config: [
          { technique_id: "T1059.001", mitigation_id: "M1042", action: "restrict", rationale: "why" },
        ],
        recalled_memories: [],
      },
    };

    // Split a frame across two chunks to exercise the incomplete-tail buffering.
    const frames = [
      'data: {"type":"token","content":"hel',
      'lo"}\n\n',
      `data: ${JSON.stringify({ type: "message", content: custom })}\n\n`,
      "data: [DONE]\n\n",
    ];

    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(sseResponse(frames));

    const tokens: string[] = [];
    let graphData: unknown = null;

    await streamThreatGraph({
      message: "test",
      onToken: (t) => tokens.push(t),
      onThreatGraph: (d) => (graphData = d),
    });

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(tokens.join("")).toBe("hello");
    expect(graphData).toMatchObject({
      mermaid: "graph TD; A-->B;",
      mechanics: [{ technique_id: "T1059.001" }],
      defense_config: [{ mitigation_id: "M1042" }],
    });
  });

  it("surfaces a plain AI terminal message (no custom_data) as final text", async () => {
    // Simulates the input safety gate (block_unsafe_content) refusing an unsafe
    // input: the terminal message is a normal `ai` message with plain-text
    // refusal content and NO mermaid custom_data.
    const refusal: ChatMessage = {
      type: "ai",
      content:
        "I can't help with that request. The submitted text was flagged as unsafe.",
    };

    const frames = [
      `data: ${JSON.stringify({ type: "message", content: refusal })}\n\n`,
      "data: [DONE]\n\n",
    ];

    vi.spyOn(globalThis, "fetch").mockResolvedValue(sseResponse(frames));

    let finalText: string | null = null;
    let graphData: unknown = null;

    await streamThreatGraph({
      message: "unsafe input",
      onThreatGraph: (d) => (graphData = d),
      onFinalText: (t) => (finalText = t),
    });

    expect(graphData).toBeNull();
    expect(finalText).toBe(
      "I can't help with that request. The submitted text was flagged as unsafe.",
    );
  });

  it("does NOT emit final text on the happy path (graph produced)", async () => {
    const custom: ChatMessage = {
      type: "custom",
      content: "",
      custom_data: { mermaid: "graph TD; A-->B;", mechanics: [], defense_config: [], recalled_memories: [] },
    };
    const frames = [
      `data: ${JSON.stringify({ type: "message", content: custom })}\n\n`,
      "data: [DONE]\n\n",
    ];
    vi.spyOn(globalThis, "fetch").mockResolvedValue(sseResponse(frames));

    let finalText: string | null = null;
    let graphData: unknown = null;
    await streamThreatGraph({
      message: "safe input",
      onThreatGraph: (d) => (graphData = d),
      onFinalText: (t) => (finalText = t),
    });
    expect(graphData).not.toBeNull();
    expect(finalText).toBeNull();
  });

  it("surfaces server error frames", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      sseResponse(['data: {"type":"error","content":"boom"}\n\n', "data: [DONE]\n\n"]),
    );
    let err: string | null = null;
    await streamThreatGraph({ message: "x", onError: (e) => (err = e) });
    expect(err).toBe("boom");
  });

  it("throws on non-ok HTTP responses", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("nope", { status: 500, statusText: "Server Error" }),
    );
    await expect(streamThreatGraph({ message: "x" })).rejects.toThrow(/500/);
  });
});
