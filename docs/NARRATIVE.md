# PF-001 — Project Narrative

Plain-language walkthrough of the Threat-Intel → Attack-Graph Mapper: what it does, how the
pieces fit, and why each pillar exists. Doubles as an interview talking-track.

---

## 1. What the product is

A security analyst pastes in a messy, unstructured **threat report** — e.g.:

> "The actor sent a phishing email with a macro-laden Word doc; on open it ran PowerShell to
> download a payload, created a scheduled task for persistence, then exfiltrated data over HTTPS."

The system automatically:
1. **understands** what the attacker did,
2. **draws** it as an interactive **Mermaid.js attack graph**, and
3. **proposes concrete defenses** for each step.

It turns a wall of prose into a picture + an action plan.

## 2. The pipeline (LangGraph orchestrates it)

LangGraph is a state machine: data flows through **nodes**, each doing one job and updating a
shared `State` object.

| Node | Job |
|---|---|
| `Extractor` | Read raw text, pull out discrete attacker **techniques** (phishing attachment, PowerShell exec, scheduled-task persistence, HTTPS exfil). |
| `Graph_Architect` | Turn those techniques into valid **Mermaid.js** so the UI renders the attack flow. |
| `Defensive_Guardrail` | For each technique, produce a **defensive configuration** (control/rule/setting to detect or block it). |

## 3. What MITRE ATT&CK is

**MITRE ATT&CK** is the free, public, industry-standard **encyclopedia of how attackers operate**:

- **Tactics** — the attacker's goal at a stage (Initial Access, Execution, Persistence, Exfiltration…).
- **Techniques** — *how* they do it, each with a stable ID: **T1566.001** "Spearphishing Attachment",
  **T1059.001** "PowerShell", **T1053.005** "Scheduled Task", **T1048** "Exfiltration Over
  Alternative Protocol".
- **Mitigations** — official recommended defenses, each with an ID: **M1049** "Antivirus/Antimalware",
  **M1042** "Disable or Remove Feature", **M1026** "Privileged Account Management".

It's a giant authoritative lookup table: *technique → what it is → how to defend against it* — the
common language every SOC uses.

## 4. Why RAG (grounding), and why it matters

An LLM alone will **hallucinate** — invent technique IDs, misremember mitigations, give generic
advice. Unacceptable for a security product.

**RAG (Retrieval-Augmented Generation):** instead of asking the LLM to recall from memory, we
**retrieve the relevant real ATT&CK entries** from a corpus and hand them to the LLM as context:
"base your answer on *these* authoritative facts." Output becomes **grounded** — traceable to real
MITRE IDs, not invented.

### How RAG "injects into" the nodes
- **`Extractor`:** "sent a booby-trapped Word attachment" doesn't obviously map to a canonical
  technique. We embed the phrase, retrieve the closest ATT&CK technique descriptions, and ask the
  LLM *"which official technique is this?"* → **T1566.001**, not a made-up label. *Grounding =
  accurate identification.*
- **`Defensive_Guardrail`:** now knowing the step is **T1059.001 (PowerShell)**, we retrieve the
  official mitigations linked to it (M1042, M1038, M1049…) and ask the LLM to *"write a defense
  config using these real controls."* → credible, industry-recognized defenses, not "use antivirus"
  fluff. *Grounding = real-world defenses.*

"Injecting into the nodes" literally means: **before the LLM generates, run a retrieval query and
prepend the retrieved ATT&CK facts to the prompt.**

## 5. Hybrid retrieval — why each piece

Retrieval quality determines grounding quality. The mature pipeline:

1. **Embedding model** → text → vectors; finds *semantically* similar entries ("booby-trapped doc"
   ≈ "malicious attachment"). Strong on meaning, weak on exact keywords.
2. **BM25 (sparse keyword search)** → nails exact terms like "PowerShell" or "T1059" that embeddings
   blur. Complementary to dense.
3. **RRF (Reciprocal Rank Fusion)** → merges the two ranked lists robustly, no weight-tuning.
4. **Cross-encoder reranker** → re-scores the fused top-N by reading *(query, candidate) together*
   (more accurate than embedding similarity) and reorders so the best 3–5 land at the top of the
   prompt — which matters because prompt space is limited.

Net: dense finds meaning, sparse nails keywords, RRF blends, reranker sharpens → the LLM sees the
most relevant ATT&CK facts.

## 6. How the six pillars wrap around it

- **Orchestration (LangGraph):** routes text → Extractor → RAG → Graph_Architect → Defensive_Guardrail.
- **Retrieval / RAG:** grounds Extractor + Defensive_Guardrail in ATT&CK (§4–5).
- **Memory (Mem0):** remembers techniques/reports/actors seen before across sessions — dedupe,
  annotate, build institutional knowledge.
- **Guardrails:** validate inputs (PII/junk) and enforce structured output (valid Mermaid, well-formed
  defense config).
- **Observability (Langfuse):** trace every node — latency, prompts, tokens — for debuggability and
  explainability.
- **Agent evaluation (Langfuse):** score the agents' behavior on a fixture dataset (right techniques?
  defenses faithful to retrieved mitigations?) — quality *measured*, not asserted.

## 7. One concrete pass

Input: *"Phishing email w/ macro Word doc → PowerShell downloads payload → scheduled task for
persistence → exfil over HTTPS."*

→ **Extractor + RAG** → `[T1566.001, T1059.001, T1053.005, T1048]`
→ **Graph_Architect** → Mermaid: `Phishing Attachment → PowerShell Exec → Scheduled Task → Exfil over HTTPS`
→ **Defensive_Guardrail + RAG** → per step: block macros (M1042), constrain/log PowerShell
   (M1038/M1049), monitor scheduled-task creation, egress-filter HTTPS (M1037).
→ **UI** renders graph + defense table. **Langfuse** traced it; **eval** scored it; **Mem0**
   remembered it.

## 8. The knowledge corpus

Grounding needs a corpus of ATT&CK techniques + mitigations. See `data/attack/`:
- `attack_corpus.seed.jsonl` — a small hand-curated starter (works offline, day one).
- `scripts/fetch_attack_corpus.py` — downloads the official Enterprise ATT&CK STIX and distills it
  into a comprehensive-but-manageable JSONL for real grounding.
