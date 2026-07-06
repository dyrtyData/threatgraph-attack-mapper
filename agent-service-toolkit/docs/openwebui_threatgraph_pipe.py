"""
title: ThreatGraph Attack-Graph Mapper
author: perficient-threatgraph (PF-001)
description: Drives the agent-service-toolkit `threatgraph` LangGraph agent over its
    FastAPI POST-SSE endpoint and renders the Mermaid attack graph + grounded defense
    configuration inside Open WebUI. Paste this into Open WebUI → Admin Panel →
    Functions → "+", then set the Valves (AGENT_URL / AUTH_TOKEN).
version: 0.1.0
requirements: requests
"""

# NOTE: This is an Open WebUI *Pipe function* (integration glue), NOT part of the
# committed Open WebUI source (which stays git-ignored). It runs inside the Open WebUI
# server/container. From the container, the host FastAPI service is reachable at
# host.docker.internal:8081 (Docker Desktop). The service's terminal `custom` message
# carries custom_data = {mechanics, mermaid, defense_config, recalled_memories}, which
# mirrors what the Streamlit and React clients render.

import json

import requests
from pydantic import BaseModel, Field


class Pipe:
    class Valves(BaseModel):
        AGENT_URL: str = Field(
            default="http://host.docker.internal:8081",
            description="Base URL of the agent-service-toolkit FastAPI service. "
            "From a Docker container on macOS/Windows use host.docker.internal; "
            "if Open WebUI runs natively use http://localhost:8081.",
        )
        AUTH_TOKEN: str = Field(
            default="",
            description="Bearer token = the service's AUTH_SECRET. Leave blank if the "
            "service runs without auth.",
        )
        TIMEOUT_S: int = Field(default=180, description="HTTP timeout (seconds).")

    def __init__(self):
        self.valves = self.Valves()

    def pipes(self):
        # Registers a single selectable "model" in Open WebUI's model picker.
        return [{"id": "threatgraph", "name": "ThreatGraph Attack-Graph Mapper"}]

    def pipe(self, body: dict):
        messages = body.get("messages", [])
        user_text = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                user_text = m.get("content", "")
                break
        if not user_text:
            return "Paste unstructured threat-intel text to analyze."

        headers = {"Content-Type": "application/json"}
        if self.valves.AUTH_TOKEN:
            headers["Authorization"] = f"Bearer {self.valves.AUTH_TOKEN}"

        # Omit `model` so the service uses its configured DEFAULT_MODEL (avoids enum
        # mismatch). stream_tokens=False → we only need the terminal custom message.
        payload = {"message": user_text, "stream_tokens": False}

        try:
            resp = requests.post(
                f"{self.valves.AGENT_URL}/threatgraph/stream",
                json=payload,
                headers=headers,
                stream=True,
                timeout=self.valves.TIMEOUT_S,
            )
            resp.raise_for_status()
        except requests.HTTPError as e:
            return f"Agent service error: {e} — check AGENT_URL/AUTH_TOKEN valves."
        except requests.RequestException as e:
            return f"Could not reach the agent service at {self.valves.AGENT_URL}: {e}"

        custom = None
        # Track the most recent plain-text message so we can surface a refusal.
        # When the input safety gate (guard_input → block_unsafe_content) blocks
        # an unsafe/prompt-injection input, the terminal message is a normal `ai`
        # message with plain-text refusal content and NO mermaid custom_data.
        last_text = ""
        for line in resp.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data: "):
                continue
            data = line[len("data: ") :]
            if data == "[DONE]":
                break
            try:
                event = json.loads(data)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "token":
                # Accumulate any streamed tokens as a fallback terminal text.
                last_text += str(event.get("content") or "")
            elif event.get("type") == "message":
                msg = event.get("content", {})
                cdata = msg.get("custom_data") or {}
                if cdata.get("mermaid"):
                    custom = cdata
                else:
                    content = msg.get("content")
                    if isinstance(content, str) and content.strip():
                        last_text = content

        if custom:
            return self._render_markdown(custom)

        # No graph — surface the terminal plain-text message (e.g. Safeguard
        # refusal) instead of a generic "no graph" line.
        if last_text.strip():
            return "### 🛡️ Agent response\n\n" + last_text.strip()

        return "No attack graph was produced for that input."

    @staticmethod
    def _render_markdown(custom: dict) -> str:
        parts: list[str] = []

        mermaid = custom.get("mermaid", "").strip()
        if mermaid:
            parts.append("### 🗺️ Attack graph\n\n```mermaid\n" + mermaid + "\n```")

        recalled = custom.get("recalled_memories") or []
        if recalled:
            lines = ["### 🧠 Recalled from prior analyses"]
            for r in recalled:
                text = r.get("memory") or r.get("text") or str(r)
                score = r.get("score")
                lines.append(f"- {text}" + (f" _(relevance {score:.3f})_" if isinstance(score, (int, float)) else ""))
            parts.append("\n".join(lines))

        mechanics = custom.get("mechanics") or []
        if mechanics:
            rows = ["### Extracted mechanics\n", "| Tactic | Technique | Name | Evidence |", "|---|---|---|---|"]
            for m in mechanics:
                rows.append(
                    f"| {m.get('tactic','')} | {m.get('technique_id','')} | "
                    f"{m.get('name','')} | {m.get('evidence','')} |"
                )
            parts.append("\n".join(rows))

        defense = custom.get("defense_config") or []
        if defense:
            rows = ["### 🛡️ Defense configuration\n", "| Technique | Mitigation | Action | Rationale |", "|---|---|---|---|"]
            for d in defense:
                rows.append(
                    f"| {d.get('technique_id','')} | {d.get('mitigation_id','')} | "
                    f"{d.get('action','')} | {d.get('rationale','')} |"
                )
            parts.append("\n".join(rows))

        return "\n\n".join(parts)
