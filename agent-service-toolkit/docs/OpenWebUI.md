# Open WebUI — third UI for the `threatgraph` agent

This wires **Open WebUI** to the same FastAPI backend as the Streamlit and React
clients, via an Open WebUI **Pipe function** that calls `POST /threatgraph/stream` and
renders the Mermaid attack graph + grounded defense configuration.

> **Hygiene:** Open WebUI itself stays **git-ignored** (run in place / from the official
> Docker image). The only files committed are this doc and the integration snippet
> [`openwebui_threatgraph_pipe.py`](./openwebui_threatgraph_pipe.py). No Open WebUI source
> enters the repo.

## 1. Run Open WebUI (Docker)

```sh
docker run -d \
  -p 3000:8080 \
  --add-host=host.docker.internal:host-gateway \
  -v open-webui:/app/backend/data \
  --name open-webui \
  ghcr.io/open-webui/open-webui:main
```

Open **http://localhost:3000** and create the first account (this becomes the local admin;
it's a local SQLite user in the `open-webui` Docker volume — not a real cloud signup).

- `--add-host=host.docker.internal:host-gateway` lets the container reach the FastAPI
  service running on your **host** at `host.docker.internal:8081`.
- To stop / restart later: `docker stop open-webui` / `docker start open-webui`.
- The image is multi-GB; the first `docker run` pulls it (one-time).

## 2. Start the agent service (host)

```sh
# from agent-service-toolkit/
MODE=dev PORT=8081 uv run python src/run_service.py
```

If `AUTH_SECRET` is set in `.env` (bearer auth ON), note its value — you'll paste it into
the pipe's `AUTH_TOKEN` valve in step 3. (Unlike the browser React client, the pipe runs
server-side inside the Open WebUI container, so a token in a Valve is fine — it is not
shipped to a browser.)

## 3. Add the Pipe function

1. In Open WebUI: **Admin Panel → Functions → “+” (New Function)**.
2. Paste the entire contents of [`openwebui_threatgraph_pipe.py`](./openwebui_threatgraph_pipe.py).
3. Save, then **enable** the function.
4. Open the function's **Valves** (gear icon) and set:
   - `AGENT_URL` = `http://host.docker.internal:8081` (Docker) — or `http://localhost:8081`
     if you run Open WebUI natively (not in Docker).
   - `AUTH_TOKEN` = the service's `AUTH_SECRET` value (leave blank if auth is off).

## 4. Use it

Start a **New Chat**, pick the **“ThreatGraph Attack-Graph Mapper”** model in the model
selector (the pipe registers it), and paste unstructured threat-intel text, e.g.:

> An adversary sent a spearphishing email with a macro-enabled Word attachment; the macro
> launched PowerShell to download a second-stage payload; the actor dumped LSASS memory to
> harvest credentials and moved laterally over RDP before exfiltrating data to a cloud store.

You'll get the rendered **Mermaid kill-chain graph** (Open WebUI renders ```mermaid fenced
blocks) plus the **Extracted mechanics** and **Defense configuration** tables — the same
`custom_data` the Streamlit and React clients consume.

## Troubleshooting

- **"Could not reach the agent service …"** — the container can't see the host. Confirm the
  service is up (`curl localhost:8081/health`) and `AGENT_URL` uses `host.docker.internal`
  (Docker), not `localhost`.
- **"Agent service error: 401"** — bearer auth is on; set the `AUTH_TOKEN` valve to the
  service's `AUTH_SECRET`.
- **Graph doesn't draw** — ensure the reply contains a ```mermaid fenced block (Open WebUI
  renders it automatically); check the function is enabled and the correct model is selected.
- **No CORS needed here** — the pipe calls the service server-side (from the Open WebUI
  backend), so unlike the browser React client this path needs no CORS.
