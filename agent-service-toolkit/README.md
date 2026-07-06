# 🧰 AI Agent Service Toolkit

[![build status](https://github.com/JoshuaC215/agent-service-toolkit/actions/workflows/test.yml/badge.svg)](https://github.com/JoshuaC215/agent-service-toolkit/actions/workflows/test.yml) [![codecov](https://codecov.io/github/JoshuaC215/agent-service-toolkit/graph/badge.svg?token=5MTJSYWD05)](https://codecov.io/github/JoshuaC215/agent-service-toolkit) [![Python Version](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2FJoshuaC215%2Fagent-service-toolkit%2Frefs%2Fheads%2Fmain%2Fpyproject.toml)](https://github.com/JoshuaC215/agent-service-toolkit/blob/main/pyproject.toml)
[![GitHub License](https://img.shields.io/github/license/JoshuaC215/agent-service-toolkit)](https://github.com/JoshuaC215/agent-service-toolkit/blob/main/LICENSE) [![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_red.svg)](https://agent-service-toolkit.streamlit.app/)

A full toolkit for running an AI agent service built with LangGraph, FastAPI and Streamlit.

It includes a [LangGraph](https://langchain-ai.github.io/langgraph/) agent, a [FastAPI](https://fastapi.tiangolo.com/) service to serve it, a client to interact with the service, and a [Streamlit](https://streamlit.io/) app that uses the client to provide a chat interface. Data structures and settings are built with [Pydantic](https://github.com/pydantic/pydantic).

This project offers a template for you to easily build and run your own agents using the LangGraph framework. It demonstrates a complete setup from agent definition to user interface, making it easier to get started with LangGraph-based projects by providing a full, robust toolkit.

**[🎥 Watch a video walkthrough of the repo and app](https://www.youtube.com/watch?v=pdYVHw_YCNY)**

---

## 🛰️ ThreatGraph (PF-001) — the multi-agent pipeline built on this toolkit

This repo hosts **ThreatGraph**, a registered `threatgraph` LangGraph agent that ingests
unstructured threat-intelligence text and emits (a) a Mermaid.js attack graph of the attacker's
kill-chain and (b) a structurally validated defensive configuration, grounded in hybrid RAG over
the full MITRE ATT&CK corpus, remembered via hosted Mem0, and traced + evaluated in Langfuse.

- **Architecture pillars** → how ThreatGraph maps to the 7 fundamental multi-agent architecture
  pillars (+ MVP standards), with concrete `file:path` references and per-pillar demo notes:
  see [`docs/ARCHITECTURE_PILLARS.md`](docs/ARCHITECTURE_PILLARS.md).
- **Build journey + operational lessons + timing table** → [`PROGRESS.md`](PROGRESS.md).

### Run all surfaces

All UIs talk to the **same** FastAPI backend. Start it once (from `agent-service-toolkit/`):

```sh
# MODE=dev enables auto-reload (the service does NOT reload by default);
# PORT=8081 avoids a common :8080 collision. Prefix everything with `uv run`
# (bare `python` uses the wrong interpreter and fails on missing deps).
MODE=dev PORT=8081 uv run python src/run_service.py
```

Then pick a UI / task:

| Surface | Command | Notes |
| --- | --- | --- |
| **Streamlit** (fast/dev path) | `AGENT_URL=http://localhost:8081 uv run streamlit run src/streamlit_app.py` | Defaults the agent selector to `threatgraph`; shows the recalled-memories panel. |
| **React client** (polished) | `cd ../frontend && npm ci && npm run dev` (`http://localhost:5173`) | POST-SSE; see the React section below for the `frontend/.env` token note + CORS. |
| **Open WebUI** (third UI) | see [`docs/OpenWebUI.md`](docs/OpenWebUI.md) | Pipe function POSTs to `/threatgraph/stream`; server-side call, no CORS needed. |
| **Evals harness** | `uv run --env-file ../.env python evals/run_experiment.py` | Langfuse dataset + experiment + SDK evaluators (`--env-file` so keys reach `os.environ`). |

> **Tracing is off by default:** set `LANGFUSE_TRACING=true` in `.env` (keys alone do NOT turn
> tracing on) and restart the service to emit the per-node span tree.

---

## Overview

### [Try the app!](https://agent-service-toolkit.streamlit.app/)

<a href="https://agent-service-toolkit.streamlit.app/"><img src="media/app_screenshot.png" width="600"></a>

### Quickstart

Run directly in python

```sh
# At least one LLM API key is required
echo 'OPENAI_API_KEY=your_openai_api_key' >> .env

# uv is the recommended way to install agent-service-toolkit, but "pip install ." also works
# For uv installation options, see: https://docs.astral.sh/uv/getting-started/installation/
curl -LsSf https://astral.sh/uv/0.11.26/install.sh | sh

# Install dependencies. "uv sync" creates .venv automatically
uv sync --frozen
source .venv/bin/activate
python src/run_service.py

# In another shell
source .venv/bin/activate
streamlit run src/streamlit_app.py
```

Run with docker

```sh
echo 'OPENAI_API_KEY=your_openai_api_key' >> .env
docker compose watch
```

### Architecture Diagram

<img src="media/agent_architecture.png" width="600">

### Key Features

1. **LangGraph Agent and latest features**: A customizable agent built using the LangGraph framework. Implements the latest LangGraph v1.0 features including human in the loop with `interrupt()`, flow control with `Command`, long-term memory with `Store`, and `langgraph-supervisor`.
1. **FastAPI Service**: Serves the agent with both streaming and non-streaming endpoints.
1. **Advanced Streaming**: A novel approach to support both token-based and message-based streaming.
1. **Streamlit Interface**: Provides a user-friendly chat interface for interacting with the agent, including voice input and output.
1. **Multiple Agent Support**: Run multiple agents in the service and call by URL path. Available agents and models are described in `/info`
1. **Asynchronous Design**: Utilizes async/await for efficient handling of concurrent requests.
1. **Content Moderation**: Implements Safeguard for content moderation (requires Groq API key).
1. **RAG Agent**: A basic RAG agent implementation using ChromaDB - see [docs](docs/RAG_Assistant.md).
1. **Feedback Mechanism**: Includes a star-based feedback system integrated with LangSmith.
1. **Docker Support**: Includes Dockerfiles and a docker compose file for easy development and deployment.
1. **Testing**: Includes robust unit and integration tests for the full repo.

### Key Files

The repository is structured as follows:

- `src/agents/`: Defines several agents with different capabilities
- `src/schema/`: Defines the protocol schema
- `src/core/`: Core modules including LLM definition and settings
- `src/service/service.py`: FastAPI service to serve the agents
- `src/client/client.py`: Client to interact with the agent service
- `src/streamlit_app.py`: Streamlit app providing a chat interface
- `tests/`: Unit and integration tests

## Setup and Usage

1. Clone the repository:

   ```sh
   git clone https://github.com/JoshuaC215/agent-service-toolkit.git
   cd agent-service-toolkit
   ```

2. Set up environment variables:
   Create a `.env` file in the root directory. At least one LLM API key or configuration is required. See the [`.env.example` file](./.env.example) for a full list of available environment variables, including a variety of model provider API keys, header-based authentication, LangSmith tracing, testing and development modes, and OpenWeatherMap API key.

3. You can now run the agent service and the Streamlit app locally, either with Docker or just using Python. The Docker setup is recommended for simpler environment setup and immediate reloading of the services when you make changes to your code.

### Additional setup for specific AI providers

- [Setting up Ollama](docs/Ollama.md)
- [Setting up VertexAI](docs/VertexAI.md)
- [Setting up RAG with ChromaDB](docs/RAG_Assistant.md)

### Building or customizing your own agent

To customize the agent for your own use case:

1. Add your new agent to the `src/agents` directory. You can copy `research_assistant.py` or `chatbot.py` and modify it to change the agent's behavior and tools.
1. Import and add your new agent to the `agents` dictionary in `src/agents/agents.py`. Your agent can be called by `/<your_agent_name>/invoke` or `/<your_agent_name>/stream`.
1. Adjust the Streamlit interface in `src/streamlit_app.py` to match your agent's capabilities.


### Handling Private Credential files

If your agents or chosen LLM require file-based credential files or certificates, the `privatecredentials/` has been provided for your development convenience. All contents, excluding the `.gitkeep` files, are ignored by git and docker's build process. See [Working with File-based Credentials](docs/File_Based_Credentials.md) for suggested use.


### Docker Setup

This project includes a Docker setup for easy development and deployment. The `compose.yaml` file defines three services: `postgres`, `agent_service` and `streamlit_app`. The `Dockerfile` for each service is in their respective directories.

For local development, we recommend using [docker compose watch](https://docs.docker.com/compose/file-watch/). This feature allows for a smoother development experience by automatically updating your containers when changes are detected in your source code.

1. Make sure you have Docker and Docker Compose (>= [v2.23.0](https://docs.docker.com/compose/release-notes/#2230)) installed on your system.

2. Create a `.env` file from the `.env.example`. At minimum, you need to provide an LLM API key (e.g., OPENAI_API_KEY).
   ```sh
   cp .env.example .env
   # Edit .env to add your API keys
   ```

3. Build and launch the services in watch mode:

   ```sh
   docker compose watch
   ```

   This will automatically:
   - Start a PostgreSQL database service that the agent service connects to
   - Start the agent service with FastAPI
   - Start the Streamlit app for the user interface

4. The services will now automatically update when you make changes to your code:
   - Changes in the relevant python files and directories will trigger updates for the relevant services.
   - NOTE: If you make changes to the `pyproject.toml` or `uv.lock` files, you will need to rebuild the services by running `docker compose up --build`.

5. Access the Streamlit app by navigating to `http://localhost:8501` in your web browser.

6. The agent service API will be available at `http://0.0.0.0:8080`. You can also use the OpenAPI docs at `http://0.0.0.0:8080/redoc`.

7. Use `docker compose down` to stop the services.

This setup allows you to develop and test your changes in real-time without manually restarting the services.

### Building other apps on the AgentClient

The repo includes a generic `src/client/client.AgentClient` that can be used to interact with the agent service. This client is designed to be flexible and can be used to build other apps on top of the agent. It supports both synchronous and asynchronous invocations, and streaming and non-streaming requests.

See the `src/run_client.py` file for full examples of how to use the `AgentClient`. A quick example:

```python
from client import AgentClient
client = AgentClient()

response = client.invoke("Tell me a brief joke?")
response.pretty_print()
# ================================== Ai Message ==================================
#
# A man walked into a library and asked the librarian, "Do you have any books on Pavlov's dogs and Schrödinger's cat?"
# The librarian replied, "It rings a bell, but I'm not sure if it's here or not."

```

### Development with LangGraph Studio

The agent supports [LangGraph Studio](https://langchain-ai.github.io/langgraph/concepts/langgraph_studio/), the IDE for developing agents in LangGraph.

`langgraph-cli[inmem]` is installed with `uv sync`. You can simply add your `.env` file to the root directory as described above, and then launch LangGraph Studio with `langgraph dev`. Customize `langgraph.json` as needed. See the [local quickstart](https://langchain-ai.github.io/langgraph/cloud/how-tos/studio/quick_start/#local-development-server) to learn more.

### Local development without Docker

You can also run the agent service and the Streamlit app locally without Docker, just using a Python virtual environment.

1. Create a virtual environment and install dependencies:

   ```sh
   uv sync --frozen
   source .venv/bin/activate
   ```

2. Run the FastAPI server:

   ```sh
   python src/run_service.py
   ```

3. In a separate terminal, run the Streamlit app:

   ```sh
   streamlit run src/streamlit_app.py
   ```

4. Open your browser and navigate to the URL provided by Streamlit (usually `http://localhost:8501`).

### React client (Vite + Tailwind v4) — `threatgraph` polished UI

A minimal Vite + React + TypeScript + Tailwind v4 client lives in the repo-root
`frontend/` directory (sibling to `agent-service-toolkit/`). It consumes the same
FastAPI `POST /threatgraph/stream` SSE endpoint (via `fetch` +
`response.body.getReader()`) and renders the Mermaid attack graph plus the
validated defense configuration.

1. Start the FastAPI server (the client's default backend is `http://localhost:8081`).

   ```sh
   # from agent-service-toolkit/
   MODE=dev PORT=8081 uv run python src/run_service.py
   ```

   **Auth note (important):** if the repo-root `.env` sets `AUTH_SECRET`, bearer auth
   is ON and the browser must send a matching token. Setting `AUTH_SECRET=` (empty) on
   the command line does **not** disable it — `Settings` uses `env_ignore_empty=True`, so
   an empty value is ignored and it falls back to the `.env` value (verified). The clean
   fix is to give the browser the token via a git-ignored `frontend/.env`
   (`VITE_AGENT_TOKEN=<same value as AUTH_SECRET>`, see step 4) and run the service
   normally with auth ON. (Only remove/blank `AUTH_SECRET` *in `.env` itself* if you truly
   want auth off.) NOTE: Vite inlines `VITE_*` vars into the browser bundle, so this
   embedded-token shortcut is for **local dev only** — a production browser app would use a
   real user-auth flow, not a shared bearer secret.

2. In a separate terminal, install and run the client:

   ```sh
   cd ../frontend
   npm ci          # or `npm install` the first time (creates package-lock.json)
   npm run dev     # http://localhost:5173
   ```

3. Build / test the client:

   ```sh
   npm run build   # tsc -b && vite build → frontend/dist
   npm run test    # vitest (SSE parser + AttackGraph smoke tests)
   ```

**Configuration.** The backend base URL is set via the `VITE_AGENT_URL`
environment variable (default `http://localhost:8081`). Copy `frontend/.env.example`
to `frontend/.env` to override it, e.g. `VITE_AGENT_URL=http://localhost:8081`. If the
service is started with an `AUTH_SECRET`, set `VITE_AGENT_TOKEN` to the same value so
the browser sends `Authorization: Bearer <token>`; locally, with `AUTH_SECRET` unset,
no token is required.

**CORS (browser clients).** Unlike the server-side Streamlit app and the Python
`AgentClient`, a browser client makes a *cross-origin* request (from
`http://localhost:5173` to `http://localhost:8081`) and needs the service to return
CORS headers — otherwise the browser blocks the response and the client reports
"Failed to fetch". The service adds FastAPI's `CORSMiddleware`, allowing the Vite dev
origins by default. To serve the client from a different origin, set
`CORS_ALLOW_ORIGINS` on the service (a JSON array or a comma-separated string), e.g.
`CORS_ALLOW_ORIGINS='["https://myapp.example"]'` or
`CORS_ALLOW_ORIGINS=http://localhost:5173,http://127.0.0.1:5173`.

> `frontend/node_modules/` and `frontend/dist/` are git-ignored; only source and
> `package-lock.json` are committed.

## Projects built with or inspired by agent-service-toolkit

The following are a few of the public projects that drew code or inspiration from this repo.

- **[PolyRAG](https://github.com/QuentinFuxa/PolyRAG)** - Extends agent-service-toolkit with RAG capabilities over both PostgreSQL databases and PDF documents.
- **[alexrisch/agent-web-kit](https://github.com/alexrisch/agent-web-kit)** - A Next.JS frontend for agent-service-toolkit
- **[raushan-in/dapa](https://github.com/raushan-in/dapa)** - Digital Arrest Protection App (DAPA) enables users to report financial scams and frauds efficiently via a user-friendly platform.

**Please create a pull request editing the README or open a discussion with any new ones to be added!** Would love to include more projects.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. Currently the tests need to be run using the local development without Docker setup. To run the tests for the agent service:

1. Ensure you're in the project root directory and have activated your virtual environment.

2. Install the development dependencies and pre-commit hooks:

   ```sh
   uv sync --frozen
   pre-commit install
   ```

3. Run the tests using pytest:

   ```sh
   pytest
   ```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
