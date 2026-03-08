# WISE
WebAssembly Intelligent Security Engine.

![WISE Banner](./images/wise_banner.png)

WISE is a security-focused WebAssembly analysis platform for malware analysis and reverse engineering.  
It combines static decompilation, URL-based dynamic analysis, threat-intel enrichment, and investigation tracking in one workflow.

## Table of Contents
- [What WISE Does](#what-wise-does)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Runbook](#runbook)
- [Architecture](#architecture)
- [Data Model](#data-model)
- [LangGraph Decompiler Chain](#langgraph-decompiler-chain)
- [App Flow](#app-flow)
- [Troubleshooting](#troubleshooting)

## What WISE Does
- Analyzes `.wasm` samples with `wasm-decompile` and AI-assisted reconstruction.
- Performs URL dynamic analysis with Docker + Playwright instrumentation.
- Generates analyst artifacts (decompiled code, summaries, function name maps, findings, traces).
- Enriches investigations with CTI sources (VirusTotal, AlienVault OTX, OpenCTI).
- Stores each investigation with queue status and result metadata for triage and review.

## Quick Start
### Prerequisites
- Python `3.12+`
- Node.js `18+`
- Docker
- `wabt` toolkit (`wasm2wat`)
- (Optional) `binaryen` (`wasm-decompile`)

Ubuntu/Debian packages:
```bash
sudo apt update
sudo apt install -y \
  python3 python3-venv python3-pip \
  nodejs npm \
  docker.io \
  wabt binaryen \
  binutils ssdeep \
  git curl
```

Notes:
- `binutils` provides `strings` used for artifact enrichment.
- `ssdeep` enables fuzzy hash generation for metadata.
- Add your user to Docker group and re-login:
```bash
sudo usermod -aG docker "$USER"
```

### Setup
```bash
git clone <your-repo-url>
cd WISE
chmod +x ./setup.sh
./setup.sh
```

`setup.sh` creates a virtualenv, installs Python dependencies, initializes DB, builds Docker images (if Docker exists), and builds frontend assets (if `npm` exists).

### Run Services
Backend:
```bash
source virtualenv/bin/activate
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Frontend:
```bash
cd frontend
npm install
npm run dev
```

Endpoints:
- API: `http://localhost:8000`
- API docs: `http://localhost:8000/docs`
- UI: `http://localhost:5173`

## Configuration
WISE uses centralized configuration in `wise_config.py` with env var overrides.

Update these first in `wise_config.py` (or via env vars):

1. `CONFIG["decompiler"]["provider"]` / `WISE_PROVIDER`
- Select your active LLM provider (`openai`, `anthropic`, `google`, `openrouter`, `ollama`).

2. `CONFIG["decompiler"]["model"]` / `WISE_MODEL`
- Set the actual model you want for decompilation quality/cost tradeoff.

3. `CONFIG["decompiler"]["temperature"]` / `WISE_TEMPERATURE`
- Keep low (`0.0` to `0.2`) for deterministic reverse-engineering output.

4. `CONFIG["backend"]["host"]` + `CONFIG["backend"]["port"]`
- Required when deploying off localhost or behind reverse proxies.

5. `CONFIG["dynan"]["image_tag"]` + `CONFIG["analyzer"]["yaragen_image"]`
- Must match locally built Docker image tags.

6. Timeout and throughput knobs:
- `WASM_DECOMPILE_TIMEOUT`, `YARAGEN_TIMEOUT`
- `DYNAN_EXECUTION_TIMEOUT`, `DYNAN_ANALYSIS_TIMEOUT_MS`
- `WISE_LLM_MAX_RETRIES`, `WISE_MAX_PROMPT_TOKENS`

Recommended minimal env setup before first run:
```bash
export WISE_PROVIDER=openai
export WISE_MODEL=gpt-4o-mini
export OPENAI_API_KEY="sk-..."
```

Supported providers and what to set:

1. `openai`
- `WISE_PROVIDER=openai`
- Required key: `OPENAI_API_KEY`
- Example models: `gpt-4o-mini`, `gpt-4.1-mini`

2. `anthropic`
- `WISE_PROVIDER=anthropic`
- Required key: `ANTHROPIC_API_KEY`
- Example models: `claude-3-5-sonnet-latest`, `claude-3-7-sonnet-latest`

3. `google`
- `WISE_PROVIDER=google`
- Required key: `GOOGLE_API_KEY`
- Example models: `gemini-1.5-pro`, `gemini-1.5-flash`

4. `openrouter`
- `WISE_PROVIDER=openrouter`
- Required key: `OPENROUTER_API_KEY`
- Example models: `openai/gpt-4o-mini`, `anthropic/claude-3.5-sonnet`

5. `ollama` (local)
- `WISE_PROVIDER=ollama`
- No API key required
- Optional: `OLLAMA_BASE_URL` (default `http://localhost:11434`)
- Example models: `qwen2.5-coder:7b`, `llama3.1:8b`

Core runtime keys:
```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-..."
export GOOGLE_API_KEY="..."
export OPENROUTER_API_KEY="sk-..."
```

Optional CTI keys:
```bash
export VIRUSTOTAL_API_KEY="..."
export OPENCTI_API_KEY="..."
export OTX_API_KEY="..."
```

Optional frontend `.env` (`frontend/.env`):
```bash
VITE_API_BASE=http://localhost:8000/api
VITE_API_TIMEOUT=30000
```

## Runbook
1. Start backend and frontend.
2. Submit a WASM file or URL from the UI.
3. Worker processes queue and updates investigation status.
4. Review outputs:
    - static analysis (`decompiled C`, `summary`, `function map`, `security findings`, `YARA`)
    - dynamic artifacts (`trace`, `network`, runtime artifacts)
5. Re-run investigation from the UI if needed.

## Architecture
High-level application flow from user interaction to analysis pipelines and enrichment services.

![Architecture Diagram](./images/architecture.png)

Key points:
- Frontend calls FastAPI for ingestion, queue visibility, and result retrieval.
- Backend orchestrates work and persists orchestration state in `backend/wise.db`.
- Background worker executes static and dynamic pipelines.
- Threat-intel integration enriches analysis output.

## Infrastructure
Deployment view of host-local components, containerized runtime, and external dependencies.

![Infrastructure Diagram](./images/Infrastructure.png)

Key points:
- `AppHost` contains API, worker, frontend, and storage.
- `DynInfra` isolates runtime website execution through Docker + Playwright.
- External providers are optional but used for LLM inference and CTI enrichment.

## Data Model
Logical schema for `backend/wise.db` and per-investigation payload DBs.

`wise.db` relationship view:

![WISE DB ER Diagram](./images/er_diagram_wise.png)

Per-investigation DB (`analysis_<id>.db`) view:

![Per-Investigation DB ER Diagram](./images/er_diagram_idb.png)

Key points:
- `investigations` is the root table.
- `analysis_results` is the lightweight index table in `wise.db`.
- Heavy static-analysis payloads are stored in `backend/analysis_results/analysis_<id>.db`.
- `processing_queue` tracks worker lifecycle.
- `dynamic_results` stores dynamic run data, cached CTI, and trace-viewer payload.
- Foreign keys in `wise.db` are enforced with `ON DELETE CASCADE`.

## LangGraph Decompiler Chain
Execution stages for AI-assisted static decompilation from WASM input to analyst-ready output.

![LangGraph Chain Diagram](./images/langgraph.png)

Stages:
1. Parsing: load and structure WASM program content.
2. Code reconstruction: symbol inference, lifting, refinement, and finalization.
3. Security analysis: vulnerability scanning on finalized output.
4. Reporting: analyst-readable summary generation.
5. Artifacts: decompiled C, summary, function map, and security findings.

## App Flow
End-to-end user workflow in the WISE interface.

![WISE App Flow](./images/app_flow.png)

## Troubleshooting
- Backend fails to start: activate virtualenv and ensure `pip install -r requirements.txt` was run.
- Dynamic analysis fails: check Docker daemon status and image build logs.
- Missing CTI results: ensure API keys are set and outbound access is available.
- Empty static outputs: verify sample is valid WASM and required binaries are installed (`wabt`, optional `binaryen`).
