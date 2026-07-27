<img src="logo.png" alt="5STONES" width="220" />

# 5STONES — AI-Assisted Threat Modeling Platform

> *Start with what you have, be transparent about what you don't know, and produce output that every role can act on.*

5STONES is an open-source threat modeling platform built for teams that need to ship fast without skipping security. It uses STRIDE and LINDDUN frameworks — augmented by AI — to generate structured threat analysis, control mappings, and test scenarios from whatever artifacts you already have: a PRD, an API spec, a database schema, or just a rough description.

No security PhD required. No black-box output. Every result includes a confidence score and an explicit list of what the model didn't know.

---

## Quick Start

### 1. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate    # macOS/Linux
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — set OPENAI_API_KEY and OPENAI_BASE_URL
```

### 3. Run the server

```bash
python -m backend.main
# Server starts at http://127.0.0.1:8000
```

### 4. Open the app

Navigate to **http://127.0.0.1:8000** in your browser.

---

## What It Does

| Capability | Status |
|---|---|
| Project management | ✅ |
| Multi-step intake wizard | ✅ |
| Artifact upload & AI parsing | ✅ |
| Trust boundary detection | ✅ |
| STRIDE threat generation | ✅ |
| LINDDUN privacy threat generation | ✅ |
| Control mapping (built-in catalog) | ✅ |
| Test scenario generation | ✅ |
| Confidence scoring & assumption register | ✅ |
| Missing information tracker | ✅ |
| BYOK AI provider (OpenAI-compatible) | ✅ |
| Local LLM support | ✅ |
| Export: Markdown, CSV, JSON | ✅ |
| MCP client configuration | ✅ |
| Audit logging | ✅ |

---

## Supported AI Providers

Any OpenAI-compatible endpoint works out of the box:

| Provider | Base URL |
|---|---|
| OpenAI | `https://api.openai.com/v1` |
| Azure OpenAI | `https://<resource>.openai.azure.com/openai/deployments/<model>` |
| OpenRouter | `https://openrouter.ai/api/v1` |
| Ollama (local) | `http://localhost:11434/v1` with `OPENAI_API_KEY=ollama` |
| LM Studio | `http://localhost:1234/v1` |

---

## Supported Input Formats

| Type | Format |
|---|---|
| PRD | Plain text |
| OpenAPI / Swagger | YAML or JSON |
| Postman Collection | JSON |
| Markdown | `.md` |
| Database Schema | SQL or text |
| API list | CSV |

---

## API Docs

Once the server is running:

- **Swagger UI** → http://127.0.0.1:8000/api/docs
- **ReDoc** → http://127.0.0.1:8000/api/redoc

---

## Security

- API keys are **encrypted at rest** using Fernet symmetric encryption
- API keys are **never logged** or returned in API responses
- Set a strong `APP_SECRET_KEY` in `.env` before any production use
- For sensitive workspaces, use `data_policy: local_only` and a locally-hosted model
- All MCP invocations are written to the audit log

---

## Project Structure

```
5stones/
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── models/schemas.py    # Pydantic data models
│   ├── routers/             # API route handlers
│   ├── services/            # Business logic (AI, parsing, threat generation)
│   ├── utils/               # Storage, encryption, audit logging
│   └── data/                # JSON file storage
└── frontend/
    ├── index.html           # Dashboard
    ├── project-new.html     # New project wizard
    ├── analysis.html        # Analysis workspace
    ├── report.html          # Full report view
    ├── settings.html        # BYOK & LLM configuration
    ├── css/                 # Design system
    └── js/                  # Page controllers
```

---

## Design Principles

**Work with incomplete information.** Real threat modeling rarely starts with a complete picture. 5STONES accepts partial inputs and surfaces confidence scores alongside every finding — so teams know exactly which risks are well-understood and which need more investigation.

**Role-aware output.** A security finding is only useful if the right person can act on it. The output is structured for three distinct audiences: developers need test scenarios and control guidance; security teams need threat classification and risk ratings; QA teams need concrete test cases.

**No hidden assumptions.** Every AI-generated output includes a register of what was assumed. If the model inferred something it wasn't told, that assumption is visible and editable.

---

*5STONES is named after the principle that a small, well-aimed effort — built on what you already have — is more effective than a perfect tool you never use.*
