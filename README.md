# ThreatModelz — AI-Assisted Threat Modeling Platform

MVP untuk platform threat modeling berbasis AI. Mendukung STRIDE, LINDDUN, BYOK, Local LLM, dan MCP client.

## Quick Start

### 1. Install dependencies

```bash
cd Threatmodelz
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

## Features (MVP)

| Feature | Status |
|---------|--------|
| Project management | ✅ |
| Manual intake wizard (multi-step) | ✅ |
| Artifact upload & AI parsing | ✅ |
| Trust boundary detection | ✅ |
| STRIDE threat generation | ✅ |
| LINDDUN privacy threat generation | ✅ |
| Control mapping (built-in catalog) | ✅ |
| Test scenario generation | ✅ |
| Confidence + assumption register | ✅ |
| Missing information generator | ✅ |
| BYOK AI provider (OpenAI-compatible) | ✅ |
| Local LLM support | ✅ |
| Export: Markdown, CSV, JSON | ✅ |
| Basic MCP client config | ✅ |
| Audit logging | ✅ |

---

## Supported AI Providers

Any OpenAI-compatible endpoint:
- **OpenAI** — `https://api.openai.com/v1`
- **Azure OpenAI** — `https://<resource>.openai.azure.com/openai/deployments/<model>`
- **OpenRouter** — `https://openrouter.ai/api/v1`
- **Local Ollama** — `http://localhost:11434/v1` with `OPENAI_API_KEY=ollama`
- **LM Studio** — `http://localhost:1234/v1`

---

## Supported Artifact Types

| Type | Format |
|------|--------|
| PRD | Plain text |
| OpenAPI / Swagger | YAML or JSON |
| Postman Collection | JSON |
| Markdown | .md |
| Database Schema | SQL or text |
| CSV API list | CSV |

---

## API Documentation

Once running, visit:
- **Swagger UI**: http://127.0.0.1:8000/api/docs
- **ReDoc**: http://127.0.0.1:8000/api/redoc

---

## Security Notes

- API keys are **encrypted at rest** using Fernet symmetric encryption
- API keys are **never logged** or returned in API responses (masked only)
- Set a strong `APP_SECRET_KEY` in `.env` for production use
- For sensitive workspaces, use `data_policy: local_only` and configure Local LLM
- All MCP invocations are logged to audit log

---

## Project Structure

```
Threatmodelz/
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── models/schemas.py    # Pydantic data models
│   ├── routers/             # API route handlers
│   ├── services/            # Business logic (AI, parsing, threat gen)
│   ├── utils/               # Storage and audit logging
│   └── data/                # JSON file storage
└── frontend/
    ├── index.html           # Dashboard
    ├── project-new.html     # New project wizard
    ├── analysis.html        # Analysis workspace
    ├── report.html          # Full report view
    ├── settings.html        # BYOK & LLM config
    ├── css/                 # Design system
    └── js/                  # Page controllers
```
