<div align="center">
  <img src="logo.png" alt="5STONES" width="240" />

  # 5STONES

  ### See the risk before it ships.

  A structured security review workspace for teams that need clarity before they ship.

  <p>
    <a href="#quick-start">Quick start</a> ·
    <a href="#product-tour">Product tour</a> ·
    <a href="#analysis-providers">Analysis providers</a> ·
    <a href="#security-notes">Security notes</a>
  </p>
</div>

5STONES turns the system context you already have a PRD, API specification, database schema, or rough description into a clear, review-ready security dossier. It brings architecture context, trust-boundary decisions, STRIDE and LINDDUN findings, control mappings, test scenarios, evidence, and open questions into one supporting document for engineering, security, and QA teams.

## Product tour

<table>
  <tr>
    <td width="33%" align="center"><strong>Dashboard</strong><br /><sub>Track projects and risk posture</sub></td>
    <td width="33%" align="center"><strong>Analysis diagram</strong><br /><sub>Explore components and trust zones</sub></td>
    <td width="33%" align="center"><strong>Security report</strong><br /><sub>Turn findings into action</sub></td>
  </tr>
  <tr>
    <td><img src="demo/page_dashboard.gif" alt="5STONES dashboard demo" width="100%" /></td>
    <td><img src="demo/page_diagram.gif" alt="5STONES analysis diagram demo" width="100%" /></td>
    <td><img src="demo/page_report.gif" alt="5STONES security report demo" width="100%" /></td>
  </tr>
</table>

## Why 5STONES?

- **Start with incomplete information.** Import what exists and make gaps explicit instead of waiting for perfect documentation.
- **Ground findings in context.** Review trust boundaries, evidence, confidence, and assumptions before acting on a result.
- **Give every role a next step.** Developers get controls and test scenarios; security teams get threat classification; QA gets an actionable backlog.
- **Keep the workflow flexible.** Use the built-in analysis engine, a connected provider, or a local model while keeping the review structure consistent.

## How it works

```text
Context → Parse & reconcile → Review trust boundaries → Analyze → Act
  PRD       OpenAPI/Postman     STRIDE + LINDDUN       Controls   Tests
  Schema    Markdown/CSV        Evidence & assumptions  Gaps      Reports
```

## Quick start

### 1. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate    # macOS/Linux
pip install -r requirements.txt
```

### 2. Configure the environment

```bash
cp .env.example .env
# Edit .env and set your provider values.
```

For a connected provider, configure `OPENAI_API_KEY`, `OPENAI_BASE_URL`, and `OPENAI_MODEL`. For local inference, use the local endpoint settings shown in `.env.example`.

The local development profile binds to a loopback `HOST` (default
`127.0.0.1`) and defaults to `AUTH_MODE=local_users`; API access then requires a
SQLite-backed user account and project data is scoped to that account's
workspace. After copying `.env.example`, seed the first administrator account:

```bash
python3 scripts/seed_local_user.py
```

The helper prompts for the email and password without echoing the password.
Passwords must be at least 12 characters and are stored as salted
PBKDF2-HMAC-SHA256 hashes. User and session records are stored in
`$DATA_DIR/auth/auth.sqlite3` (or `AUTH_DB_PATH` when configured), with restrictive
file permissions. The script creates an Admin by default. Existing projects
without a `workspace_id` stay hidden after enabling local account auth; pass
`--adopt-legacy-projects` when seeding to assign those projects to the selected
workspace.

Self-registration is disabled by default. To allow controlled local signup,
set `AUTH_REGISTRATION_ENABLED=true` and configure a unique
`AUTH_REGISTRATION_KEY` with at least 32 characters. The registration page
creates Analyst accounts only; workspace and role are fixed by server config.
Local account mode is rejected under `APP_ENV=enterprise`. Use the enterprise
profile for any shared deployment.

Only the `local_dev` and `enterprise` deployment profiles are accepted at
startup. The API rejects non-loopback clients in local development.
For an enterprise deployment, configure `APP_ENV=enterprise`,
`AUTH_MODE=oidc_jwt`, HTTPS `AUTH_JWKS_URL`, `AUTH_ISSUER`, `AUTH_AUDIENCE`,
explicit HTTPS `CORS_ALLOWED_ORIGINS`, and a unique `APP_SECRET_KEY` of at least
32 characters. JWTs must contain the configured workspace and roles claims;
the server uses those verified claims for project access and role checks. The
legacy static workspace-token adapter is development-only and is rejected in
enterprise mode.

Provider settings and audit views are scoped to the verified workspace and are
stored below `DATA_DIR/workspace_settings`. Existing global `settings.json`
values are not copied automatically into enterprise workspaces; migrate or
reconfigure each workspace through a reviewed operator process. The API-side
OIDC/JWT verification is present, but this repository does not yet include the
organization's browser login/session adapter. Complete that IdP integration
and place static pages behind the organization's access layer before using the
web UI as an enterprise deployment.

Provider endpoints are allowlisted before any outbound model request. OpenAI and
OpenRouter hosts are built in; add a custom provider hostname to
`LLM_PROVIDER_ALLOWLIST`. A project with `data_policy=local_only` requires a
configured local endpoint and will not use an active cloud provider.

### 3. Run the server

```bash
python -m backend.main
```

Open **http://127.0.0.1:8000** in your browser.

## What it does

| Capability | Status |
|---|---|
| Project management | ✅ |
| Artifact upload and structured parsing | ✅ |
| Evidence-backed trust-boundary review | ✅ |
| STRIDE threat generation | ✅ |
| LINDDUN privacy analysis | ✅ |
| Control mapping from built-in catalog | ✅ |
| Test scenario generation | ✅ |
| Connected analysis provider configuration | ✅ |
| Local analysis runtime | ✅ |
| Markdown, CSV, and JSON export | ✅ |
| Audit logging | ✅ |

The Report page and report exports show formal sign-off status separately from the enterprise release decision (`ready`, `not_ready`, or `superseded`). JSON includes release blocker details; Markdown and CSV include the verdict and blocker codes. When viewing an older snapshot, the UI labels the displayed verdict as the current project decision. A historical `signed` status alone does not mean the current report is approved for enterprise release.

## Analysis providers

The review workflow can use any OpenAI-compatible endpoint or a local inference server:

| Provider | Base URL |
|---|---|
| OpenAI | `https://api.openai.com/v1` |
| Azure OpenAI | `https://<resource>.openai.azure.com/openai/deployments/<model>` |
| OpenRouter | `https://openrouter.ai/api/v1` |
| Ollama | `http://localhost:11434/v1` with `OPENAI_API_KEY=ollama` |
| LM Studio | `http://localhost:1234/v1` |

## Supported input formats

| Input | Formats |
|---|---|
| Product requirements | Plain text, Markdown, PDF, DOCX |
| API contracts | OpenAPI / Swagger YAML or JSON |
| API collections | Postman JSON, HAR |
| Data models | SQL or text database schema |
| API inventory | CSV |

## Project archive and account data

From the dashboard, use **Export** on a project to download a ZIP containing
that project's context and parsed source metadata, findings, canonical DFD,
latest analysis state, and report revision history. **Import archive** restores
it into the account that is currently signed in. The archive's original workspace owner is ignored, and
an existing project ID is never overwritten. Archives are limited to 5 MiB.

Local accounts have separate workspace IDs, and the local account store rejects
assigning the same workspace ID to a second account. Projects from before
account scoping have no owner and remain hidden. The dashboard offers **Recover
previous data** only to the sole local administrator account; recovery assigns
those legacy projects to that account and creates a local backup before the
ownership metadata changes. Once another local account exists, that recovery
action is unavailable. Enterprise OIDC workspace membership continues to be
controlled by the identity provider's verified workspace claim.

## Golden-corpus quality gate

Run the versioned offline evaluation before changing threat validation,
control applicability, or test generation:

```bash
python -m backend.services.golden_corpus_service
```

The command exits non-zero when unsupported-finding rate, finding
precision/recall, DFD/control/test mapping precision/recall, executable-test
rate, or blocked-test accuracy misses the thresholds stored in
`fixtures/threat_model_golden_corpus.json`. The JSON output includes per-case
false positives/negatives and deterministic corpus, candidate, and evaluation
fingerprints.

To qualify a provider/model snapshot without writing production project data,
pass a JSON object keyed by corpus `case_id`:

```bash
python -m backend.services.golden_corpus_service \
  --reports /path/to/provider-report-snapshots.json \
  --output /tmp/golden-evaluation.json
```

The bundled candidates are an offline regression baseline for the application
pipeline, not evidence that a live provider has passed. Provider releases must
be evaluated using captured, redacted report snapshots against independently
reviewed corpus labels.

## Pre-release decision API

Consumer CI can read the current project decision with an authenticated request:

```text
GET /api/projects/{project_id}/release-decision
```

The response is `ready`, `not_ready`, or `superseded`, with the report and DFD
revisions, source/context fingerprints, approval actor, snapshot hash, and
blocker codes. `ready` requires a Reviewer-signed snapshot whose source
manifest, project context, DFD, analysis run, report revision, and stored
snapshot digest still match current state. A source/DFD/context change returns
`superseded`; a missing signature, snapshot, or quality-gate evidence returns
`not_ready`. The endpoint is workspace-scoped. In enterprise, call it with the
organization's verified OIDC/JWT identity; local development should use the
SQLite-backed local user mode described above and must not be exposed as a
shared service with authentication disabled. A decision can be
`ready` only when the server runs with `APP_ENV=enterprise` and
`AUTH_MODE=oidc_jwt`, and the immutable approval snapshot records the same
enterprise OIDC/JWT context. Local-development and legacy signatures remain
`not_ready` until a Reviewer signs again in the enterprise profile. Only the
Reviewer role can sign off; Admin alone is not an approval role.

Consumer CI can use the included fail-closed CLI. Store a short-lived,
workspace-scoped OIDC/JWT in the CI secret `CR8_PROJECT_RELEASE_TOKEN`; do not
pass it as a command-line argument or place it in the endpoint URL:

```bash
CR8_PROJECT_RELEASE_TOKEN="$RELEASE_API_TOKEN" npm run cr8:project-release -- \
  --decision-url "https://5stones.example/api/projects/payments-api/release-decision" \
  --project-id "payments-api"
```

The CLI exits `0` only for a complete `ready` response with a valid decision
fingerprint, enterprise OIDC/JWT authority, and matching project/revision
fields. It exits nonzero for
`not_ready`, `superseded`, malformed/tampered responses, transport failures,
and insecure non-loopback HTTP. CI output includes blocker codes but omits
blocker messages to reduce architecture detail in build logs.

This command checks the **project report decision only**. An application
release workflow must also require a passing, current 5STONES provider/tool
qualification (`npm run cr8:release` or the organization's trusted equivalent)
before relying on findings from that build. The provider qualification artifact
and its reviewer evidence must be handed to that workflow through a trusted,
run-bound mechanism; a project report signed by itself does not qualify the
5STONES model/provider.

For GitHub Actions, the repository includes a composite action that invokes
the same fail-closed consumer. Pin the action to an immutable commit SHA and
store the short-lived API token as a protected Actions secret:

```yaml
permissions:
  contents: read

jobs:
  threat-model-release:
    runs-on: ubuntu-latest
    steps:
      - name: Require a current 5STONES decision
        uses: YOUR_ORG/5stones/.github/actions/project-release-gate@IMMUTABLE_COMMIT_SHA
        with:
          project_id: payments-api
          qualification_path: artifacts/p0/cr8_qualification.json
          reviewer_evidence_path: artifacts/p0/reviewer_evidence.json
          review_evidence_hmac_key: ${{ secrets.CR8_REVIEW_EVIDENCE_HMAC_KEY }}
          decision_url: https://5stones.example/api/projects/payments-api/release-decision
          release_api_token: ${{ secrets.CR8_PROJECT_RELEASE_TOKEN }}
```

The action requires Node.js 18 or newer. It first verifies the live provider
qualification and run-bound signed reviewer evidence, then checks the current
project decision. The calling workflow must retrieve those JSON artifacts from
the trusted qualification run before invoking the action; do not accept them
from an untrusted pull request. Replace the organization, project ID, artifact
paths, endpoint, and pinned SHA with values approved for the deployment.
Adding this reusable action does not count as target-application CI integration
until an application repository calls it and a protected pipeline run
demonstrates the expected pass/fail behavior.

## Design principles

**Work with incomplete information.** Real threat modeling rarely starts with a complete picture. 5STONES surfaces confidence scores and missing information alongside every finding.

**Make assumptions visible.** If the analysis infers something it was not told, that assumption is recorded, reviewable, and editable.

**Produce role-aware output.** A finding is only useful when the right person can act on it. Every report connects threats to controls, owners, evidence, and executable tests.

## Security notes

- Keep secrets in `.env` or a managed secret store. Never commit real API keys, local settings, audit logs, generated reports, or runtime caches.
- Use a strong, unique `APP_SECRET_KEY` for every environment.
- The included server is still an MVP deployment. API authentication, role checks, workspace scoping, restricted CORS, and provider URL allowlisting are implemented, but browser SSO, rate limiting, durable append-only audit, transactional/concurrent storage, and backup/restore procedures still need deployment work before enterprise release.

## The name

5STONES is named after the principle that a small, well-aimed effort built on what you already have is more effective than a perfect tool you never use.
