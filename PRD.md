# Product Requirements Document

## AI-Assisted Threat Modeling Platform with MCP, BYOK, and Local LLM Support

## 1. Product Summary

Produk ini adalah platform internal untuk membantu Security, Red Team, AppSec, Developer, QA, dan Compliance melakukan threat modeling secara lebih cepat, konsisten, dan evidence-based.

Platform akan menerima input berupa PRD, API spec, Postman collection, Burp/HAR traffic, source code, architecture diagram, database schema, Jira ticket, atau input manual. Sistem kemudian menggunakan AI untuk membantu menghasilkan:

* Trust boundary
* Data flow
* Threat berdasarkan STRIDE
* Privacy threat berdasarkan LINDDUN
* Recommended security/privacy control
* Security test scenario
* Missing information
* Assumption register
* Confidence level
* Exportable security review report

Platform ini akan mendukung **MCP / Model Context Protocol** agar AI dapat terhubung secara standar ke sumber data dan tools internal. MCP adalah open protocol untuk menghubungkan aplikasi AI ke external systems, data sources, tools, dan workflows. MCP menggunakan arsitektur host-client-server, di mana server dapat expose **Resources**, **Prompts**, dan **Tools** untuk digunakan oleh AI client.

---

## 2. Background

Saat melakukan threat modeling, masalah yang sering terjadi adalah:

1. PRD tidak lengkap.
2. Techdoc tidak tersedia.
3. Architecture diagram tidak update.
4. Dev team tidak punya waktu untuk diskusi panjang.
5. Security review sering dilakukan mendekati release.
6. QA belum punya security test scenario yang jelas.
7. Security finding baru muncul saat pentest, bukan saat design phase.
8. Data privacy risk seperti PII leakage sering tidak terlihat di awal.

Akibatnya, threat modeling menjadi tidak konsisten dan sulit diskalakan.

Produk ini dibuat untuk mengubah threat modeling dari aktivitas manual-heavy menjadi **semi-automated security design review** berbasis artifact, AI, framework, dan reusable control catalog.

---

## 3. Problem Statement

Security team membutuhkan tools yang dapat membantu membuat initial threat model meskipun dokumentasi tidak lengkap, dengan tetap menampilkan evidence, assumption, confidence, dan missing information secara transparan.

Produk harus dapat menjawab pertanyaan utama berikut:

* Di mana trust boundary berada?
* Data sensitif apa yang diproses?
* Threat apa yang mungkin terjadi?
* Control apa yang dibutuhkan?
* Test scenario apa yang perlu dilakukan oleh Security/QA?
* Informasi apa yang masih belum jelas?
* Bagian mana yang berbasis evidence dan bagian mana yang masih assumption?

---

## 4. Goals

### 4.1 Product Goals

1. Membantu Security melakukan threat modeling lebih cepat dan konsisten.
2. Menghasilkan output yang actionable untuk Dev, QA, Security, dan Compliance.
3. Mendukung STRIDE untuk security threat dan LINDDUN untuk privacy threat.
4. Mendukung AI provider fleksibel melalui BYOK.
5. Mendukung Local LLM untuk kebutuhan privacy, confidentiality, dan cost control.
6. Mendukung MCP agar platform dapat mengambil konteks dari tools/sumber data internal secara standar.
7. Menghasilkan security test scenario yang bisa langsung dijadikan QA/security backlog.
8. Mengurangi dependency terhadap meeting panjang dengan dev team.
9. Menampilkan gap, assumption, dan confidence level secara jelas.

### 4.2 Business Goals

1. Shift-left security review sebelum development/release.
2. Mengurangi jumlah repeated vulnerability seperti IDOR, BAC, missing validation, PII leakage, dan insecure webhook.
3. Meningkatkan visibility security risk pada fitur baru.
4. Membantu compliance terhadap ISO 27001, PCI DSS, dan privacy regulation seperti UU PDP.
5. Membuat threat modeling menjadi repeatable process, bukan ad-hoc review.

---

## 5. Non-Goals

Produk ini tidak bertujuan untuk:

1. Menggantikan security engineer sepenuhnya.
2. Memberikan vulnerability proof-of-concept eksploitasi otomatis.
3. Melakukan active attack ke production system.
4. Menjadi scanner SAST/DAST penuh.
5. Menjamin semua threat terdeteksi 100%.
6. Menjadi source of truth tunggal tanpa human review.
7. Menyimpan API key user tanpa enkripsi dan access control yang kuat.

---

## 6. Target Users

### 6.1 Primary Users

| User                       | Need                                                    |
| -------------------------- | ------------------------------------------------------- |
| Security Engineer / AppSec | Membuat threat model dan security review lebih cepat    |
| Red Team                   | Membuat abuse case dan test scenario berdasarkan design |
| QA Engineer                | Mendapat security test case yang bisa dieksekusi        |
| Developer                  | Memahami control yang harus diterapkan                  |
| Product Manager            | Melihat security/privacy risk sejak PRD                 |
| Compliance / Privacy Team  | Melihat data flow, PII usage, dan privacy risk          |

### 6.2 User Persona

#### Persona 1 — Senior Red Team / AppSec

Butuh melihat trust boundary, abuse case, missing control, dan test scenario tanpa harus menunggu techdoc lengkap.

#### Persona 2 — Backend Developer

Butuh checklist kontrol seperti authorization, validation, logging, rate limit, signature, dan data minimization.

#### Persona 3 — QA Engineer

Butuh test scenario yang jelas, misalnya IDOR test, role bypass test, amount manipulation test, dan PII exposure test.

#### Persona 4 — Product Manager

Butuh visibility apakah fitur baru memiliki high-risk flow, sensitive data, external integration, atau compliance concern.

---

## 7. Product Scope

### 7.1 MVP Scope

MVP harus mencakup:

1. Project/workspace management.
2. Manual feature intake form.
3. Artifact upload.
4. Basic artifact parser.
5. Data flow builder.
6. Trust boundary detector.
7. STRIDE threat generator.
8. LINDDUN privacy threat generator.
9. Control mapper.
10. Test scenario generator.
11. Confidence and assumption register.
12. Missing information generator.
13. BYOK AI provider support.
14. Local LLM mode.
15. Basic MCP client support.
16. Export to Markdown, CSV, and JSON.

### 7.2 Future Scope

1. Jira integration.
2. GitHub/GitLab repository integration.
3. Swagger/Postman auto-sync.
4. Burp/HAR import.
5. MCP server mode.
6. Multi-agent threat modeling review.
7. Threat model diff between versions.
8. Approval workflow.
9. Compliance mapping.
10. Metrics dashboard.
11. Risk scoring engine.
12. Integration with ticketing and CI/CD.

---

## 8. MCP Product Requirements

MCP support perlu dibuat bukan hanya sebagai “nice to have”, tapi sebagai core integration layer.

MCP mendukung arsitektur host-client-server. Host mengelola client instances, lifecycle, permissions, authorization decision, security policy, dan context aggregation. Server menyediakan resources, tools, dan prompts, serta dapat berupa local process atau remote service.

### 8.1 MCP Usage Model

Produk akan mendukung dua mode MCP:

| Mode            | Description                                                           | Example                                               |
| --------------- | --------------------------------------------------------------------- | ----------------------------------------------------- |
| MCP Client Mode | Platform bertindak sebagai MCP client yang connect ke MCP server lain | Connect ke repo, docs, issue tracker, asset inventory |
| MCP Server Mode | Platform expose threat modeling capability sebagai MCP server         | External AI client dapat call `generate_threat_model` |

### 8.2 MCP Features to Cover

| MCP Feature            | Product Requirement                                                                                       |
| ---------------------- | --------------------------------------------------------------------------------------------------------- |
| Resources              | Platform dapat membaca context dari file, API spec, diagram, schema, code, logs, dan artifact lain        |
| Prompts                | Platform menyediakan prompt template untuk STRIDE, LINDDUN, control mapping, dan test scenario generation |
| Tools                  | Platform expose function seperti parse artifact, generate threat, map control, dan export report          |
| Transport              | Mendukung stdio untuk local MCP server dan Streamable HTTP untuk remote MCP server                        |
| Authorization          | Mendukung scoped access, token-based auth, dan server permission policy                                   |
| Capability Negotiation | Platform harus membaca declared capability dari MCP server sebelum memakai resources/tools/prompts        |
| Human Approval         | Sensitive tool invocation harus menampilkan approval prompt                                               |
| Audit Logging          | Semua MCP call harus terekam untuk audit                                                                  |

MCP mendefinisikan dua transport standar, yaitu stdio dan Streamable HTTP. Untuk Streamable HTTP, implementasi harus memperhatikan validasi Origin header, binding local server ke localhost jika berjalan lokal, dan authentication untuk koneksi.

---

## 9. BYOK and Local LLM Requirements

### 9.1 BYOK

BYOK berarti user membawa API key sendiri untuk AI provider.

Supported provider pada MVP:

| Provider Type    | Example                          |
| ---------------- | -------------------------------- |
| Cloud LLM        | OpenAI-compatible endpoint       |
| Enterprise LLM   | Azure OpenAI-compatible endpoint |
| Custom LLM       | OpenRouter-compatible endpoint   |
| Internal Gateway | Company-managed LLM gateway      |

Requirements:

1. User dapat menambahkan model provider.
2. User dapat memasukkan API key sendiri.
3. API key harus terenkripsi at rest.
4. API key tidak boleh muncul di log.
5. User dapat memilih model per workspace/project.
6. Admin dapat membatasi provider yang boleh digunakan.
7. Platform harus support custom base URL.
8. Platform harus support model selection.
9. Platform harus support token limit configuration.
10. Platform harus support fallback provider.

### 9.2 Local LLM

Local LLM digunakan untuk scenario data sensitif, confidential artifact, atau cost-sensitive environment.

Requirements:

1. User dapat memilih Local LLM mode.
2. Platform dapat connect ke local inference endpoint.
3. Platform harus support OpenAI-compatible local endpoint.
4. Platform harus menampilkan warning jika model lokal memiliki context length terbatas.
5. Platform harus support chunking artifact.
6. Platform harus support no-internet mode.
7. Platform harus bisa berjalan tanpa mengirim data ke cloud provider.
8. Platform harus menampilkan model capability limitation.
9. Platform harus mendukung prompt template yang lebih compact untuk local model.
10. Platform harus menyimpan hasil generation secara lokal sesuai workspace policy.

---

## 10. Input Requirements

### 10.1 Manual Input

User dapat mengisi input minimal berikut:

| Field               | Required | Example                                    |
| ------------------- | -------: | ------------------------------------------ |
| Feature Name        |      Yes | Checkout Payment                           |
| Feature Description |      Yes | Customer melakukan pembayaran via checkout |
| Actor               |      Yes | Customer, Merchant, Admin                  |
| Entry Point         |      Yes | Web, Mobile, API, Webhook                  |
| Data Involved       |      Yes | name, phone, amount, transaction_id        |
| Auth Method         | Optional | JWT, API key, HMAC                         |
| External System     | Optional | Merchant server, payment partner           |
| Critical Action     | Optional | Create payment, refund, update status      |
| Environment         | Optional | Production, staging                        |
| Existing Control    | Optional | WAF, rate limit, RBAC                      |

### 10.2 Artifact Input

Platform harus mendukung artifact berikut:

| Artifact             |     MVP |      Future |
| -------------------- | ------: | ----------: |
| Text PRD             |     Yes |         Yes |
| Markdown document    |     Yes |         Yes |
| OpenAPI/Swagger      |     Yes |         Yes |
| Postman collection   |     Yes |         Yes |
| CSV/XLSX API list    |     Yes |         Yes |
| HAR/Burp traffic     | Partial |         Yes |
| Source code zip      | Partial |         Yes |
| Architecture diagram |  Manual | AI-assisted |
| Database schema      |     Yes |         Yes |
| Jira ticket          |      No |         Yes |
| GitHub/GitLab repo   |      No |         Yes |
| Asset inventory      |     CSV |     MCP/API |

### 10.3 MCP Resource Input

MCP Resources memungkinkan server membagikan data seperti file, database schema, atau application-specific information kepada client. Resource diidentifikasi menggunakan URI dan dapat dibaca melalui protocol message seperti `resources/list` dan `resources/read`.

Platform harus dapat mengambil context dari MCP Resources seperti:

* `file://prd/checkout.md`
* `file://openapi/payment.yaml`
* `git://repo/payment-service`
* `db://schema/transaction`
* `asset://inventory/public-api`
* `jira://ticket/SEC-123`
* `burp://traffic/checkout.har`

---

## 11. Process Requirements

### 11.1 High-Level Process

```text
Input Artifact / Manual Intake / MCP Resource
        ↓
Artifact Normalization
        ↓
Entity Extraction
        ↓
Data Flow Generation
        ↓
Trust Boundary Detection
        ↓
Data Classification
        ↓
STRIDE Threat Generation
        ↓
LINDDUN Privacy Threat Generation
        ↓
Control Mapping
        ↓
Test Scenario Generation
        ↓
Confidence + Assumption + Missing Info
        ↓
Human Review
        ↓
Export / Backlog / Report
```

### 11.2 Entity Extraction

Platform harus mengekstrak entity berikut:

| Entity          | Example                      |
| --------------- | ---------------------------- |
| Actor           | Customer, Merchant, Admin    |
| Component       | Frontend, API, Service, DB   |
| Data Store      | Transaction DB, Log Storage  |
| Data Flow       | Browser → API                |
| Trust Boundary  | Public Internet → Backend    |
| Asset           | Payment status, PII, token   |
| Control         | RBAC, HMAC, rate limit       |
| External System | Merchant server, partner API |
| Critical Action | Refund, update status        |

### 11.3 Trust Boundary Detection

Platform harus mendeteksi trust boundary ketika data berpindah antar area dengan trust level berbeda.

Default trust level:

| Entity               | Trust Level              |
| -------------------- | ------------------------ |
| Anonymous User       | Untrusted                |
| Logged-in Customer   | Low Trust                |
| Merchant Server      | External Trusted         |
| Third-party Provider | External Dependency      |
| Internal Service     | Internal Trusted         |
| Admin User           | Privileged               |
| Database             | Highly Trusted           |
| Log Storage          | Sensitive Internal Store |

Example detection:

| Source           | Destination          | Trust Boundary                     |
| ---------------- | -------------------- | ---------------------------------- |
| Customer Browser | Checkout API         | Public → Internal                  |
| Merchant Server  | Webhook API          | External → Internal                |
| API Service      | Database             | Internal Service → Sensitive Store |
| Backend          | Third-party Provider | Internal → External                |
| Admin Panel      | Internal API         | Privileged User → Internal API     |

### 11.4 STRIDE Threat Generation

Platform harus menghasilkan threat berdasarkan STRIDE.

| STRIDE                 | Example Threat                           |
| ---------------------- | ---------------------------------------- |
| Spoofing               | Attacker impersonates merchant webhook   |
| Tampering              | User modifies amount or payment status   |
| Repudiation            | No audit trail for refund action         |
| Information Disclosure | User accesses another user’s transaction |
| Denial of Service      | Public API abused without rate limit     |
| Elevation of Privilege | Merchant user accesses admin function    |

### 11.5 LINDDUN Privacy Threat Generation

Platform harus menghasilkan privacy threat berdasarkan LINDDUN jika terdapat PII atau sensitive personal data.

| LINDDUN                   | Example Threat                                      |
| ------------------------- | --------------------------------------------------- |
| Linkability               | Transaction activity can be linked across services  |
| Identifiability           | Phone number identifies customer                    |
| Non-repudiation           | User behavior is over-tracked without clear purpose |
| Detectability             | Third party can detect user performed transaction   |
| Disclosure of Information | PII exposed to unauthorized party                   |
| Unawareness               | User does not know data is shared with partner      |
| Non-compliance            | Data retention or purpose is unclear                |

### 11.6 Control Mapping

Platform harus mencocokkan threat dengan control catalog.

| Threat                 | Recommended Control              |
| ---------------------- | -------------------------------- |
| IDOR                   | Object ownership validation      |
| Fake Webhook           | HMAC signature, timestamp, nonce |
| Amount Tampering       | Server-side amount calculation   |
| PII Leakage            | Data minimization and masking    |
| Replay Attack          | Nonce and timestamp validation   |
| Privilege Escalation   | Server-side RBAC/ABAC            |
| Missing Audit Trail    | Immutable audit log              |
| Sensitive Log Exposure | Log masking and filtering        |

### 11.7 Test Scenario Generation

Setiap threat harus menghasilkan test scenario dengan format:

| Field              | Description                       |
| ------------------ | --------------------------------- |
| Test Scenario Name | Nama scenario                     |
| Preconditions      | Kondisi awal                      |
| Steps              | Langkah test                      |
| Expected Result    | Hasil yang seharusnya             |
| Evidence Needed    | Screenshot, request-response, log |
| Related Control    | Control yang diuji                |
| Priority           | Critical, High, Medium, Low       |

Example:

| Field           | Example                                                 |
| --------------- | ------------------------------------------------------- |
| Scenario Name   | IDOR on Transaction Detail                              |
| Preconditions   | User A dan User B memiliki transaksi berbeda            |
| Steps           | Login sebagai User B, akses transaction ID milik User A |
| Expected Result | API return 403/404                                      |
| Evidence Needed | Request-response                                        |
| Related Control | Object ownership validation                             |
| Priority        | High                                                    |

---

## 12. Output Requirements

### 12.1 Threat Model Table

Platform harus menghasilkan table berikut:

| Field               | Description                              |
| ------------------- | ---------------------------------------- |
| Feature             | Nama fitur                               |
| Component           | Komponen terkait                         |
| Source              | Asal data/request                        |
| Destination         | Tujuan data/request                      |
| Trust Boundary      | Boundary yang dilalui                    |
| Asset               | Asset yang terdampak                     |
| Data Classification | Public, Internal, PII, Financial, Secret |
| Framework           | STRIDE atau LINDDUN                      |
| Threat Category     | Spoofing, Tampering, Disclosure, etc.    |
| Threat Description  | Penjelasan threat                        |
| Abuse Case          | Cara threat bisa terjadi                 |
| Recommended Control | Control yang disarankan                  |
| Test Scenario       | Cara menguji                             |
| Expected Result     | Hasil expected                           |
| Evidence            | Artifact pendukung                       |
| Assumption          | Asumsi yang dibuat                       |
| Missing Info        | Informasi yang belum tersedia            |
| Confidence          | High, Medium, Low                        |
| Risk Level          | Critical, High, Medium, Low              |
| Owner               | Dev, QA, Security, PM                    |
| Status              | Open, Reviewed, Accepted, Mitigated      |

### 12.2 Trust Boundary View

Output visual minimal:

```text
[Customer Browser - Untrusted]
        |
        | Trust Boundary: Public Internet → Backend
        v
[Checkout API - Internal]
        |
        | Trust Boundary: Internal Service → Sensitive Data Store
        v
[Transaction Database - Sensitive]


[Merchant Server - External Trusted]
        |
        | Trust Boundary: External → Internal
        v
[Webhook API - Internal]
```

### 12.3 Control Checklist

| Control                       | Status  | Evidence                | Owner   |
| ----------------------------- | ------- | ----------------------- | ------- |
| Object ownership check        | Unknown | Need code review        | Backend |
| HMAC webhook signature        | Unknown | Need confirmation       | Backend |
| Server-side amount validation | Unknown | Need test               | Backend |
| PII masking                   | Partial | Response contains phone | Backend |
| Audit log                     | Unknown | Need confirmation       | Backend |
| Rate limit                    | Unknown | Need gateway check      | DevOps  |

### 12.4 Security Test Backlog

| Test ID | Scenario                                 | Priority | Owner       |
| ------- | ---------------------------------------- | -------- | ----------- |
| TM-001  | Test IDOR on transaction detail          | High     | QA/Security |
| TM-002  | Test amount manipulation                 | High     | Security    |
| TM-003  | Test fake webhook without signature      | Critical | Security    |
| TM-004  | Test replay webhook                      | High     | Security    |
| TM-005  | Review PII in API response               | Medium   | QA          |
| TM-006  | Test role-based access on admin endpoint | High     | QA/Security |

### 12.5 Missing Information Report

| Area          | Question                                       | Why It Matters                      |
| ------------- | ---------------------------------------------- | ----------------------------------- |
| Webhook       | Apakah callback menggunakan HMAC signature?    | Mencegah fake payment status update |
| Authorization | Apakah ada ownership check?                    | Mencegah IDOR                       |
| PII           | Apakah phone number wajib dikirim ke frontend? | Data minimization                   |
| Logging       | Apakah PII masuk log?                          | Privacy risk                        |
| Rate Limit    | Apakah create payment punya throttling?        | Abuse prevention                    |

### 12.6 Assumption Register

| Area             | Assumption                                        | Confidence |
| ---------------- | ------------------------------------------------- | ---------- |
| Webhook          | Endpoint callback dapat diakses public            | Medium     |
| Authorization    | Transaction ID digunakan sebagai object reference | Medium     |
| PII              | Customer phone termasuk data pribadi              | High       |
| Logging          | Request body mungkin tercatat di log              | Low        |
| External Sharing | Merchant menerima sebagian data customer          | Medium     |

---

## 13. AI Requirements

### 13.1 AI Tasks

AI digunakan untuk:

1. Summarize PRD.
2. Extract actor/component/data flow.
3. Identify trust boundary.
4. Generate STRIDE threat.
5. Generate LINDDUN privacy threat.
6. Recommend controls.
7. Generate test scenario.
8. Identify missing information.
9. Assign confidence level.
10. Generate report.

### 13.2 AI Guardrails

AI tidak boleh:

1. Menghasilkan exploit payload berbahaya secara otomatis.
2. Mengklaim control sudah ada tanpa evidence.
3. Menghapus assumption tanpa human confirmation.
4. Mengirim confidential artifact ke cloud LLM jika workspace diset ke Local LLM only.
5. Menyimpan BYOK key dalam plaintext.
6. Menghasilkan risk rating final tanpa label confidence.
7. Mengubah output approved tanpa versioning.

### 13.3 Confidence Rules

| Confidence | Rule                                                     |
| ---------- | -------------------------------------------------------- |
| High       | Ada evidence dari artifact, code, API spec, atau traffic |
| Medium     | Ada indikasi kuat tapi belum verified                    |
| Low        | Berdasarkan assumption atau pattern umum                 |

---

## 14. MCP Functional Requirements

### 14.1 MCP Client

Platform harus dapat connect ke MCP server.

Requirements:

1. User dapat menambahkan MCP server.
2. User dapat memilih transport: stdio atau Streamable HTTP.
3. User dapat melihat server capability.
4. User dapat melihat available resources, prompts, dan tools.
5. User dapat memilih resource yang akan digunakan sebagai context.
6. Platform harus meminta approval sebelum menjalankan sensitive tool.
7. Platform harus menyimpan audit log untuk MCP call.
8. Platform harus membatasi scope server berdasarkan workspace policy.

### 14.2 MCP Server

Platform dapat expose dirinya sebagai MCP server.

MCP Tools yang dapat diexpose:

| Tool Name                           | Description                      |
| ----------------------------------- | -------------------------------- |
| `threatmodel.generate`              | Generate threat model dari input |
| `threatmodel.detect_trust_boundary` | Detect trust boundary            |
| `threatmodel.generate_stride`       | Generate STRIDE threats          |
| `threatmodel.generate_linddun`      | Generate LINDDUN threats         |
| `threatmodel.map_controls`          | Map threat ke controls           |
| `threatmodel.generate_tests`        | Generate security test scenarios |
| `threatmodel.export_report`         | Export report                    |

MCP Resources yang dapat diexpose:

| Resource                          | Description         |
| --------------------------------- | ------------------- |
| `threatmodel://projects/{id}`     | Project metadata    |
| `threatmodel://reports/{id}`      | Threat model report |
| `threatmodel://controls/catalog`  | Control catalog     |
| `threatmodel://templates/stride`  | STRIDE template     |
| `threatmodel://templates/linddun` | LINDDUN template    |

MCP Prompts yang dapat diexpose:

| Prompt                    | Description                      |
| ------------------------- | -------------------------------- |
| `stride_review`           | Generate STRIDE analysis         |
| `linddun_review`          | Generate privacy threat analysis |
| `security_test_generator` | Generate test scenarios          |
| `missing_info_generator`  | Generate clarification questions |
| `control_mapper`          | Recommend security controls      |

MCP Tools harus memiliki input schema dan output schema agar output dapat divalidasi. MCP tools didefinisikan dengan name, description, inputSchema, optional outputSchema, annotations, dan execution metadata.

### 14.3 MCP Security Requirements

1. Validate all MCP tool inputs.
2. Sanitize all MCP tool outputs.
3. Enforce access control for every MCP resource/tool.
4. Require user confirmation for sensitive tool invocation.
5. Rate limit MCP tool calls.
6. Log all MCP invocations.
7. Do not expose full conversation history to MCP server.
8. Do not allow MCP server to access other MCP server context directly.
9. Validate Origin header for HTTP transport.
10. Bind local MCP server to localhost by default.
11. Support token-based authorization for remote MCP.
12. Support scoped permission per MCP server.

MCP tool security guidance includes input validation, access control, rate limiting, output sanitization, user confirmation for sensitive operations, timeout, result validation, and audit logging.

---

## 15. Security and Privacy Requirements

### 15.1 Data Protection

1. Artifact must be encrypted at rest.
2. API keys must be encrypted at rest.
3. Sensitive fields must be masked in logs.
4. User can delete project data.
5. Workspace can enforce local-only processing.
6. AI request/response should be stored based on workspace policy.
7. Admin can disable cloud LLM.
8. Admin can restrict allowed MCP servers.
9. Access must follow RBAC.
10. Export must include sensitivity warning.

### 15.2 Access Control

Roles:

| Role     | Permission                           |
| -------- | ------------------------------------ |
| Viewer   | Read report                          |
| Analyst  | Create and edit threat model         |
| Reviewer | Approve/reject threat model          |
| Admin    | Manage workspace, model, MCP, policy |
| Owner    | Full access                          |

### 15.3 Audit Log

Audit log must include:

| Event                    | Required |
| ------------------------ | -------- |
| User login               | Yes      |
| Artifact upload          | Yes      |
| AI generation            | Yes      |
| MCP resource read        | Yes      |
| MCP tool call            | Yes      |
| API key added/updated    | Yes      |
| Report exported          | Yes      |
| Threat accepted/modified | Yes      |
| Control status changed   | Yes      |

---

## 16. Data Model

### 16.1 Project

```json
{
  "project_id": "uuid",
  "name": "Checkout Payment Threat Model",
  "owner": "security-team",
  "environment": "staging",
  "data_policy": "local_only | byok_allowed | cloud_allowed",
  "created_at": "timestamp",
  "updated_at": "timestamp"
}
```

### 16.2 Data Flow

```json
{
  "flow_id": "uuid",
  "source": "Customer Browser",
  "destination": "Checkout API",
  "protocol": "HTTPS",
  "data": ["transaction_id", "amount", "customer_phone"],
  "trust_boundary": "Public Internet → Internal Backend",
  "evidence": ["openapi.yaml", "prd.md"]
}
```

### 16.3 Threat

```json
{
  "threat_id": "TM-001",
  "framework": "STRIDE",
  "category": "Tampering",
  "description": "Customer may modify amount in client-side request",
  "asset": "Payment Amount",
  "control": "Server-side amount validation",
  "test_scenario": "Intercept request and modify amount",
  "confidence": "Medium",
  "risk_level": "High",
  "assumption": "Amount is submitted from frontend",
  "missing_info": "Need confirmation whether backend recalculates amount"
}
```

---

## 17. User Stories

### 17.1 Security Engineer

As a Security Engineer, I want to upload PRD/API spec so that the platform can generate initial threat model automatically.

Acceptance Criteria:

* User can upload artifact.
* System extracts actor, data, endpoint, and component.
* System generates trust boundary, threat, control, and test scenario.
* Output includes confidence and assumption.

### 17.2 Red Team

As a Red Team member, I want abuse cases and test scenarios so that I can validate design risk before pentest.

Acceptance Criteria:

* Each threat has abuse case.
* Each threat has test scenario.
* Test scenario includes steps and expected result.
* Test can be exported to CSV/Markdown.

### 17.3 Developer

As a Developer, I want clear recommended controls so that I know what to implement.

Acceptance Criteria:

* Each threat maps to at least one control.
* Control includes implementation guidance.
* Control has owner and status.

### 17.4 QA

As a QA Engineer, I want security test scenarios so that I can add them into regression test.

Acceptance Criteria:

* Test scenario has precondition, steps, expected result.
* Test scenario can be filtered by feature, severity, and owner.
* Test scenario can be exported.

### 17.5 Admin

As an Admin, I want to configure BYOK, Local LLM, and MCP policy so that company data is handled securely.

Acceptance Criteria:

* Admin can allow/deny cloud LLM.
* Admin can configure allowed MCP servers.
* Admin can enforce Local LLM only.
* Admin can view audit log.

---

## 18. MVP Acceptance Criteria

MVP is considered successful if:

1. User can create project.
2. User can input feature manually.
3. User can upload at least PRD, Markdown, OpenAPI, and Postman collection.
4. System can generate data flow.
5. System can identify trust boundary.
6. System can generate STRIDE threats.
7. System can generate LINDDUN threats when PII exists.
8. System can recommend controls.
9. System can generate test scenarios.
10. System can produce missing information list.
11. Output includes evidence, assumption, confidence, and risk level.
12. User can configure BYOK provider.
13. User can configure Local LLM endpoint.
14. User can connect at least one MCP server via stdio.
15. User can read MCP resources.
16. User can export report to Markdown, CSV, and JSON.
17. Audit log records artifact upload, AI generation, and MCP call.

---

## 19. Metrics and Success Criteria

### 19.1 Product Metrics

| Metric                                | Target       |
| ------------------------------------- | ------------ |
| Time to generate initial threat model | < 10 minutes |
| Manual fields required for MVP        | ≤ 10 fields  |
| Threats with mapped controls          | ≥ 90%        |
| Threats with test scenario            | ≥ 90%        |
| Output with confidence label          | 100%         |
| Export success rate                   | ≥ 99%        |

### 19.2 Security Process Metrics

| Metric                                              | Target   |
| --------------------------------------------------- | -------- |
| Security review started before development complete | Increase |
| Repeated IDOR/BAC finding                           | Decrease |
| PII leakage finding after release                   | Decrease |
| Dev clarification time                              | Decrease |
| QA security test coverage                           | Increase |

---

## 20. Prioritization

### P0 — Must Have

1. Manual intake.
2. Artifact upload.
3. STRIDE generation.
4. LINDDUN generation.
5. Trust boundary detection.
6. Control mapping.
7. Test scenario generation.
8. BYOK support.
9. Local LLM endpoint support.
10. Export Markdown/CSV/JSON.
11. Basic MCP client with stdio.
12. Audit log.

### P1 — Should Have

1. Streamable HTTP MCP.
2. MCP server mode.
3. Swagger parser improvement.
4. HAR/Burp parser.
5. Threat model diff.
6. Jira export.
7. Role-based workflow.
8. Compliance mapping.

### P2 — Nice to Have

1. Diagram auto-generation.
2. Multi-agent review.
3. GitHub/GitLab integration.
4. CI/CD integration.
5. Advanced risk scoring.
6. Dashboard metrics.
7. Approval workflow.
8. Custom framework support.

---

## 21. Release Plan

### Phase 1 — MVP

Focus:

* Manual intake
* Artifact upload
* STRIDE + LINDDUN generation
* Trust boundary
* Control mapping
* Test scenario
* BYOK
* Local LLM
* Basic MCP client
* Export

### Phase 2 — Integration

Focus:

* Streamable HTTP MCP
* MCP server mode
* Jira export
* GitHub/GitLab
* Burp/HAR
* Swagger advanced parser
* RBAC

### Phase 3 — Enterprise Readiness

Focus:

* Audit dashboard
* Compliance mapping
* Approval workflow
* Policy engine
* Organization-wide MCP allowlist
* Threat model versioning
* Metrics dashboard

---

## 22. Risks and Mitigations

| Risk                               | Impact                   | Mitigation                                            |
| ---------------------------------- | ------------------------ | ----------------------------------------------------- |
| AI hallucination                   | Incorrect threat/control | Show evidence, confidence, assumption                 |
| Sensitive data sent to cloud LLM   | Data leakage             | Local LLM mode, BYOK policy, admin restrictions       |
| MCP server malicious/misconfigured | Data exfiltration        | MCP allowlist, scoped permission, approval, audit log |
| Output too generic                 | Low adoption             | Use domain-specific control catalog                   |
| Dev distrusts AI output            | Low usage                | Show evidence and missing info clearly                |
| Local LLM quality lower            | Poor output              | Compact prompt, chunking, model capability warning    |
| PRD incomplete                     | Missing threat           | Assumption register and missing info report           |

---

## 23. Open Questions

1. Apakah platform ini akan digunakan hanya internal security atau juga oleh developer/QA?
2. Apakah artifact boleh dikirim ke cloud LLM atau harus default local-only?
3. MCP server apa saja yang akan di-support pada MVP?
4. Apakah Jira integration wajib di MVP?
5. Apakah threat model perlu approval dari Security Lead?
6. Risk scoring menggunakan simple rating atau CVSS/DREAD?
7. Apakah compliance mapping ke PCI DSS/ISO/UU PDP dibutuhkan di MVP?
8. Apakah output perlu langsung dibuat dalam format ticket?
9. Apakah repository source code boleh diproses oleh AI?
10. Apakah audit log perlu immutable storage?

---

## 24. Recommended MVP Output Example

### Feature: Checkout Payment

| Trust Boundary                  | Framework                       | Threat                                 | Control                            | Test Scenario                                 | Confidence |
| ------------------------------- | ------------------------------- | -------------------------------------- | ---------------------------------- | --------------------------------------------- | ---------- |
| Customer Browser → Checkout API | STRIDE - Tampering              | User modifies amount                   | Server-side amount validation      | Intercept request and change amount           | Medium     |
| Customer Browser → Checkout API | STRIDE - Information Disclosure | User accesses another user transaction | Object ownership check             | Replace transaction_id with another user’s ID | Low        |
| Merchant Server → Webhook API   | STRIDE - Spoofing               | Fake webhook updates payment status    | HMAC signature + timestamp + nonce | Send callback without valid signature         | Medium     |
| Checkout API → Frontend         | LINDDUN - Disclosure            | Customer phone exposed in response     | Data minimization and masking      | Review API response fields                    | High       |
| Backend → Log Storage           | LINDDUN - Non-compliance        | PII stored in logs                     | Log masking and retention policy   | Check application logs                        | Medium     |

---

## 25. Final Product Positioning

This product is not just a threat modeling documentation tool.

It is an:

**AI-assisted Security Design Review and Threat Modeling Platform**

Core value:

* Helps security start review even when PRD is incomplete.
* Turns incomplete information into visible assumptions.
* Converts threat modeling into actionable controls and test scenarios.
* Supports STRIDE and LINDDUN.
* Supports enterprise AI deployment through BYOK and Local LLM.
* Uses MCP as an integration layer for tools, documents, resources, and workflows.

The expected outcome is better security visibility before development is completed, with clear ownership between Product, Developer, QA, Security, and Compliance.
