# Alignment Plan — DFD dan Threat Analysis

## Baseline

- Acuan: `DFD_Feature_AI_Agent_Prompt.md`
- Status project saat ini: **grounded threat-modeling MVP dengan DFD visualization**.
- Target akhir: **semantic DFD modeling feature** yang menjadi source of truth untuk canvas, inventory, export, STRIDE, dan LINDDUN.
- Test baseline saat analisis dibuat: 24 test Python lulus dan 1 regression test JavaScript lulus.
- Belum ada perubahan implementasi pada baseline ini; file ini menjadi rencana kerja dan checklist progress.

## Goal

Align project dengan dokumen acuan, dengan fokus pada:

1. Canonical semantic DFD yang tervalidasi dan tersimpan.
2. Trust zone, ownership, scope, exposure, logical boundary, dan crossing yang benar.
3. Evidence, assertion, unknown, conflicting information, question, dan revision lifecycle.
4. STRIDE/LINDDUN yang menganalisis model DFD yang sama dan memiliki traceability ke node/flow/boundary/data.
5. UI DFD yang editable, dapat direview, disimpan, diekspor, dan dapat ditelusuri ke threat.
6. Isolation, redaction, schema validation, dan proteksi untrusted document.

## Milestone status

### M0 — Existing baseline dan fondasi

Status: **Sebagian selesai**

Sudah tersedia:

- Artifact parser untuk PRD, OpenAPI, Postman, database schema, CSV, HAR, dan Markdown.
- Postman nested folder serta inherited auth.
- Evidence catalog dengan direct/context/inference.
- Deterministic trust-boundary generation dan human review fingerprint.
- Context, services, dan scenarios view.
- Threat target references dan stale flag untuk perubahan trust-boundary review.
- Diagram interaktif, inspector, fit-to-view, fullscreen, accessible text alternative, dan PNG export.

Yang masih kurang pada milestone ini:

- Baseline fixture synthetic customer registration sesuai dokumen.
- Test contract/invariant untuk semantic DFD.
- Dokumentasi arsitektur target dan migration strategy.

Referensi utama: `backend/services/trust_boundary_service.py`, `backend/services/posture_service.py`, `frontend/analysis.html`, `frontend/js/analysis.js`.

### M1 — Canonical semantic DFD model

Status: **Sebagian selesai — prioritas P0**

Progress pada branch `codex/dfd-threat-model-alignment`:

- `backend/models/dfd.py` menambahkan canonical typed DFD contract.
- `backend/services/dfd_model_service.py` menambahkan deterministic adapter dan semantic hash/revision.
- Analysis report menyimpan `dfd_model` dan `dfd_validation`.

Deliverables:

- Tambahkan domain schema tervalidasi untuk:
  - `Model`
  - `Node`
  - `Process`
  - `DataStore`
  - `DataObject`
  - `Flow`
  - `Zone`
  - `Boundary`
  - `View`
  - `Evidence`
  - `Assertion`
  - `Question`
  - `Control`
  - `Threat`
- Model minimum memiliki `id`, `projectId`, `schemaVersion`, `revision`, `title`, `scopeDescription`, `sourceRefs`, `nodes`, `flows`, `zones`, `boundaries`, `views`, dan `questions`.
- Gunakan stable internal IDs serta display IDs `E1`, `P1`, `D1`, `F1`, `TB1`, dan `T1`.
- Pisahkan semantic model dari presentation state/layout.
- Simpan model secara eksplisit, bukan hanya sebagai derived `trust_model` di report.
- Tambahkan migration/version strategy untuk model lama.

Definition of done:

- Semua API input/output dan AI output melewati schema validation.
- Model dapat disimpan, dibuka kembali, dan memiliki revision yang jelas.
- Duplicate ID, dangling reference, invalid type, dan invalid schema ditolak.

### M2 — Graph integrity dan DFD semantics

Status: **Sebagian selesai — prioritas P0**

Progress:

- Validator sudah mendeteksi duplicate ID, dangling reference, invalid parent process, missing zone/data/boundary refs, dan zone cycle.
- Validator memisahkan blocking graph errors dari reviewable warnings.
- Regression tests untuk typed refs dan invalid graph sudah ditambahkan.

Deliverables:

- Validator graph untuk memastikan:
  - source dan target flow selalu menunjuk node yang ada;
  - setiap flow konvensional terhubung minimal ke satu process;
  - external-entity-to-store dan store-to-store menjadi review issue, bukan process fiktif;
  - request dan response adalah flow terpisah;
  - flow memiliki data label berbentuk data, bukan hanya protokol;
  - process memakai nama aktivitas;
  - process/store/actor tidak ditentukan hanya dari heuristik label;
  - same-zone flow tetap masuk scope analysis.
- Tambahkan `dataObjectIds`, `interactionKind`, `authn`, `authz`, dan lineage.
- Pertahankan detail unknown tanpa membuat default seperti `HTTPS` menjadi fakta.

Definition of done:

- Unit test untuk graph integrity, same-zone flow, invalid flow, duplicate ID, dan dangling reference.
- Postman-only input tidak menghasilkan database atau topology internal yang tidak terdokumentasi.

### M3 — Ownership, scope, exposure, zone, dan boundary crossing

Status: **Sebagian selesai — prioritas P0**

Progress:

- Canonical model sekarang memiliki field terpisah untuk scope, ownership, dan exposure dengan default `unknown`.
- Threat mapping tidak lagi fan-out ke seluruh boundary ketika tidak ada match.
- Regression test multi-boundary unmapped threat sudah ditambahkan.

Deliverables:

- Pisahkan dimensi:
  - `scope`: `in_scope`, `external_dependency`, `unknown`
  - `ownership`: `organization`, `customer`, `vendor`, `shared`, `unknown`
  - `exposure`: `internet_facing`, `private`, `local`, `unknown`
  - `trustZoneId`
- Tambahkan `boundary.types`: network, identity, privilege, tenant, organization.
- Tambahkan nested zone dan `parentZoneId`.
- Hitung crossing dari semantic membership dan ancestor, bukan dari garis visual.
- Deduplicate crossing dan simpan rationale serta origin mapping.
- Dukung logical identity/privilege/tenant crossing pada same-zone flow.
- Representasikan unresolved membership sebagai `unresolved`, bukan no-crossing.
- Jangan menjadikan ownership group otomatis sebagai trust boundary.

Critical fix:

- Perbaiki mapping di `attach_target_refs()`. Threat yang tidak match tidak boleh otomatis diarahkan ke semua boundary.
- Threat tanpa reference valid harus berstatus `unmapped` atau `insufficient_information`.

Definition of done:

- Test nested boundary, common ancestor, logical boundary, unresolved membership, dan multi-boundary threat mapping.

### M4 — Source, evidence, assertion, dan ingestion pipeline

Status: **Partial — perlu diperkuat, prioritas P1**

Sudah ada:

- Artifact hash/revision.
- Verifikasi snippet evidence terhadap source content.
- Reconciliation dan conflict record sederhana.

Yang perlu ditambahkan:

- Pipeline eksplisit: ingest → extract → normalize → validate → review → analyze → persist.
- Evidence dengan `documentId`, `documentRevision`, `documentHash`, locator terstruktur, dan redacted excerpt.
- Assertion per atribut dengan status `documented`, `inferred`, `unknown`, `conflicting`.
- Question dengan `affectedRefs`, `sourceRefs`, reason, status, dan resolution.
- Retain both assertions saat dokumen bertentangan.
- Redact secret sebelum konten dikirim ke AI, termasuk jalur generic PRD/Markdown/text.
- Postman: simpan unresolved variable references, inherited auth result, dan saved response examples bila ada.
- Jangan mengeksekusi pre-request/test script atau request dari collection.

Definition of done:

- Test secret redaction, prompt-injection text, conflicting evidence, unresolved variables, dan saved response examples.

### M5 — DFD views dan UI editing lifecycle

Status: **Belum selesai — prioritas P1**

Deliverables:

- Ganti/selaraskan view menjadi:
  - Context
  - System DFD
  - Feature DFD
- Context harus berupa projection/agregasi dengan mapping ke canonical graph.
- Feature DFD harus memiliki `parentProcessId`, child nodes, child flows, dan input/output port mapping.
- Canvas mendukung bentuk entity/process/store, directed flow, ID, label data, zone, ownership group, nested zone, collapse/expand, search, pan/zoom, fit-to-view, auto-layout, dan selection highlight.
- Tambahkan inventory table untuk nodes, flows, zones, boundaries, questions, dan threats.
- Tambahkan inspector Input–Process–Output untuk process.
- Tambahkan flow inspector untuk source, destination, data, protocol, authn/authz, crossing, evidence, question, dan threat.
- Tambahkan add/edit/remove node, flow, zone, boundary, metadata, dan validation message.
- Tambahkan undo/redo serta delete impact preview.
- Simpan posisi, viewport, collapsed group, dan layout revision.
- Regenerate menghasilkan proposal diff, tidak menimpa human edit.

Definition of done:

- Drag node tidak mengubah semantic membership secara diam-diam.
- Reload memulihkan model dan layout.
- Perubahan layout saja tidak membuat threat analysis stale.

### M6 — Graph-driven STRIDE dan LINDDUN

Status: **Partial tetapi belum aligned — prioritas P0/P1**

Progress:

- Prompt STRIDE/LINDDUN sekarang menerima canonical DFD node, data object, flow, boundary, revision, dan open questions.
- Prompt meminta affected refs berbasis stable DFD IDs serta coverage terpisah.
- Output schema validation, taxonomy migration, dan fallback semantics masih harus dikerjakan.

Deliverables STRIDE:

- Analysis adapter menerima canonical DFD snapshot, bukan hanya project summary dan boundary text.
- Evaluasi source–flow–destination, process, store, crossing, identity, privilege, dan controls.
- Tambahkan coverage assessment terpisah dari threat list.
- Jangan selalu menghasilkan enam finding.
- Pisahkan candidate threat dari validated finding.
- Threat minimum memiliki title, scenario, taxonomy version, affected refs, evidence refs, assumptions, preconditions, impact, known controls, recommended mitigations, validation steps, status, dan analyzed revision.

Deliverables LINDDUN:

- Model sender–flow–receiver dan data lifecycle.
- Data metadata untuk purpose, recipient, data subject, direct/indirect identifier, linkability, retention, deletion, notice, individual control, dan documented legal basis.
- Gunakan taxonomy/label sesuai dokumen dengan alias mapping terdokumentasi.
- Jangan menganggap consent sebagai default.
- Jangan menyatakan non-compliance tanpa obligation dan evidence.
- Threat privacy tetap dianalisis untuk data yang legitimate diproses oleh sistem.

Critical fix pada fallback:

- Fallback STRIDE/LINDDUN tidak boleh menghasilkan generic finding yang terlihat seperti temuan sistem aktual.
- Jika AI tidak tersedia, hasil minimum harus berupa coverage, assumption, question, atau candidate yang benar-benar tertaut ke model.

### M7 — Threat traceability, controls, dan stale analysis

Status: **Partial — perlu diperkuat, prioritas P1**

Progress:

- Perubahan semantic DFD hash/revision sekarang menandai dependent analysis stages stale.
- Mapping threat yang tidak terbukti tetap `unmapped`.

Deliverables:

- AI menerima daftar valid model IDs dan mengembalikan refs tersebut.
- Invalid refs ditolak atau diberi status unmapped.
- Selecting threat menyorot semua affected node, flow, boundary, dan data object.
- Existing control dipisahkan dari recommended control.
- Control memiliki `locationRef`, implementation status, dan verification evidence refs.
- Threat memiliki `analyzedRevision` dan `analysisRevision`.
- Semantic model edit menandai analysis stale.
- Layout-only edit tidak menandai stale.
- Rerun tidak menghapus human review, evidence, atau accepted decisions.

### M8 — Persistence, authorization, export, dan failure states

Status: **Belum selesai — prioritas P0/P1**

Deliverables:

- Project/workspace authorization pada semua read/write/export/analyze operation.
- User tidak dapat mengakses project lain hanya dengan mengetahui ID.
- Tambahkan revision conflict handling/optimistic concurrency.
- Pisahkan model lama dari failed/partial regeneration.
- Sediakan job/progress/cancellation bila analysis berjalan lama.
- Tampilkan extraction-failed, partial-model, unsaved, saved, stale, dan retry state.
- Export JSON round-trip yang mempertahankan semantic refs dan metadata.
- Export SVG atau PNG yang tidak memotong boundary/label.
- Enforce `local_only`, redaction policy, resource limits, dan provider URL allowlist.

### M9 — Fixture dan verifikasi acceptance criteria

Status: **Sebagian selesai — prioritas P1/P2**

Progress:

- Test suite bertambah dari 24 menjadi 27 Python tests.
- Test baru mencakup canonical model typed refs, graph invalidity, zone cycle, dan multi-boundary threat mapping.
- Synthetic customer-registration fixture lengkap dan acceptance coverage AC01–AC20 masih belum selesai.

Fixture synthetic customer registration:

- `E1 Customer`
- `P1 Memproses registrasi`
- `P2 Menyiapkan notifikasi`
- `D1 Data customer`
- `E2 Layanan email`
- `F1` sampai `F6` sesuai dokumen
- Application zone dan restricted-data zone di bawah organization ownership group
- Same-zone `F4`
- Vendor crossing `F5/F6`
- Vendor retention tetap unknown dan menghasilkan question
- Postman-only fixture tidak boleh mengklaim database/topology internal

Acceptance test groups:

- AC01–AC02: generation, persistence, Postman-only grounding.
- AC03–AC08: input/process/output, request-response, classification, nested/logical boundary, same-zone analysis.
- AC09–AC12: unknown/conflict, reload/edit, regenerate diff, feature decomposition.
- AC13–AC15: threat traceability, stale analysis, graph integrity.
- AC16–AC19: access isolation, untrusted document, import/export, failure/retry.
- AC20: visual usability, selection, collapse, inventory, keyboard navigation.

## Current acceptance status

| Area | Status sekarang |
|---|---|
| Artifact ingestion dan basic evidence | Partial / cukup baik |
| Postman nested/inherited auth | Partial / sudah ada |
| Canonical semantic DFD | Belum ada |
| Stable typed node/flow model | Belum ada |
| Ownership/scope/exposure separation | Belum ada |
| Nested and logical boundary | Belum ada |
| Same-zone analysis | Belum terpenuhi |
| Threat traceability | Partial, ada bug multi-boundary |
| STRIDE coverage model | Belum ada |
| LINDDUN PRO-aligned model | Belum ada |
| Editable DFD dan layout persistence | Belum ada |
| Regenerate diff/revision conflict | Belum ada |
| JSON round-trip/SVG export | Belum ada |
| Authentication/project isolation | Belum ada |
| Synthetic DFD fixture | Belum ada |
| Automated verification sesuai AC01–AC20 | Belum lengkap |

## Prioritas implementasi

1. **P0:** M1 canonical model dan M2 graph validator.
2. **P0:** M3 boundary/crossing semantics dan perbaikan threat mapping.
3. **P0:** M6 graph-driven threat adapter dengan validated output.
4. **P0/P1:** M8 authorization, redaction, revision, dan failure safety.
5. **P1:** M4 evidence/assertion/question pipeline.
6. **P1:** M5 editable views, inspector, inventory, layout persistence, dan regenerate diff.
7. **P1:** M7 threat traceability, controls, dan stale analysis.
8. **P1/P2:** M9 fixture, export/import, visual QA, dan acceptance tests.

## Change log

- 2026-09-19: Created branch `codex/dfd-threat-model-alignment` for rollback-safe enhanced/revamp work.
- 2026-09-19: Added canonical DFD contract, deterministic model adapter, graph validator, DFD persistence in analysis report, DFD context in STRIDE/LINDDUN prompts, semantic stale detection, and multi-boundary threat mapping regression fix.
- 2026-09-19: Verification: 27 Python unit tests and JavaScript analysis visibility regression passed.

## Progress rule

Setiap milestone hanya boleh ditandai selesai bila:

- deliverables implementasinya tersedia;
- unit/integration test terkait lulus;
- tidak ada fallback/mock yang disamarkan sebagai hasil produksi;
- acceptance criteria terkait sudah diverifikasi;
- limitation yang masih ada tercatat di file ini.
