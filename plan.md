# Alignment Plan — DFD dan Threat Analysis

## Baseline

- Acuan: `DFD_Feature_AI_Agent_Prompt.md`
- Status project saat ini: **grounded threat-modeling MVP dengan DFD visualization**.
- Target akhir: **semantic DFD modeling feature** yang menjadi source of truth untuk canvas, inventory, export, STRIDE, dan LINDDUN.
- Test baseline saat analisis dibuat: 24 test Python lulus dan 1 regression test JavaScript lulus.
- Branch enhanced/revamp: `codex/dfd-threat-model-alignment`.
- Checkpoint fondasi: `77db35f Add canonical DFD semantic model foundation`.

## Goal

Align project dengan dokumen acuan, dengan fokus pada:

1. Canonical semantic DFD yang tervalidasi dan tersimpan.
2. Trust zone, ownership, scope, exposure, logical boundary, dan crossing yang benar.
3. Evidence, assertion, unknown, conflicting information, question, dan revision lifecycle.
4. STRIDE/LINDDUN yang menganalisis model DFD yang sama dan memiliki traceability ke node/flow/boundary/data.
5. UI DFD yang editable, dapat direview, disimpan, diekspor, dan dapat ditelusuri ke threat.
6. Isolation, redaction, schema validation, dan proteksi untrusted document.

## Gap analysis terhadap `DFD_Feature_AI_Agent_Prompt.md`

Temuan ini membedakan fondasi yang sudah diimplementasikan dari alignment yang masih
belum cukup untuk menyatakan fitur DFD/threat analysis selesai.

| Area acuan | Kondisi saat ini | Gap yang perlu ditutup | Prioritas |
|---|---|---|---|
| Canonical DFD sebagai source of truth | Model typed, revisioned, persisted, dan dipakai oleh canvas/prompt | Hasil import masih banyak `unknown`/`inferred`; perlu workflow resolve/approve metadata sebelum confidence tinggi | P0 |
| Graph semantics | Dangling/duplicate/cycle, request-response, data labels, feature ports, crossing metadata, dan duplicate display IDs divalidasi | Rule domain untuk beberapa kombinasi store/process masih reviewable warning; mutation integration test belum lengkap | P0 |
| Trust zone dan boundary | Ancestor crossing, logical reviewer crossing, common-ancestor guard, unresolved membership, zone/boundary inspector, add/remove UI, dan question resolution tersedia | Pemodelan boundary logical/identity/tenant dan evidence-backed review belum lengkap di seluruh workflow | P0 |
| Data privacy/lifecycle | Data-object privacy assertions/questions dan store lifecycle unknowns sudah dibuat | Belum ada resolusi metadata privacy, retention, deletion, backup, recipient, dan legal-basis yang terintegrasi ke threat decision | P1 |
| Evidence dan provenance | Evidence catalog, redaction, assertion status, evidence validation, conflict/question records tersedia | Pipeline review/resolution dan sumber evidence pada setiap edit belum menjadi workflow UI lengkap | P1 |
| STRIDE/LINDDUN | Prompt menerima canonical snapshot; output/taxonomy/refs/coverage/revision divalidasi; deterministic graph coverage melengkapi pasangan element/category; fallback ditandai candidate-only | Demo masih memiliki banyak metadata unknown/inferred; accepted finding/control lifecycle dan engine-backed coverage review belum lengkap | P0/P1 |
| Threat traceability | Threat dapat menarget typed node/flow/boundary/data object dan tombol focus membuka elemen DFD | Highlight lintas semua projection dan controls typed ke location/evidence masih perlu ditutup | P1 |
| Revision/staleness | Semantic vs layout revision, stale marking, conflict, proposal diff/apply tersedia | Dismiss/partial review proposal, rerun job state, cancellation, dan recovery failure belum tersedia | P1 |
| Safety/isolation | Redaction, schema checks, dan configurable workspace guard tersedia | Production IdP/JWT integration, provider URL allowlist, `local_only`, resource limits, serta failure/partial-model state belum ada | P0/P1 |
| Export/import/reviewability | JSON schema-validated round-trip, SVG export, inventory, accessible text alternative, dan UI delete impact preview tersedia | Visual QA boundary/label clipping dan full destructive-flow integration test belum lengkap | P1 |

Bukti Playwright pada project demo (`11c22c23-7517-4fd5-944a-a38f53cd7768`): Context,
System DFD, Feature DFD, inventory, canonical add-element form, node inspector, dan
tombol `Focus affected DFD elements` berhasil dirender; request API project/report/DFD
merespons 200; console smoke-test terbaru tidak memiliki error/warning. Bukti ini
memverifikasi jalur UI utama, bukan completion seluruh acceptance criteria.

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

- Dokumentasi arsitektur target dan migration strategy.
- Full end-to-end baseline terhadap semua acceptance criteria.

Referensi utama: `backend/services/trust_boundary_service.py`, `backend/services/posture_service.py`, `frontend/analysis.html`, `frontend/js/analysis.js`.

### M1 — Canonical semantic DFD model

Status: **Sebagian selesai — prioritas P0**

Progress pada branch `codex/dfd-threat-model-alignment`:

- `backend/models/dfd.py` menambahkan canonical typed DFD contract.
- `backend/services/dfd_model_service.py` menambahkan deterministic adapter dan semantic hash/revision.
- Analysis report menyimpan `dfd_model` dan `dfd_validation`.
- Model DFD menjadi input prompt STRIDE/LINDDUN dan membawa revision/hash untuk stale detection.
- Endpoint `GET/PUT /api/projects/{project_id}/dfd` menyimpan model canonical dengan schema validation dan optimistic revision check.
- Model memiliki `layout_revision` terpisah dari semantic `revision`.
- Model evidence, per-attribute unknown assertions, process metadata, store metadata, dan feature projections tersimpan.
- Evidence refs pada canonical elements sekarang harus resolve ke `model.evidence`; source/manual/flow refs tetap dipertahankan sebagai evidence envelope.

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
- Crossing metadata, projection mappings, store readers/writers, data labels, and question refs ikut divalidasi.
- OpenAPI/Postman operation metadata menghasilkan flow request/response terpisah bila response fields tersedia.
- Flow tanpa process/data label tetap tersimpan sebagai review warning; tidak dibuatkan process fiktif.
- Feature view menyimpan dan memvalidasi input/output flow port mappings terhadap parent process.

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
- Crossing dihitung dari membership node dan ancestor zone dengan guard agar common ancestor tidak dihitung sebagai crossing.
- Logical reviewer crossing dapat dipertahankan pada same-zone flow; membership unknown menghasilkan `crossing_status=unresolved`.
- Synthetic customer-registration fixture mencakup nested organization/application/restricted-data zones serta vendor reverse flow.

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
- Redaction secret diterapkan pada structured parser, generic AI parser, dan evidence/use-case verification.
- Fallback parser juga memakai konten redacted ketika provider AI gagal.
- Canonical model mengubah evidence catalog menjadi `DfdEvidenceRef` dengan document revision/hash dan redacted excerpt.
- Confident fact tidak dipromosikan dari unknown classification; unknown lifecycle fields menghasilkan questions/assertions.
- Unknown privacy metadata pada data object juga menghasilkan assertions/questions untuk kebutuhan LINDDUN.

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

Status: **Partial — prioritas P1**

Progress:

- Canonical context/system views dan per-process feature projections tersedia di model.
- Context canvas memilih canonical DFD sebagai source of truth ketika model tersedia.
- Flow request/response ditampilkan sebagai edge terpisah dengan data label, interaction kind, crossing, evidence, dan unknown status.
- Canonical SVG export tersedia dan sudah diuji terhadap escaping.
- Canonical DFD inventory dapat dinavigasi dari canvas, dan inspector dapat mengedit metadata node/flow melalui revision-safe API.
- Drag pada canonical context menyimpan posisi sebagai layout-only revision.
- Toolbar canonical DFD menyediakan undo/redo history untuk semantic maupun layout snapshot.
- Level UI canonical memisahkan Context, System DFD, dan Feature DFD dengan pemilihan parent process.
- Regeneration proposal memiliki candidate model yang dapat diterapkan eksplisit tanpa menghapus layout manual.
- Canonical DFD JSON export/import telah ditambahkan melalui schema validation dan optimistic revision check.
- Inventory sekarang mencakup zone; boundary inspector dapat mengubah status, tipe,
  transition scope, dan rationale; zone inspector dapat mengubah parent dan trust assumptions.
- Backend `impact-preview` menghitung dependent node/flow/view/boundary/zone/question/threat
  sebelum deletion, dan UI delete menampilkan konfirmasi dependency sebelum mutasi.

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

Catatan status: add/edit/remove UI sudah tersedia dan backend tetap menjadi gate schema,
graph integrity, revision, dan stale analysis. Automated UI mutation test masih perlu diperkuat.

Implementasi tambahan pada checkpoint terbaru:

- Source change saat human-edited DFD masih aktif dipertahankan sebagai model utama.
- Regenerate menghasilkan `dfd_proposal` berisi diff per section dan downstream analysis tetap stale sampai proposal direview.

Definition of done:

- Drag node tidak mengubah semantic membership secara diam-diam.
- Reload memulihkan model dan layout.
- Perubahan layout saja tidak membuat threat analysis stale.

### M6 — Graph-driven STRIDE dan LINDDUN

Status: **Partial tetapi belum aligned — prioritas P0/P1**

Progress:

- Prompt STRIDE/LINDDUN sekarang menerima canonical DFD node, data object, flow, boundary, revision, dan open questions.
- Prompt meminta affected refs berbasis stable DFD IDs serta coverage terpisah.
- Output candidate divalidasi terhadap taxonomy dan current DFD IDs; dangling refs dihapus dengan warning.
- Coverage AI disimpan terpisah pada `analysis_coverage` setelah validasi.
- Deterministic graph coverage melengkapi setiap canonical element/category pair yang belum
  dikembalikan engine sebagai `insufficient_information`; target threat tervalidasi menjadi
  `candidate_identified` tanpa membuat finding baru.
- Taxonomy LINDDUN canonical digunakan untuk output baru dengan alias legacy untuk kompatibilitas report lama.
- Fallback sekarang menghasilkan satu candidate yang `Needs Info`, `candidate_only`, dan tertaut ke flow DFD pertama bila tersedia.
- Validasi AI menolak shape list yang salah, memfilter evidence/DFD IDs dangling, menambahkan title/scenario/controls/mitigations, serta menandai `analyzed_revision`.
- Non-compliance tanpa obligation dan evidence diturunkan menjadi `needs_context`/`Needs Info`, bukan confirmed legal violation.

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
- `affected_refs` dari AI dipetakan langsung ke typed semantic `target_refs` sebelum heuristic matching.
- Control fallback mengenali alias legacy LINDDUN untuk taxonomy canonical.
- Threat target langsung dari canonical IDs dipakai untuk highlight flow/node tanpa fan-out heuristic.
- Threat card menyediakan aksi `Focus affected DFD elements` yang memilih target canonical
  dan membuka inspector pada node/flow yang relevan.

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

Catatan status: target focus dan process/question/data-object review sudah diverifikasi
melalui Playwright pada demo report; controls typed ke location/evidence dan full projection
coverage masih perlu ditutup.

### M8 — Persistence, authorization, export, dan failure states

Status: **Partial — prioritas P0/P1**

Progress:

- Canonical DFD persistence endpoint, optimistic revision conflict, semantic stale marking, dan SVG export tersedia.
- UI memiliki tombol export SVG canonical.
- JSON export/import canonical dengan schema version dan optimistic revision check tersedia.
- Configurable workspace access guard melindungi list/create/read/write/export/analyze/artifact/DFD
  routes saat `WORKSPACE_AUTH_REQUIRED=true`; cross-workspace project disamarkan sebagai 404.
- Frontend meneruskan workspace ID dan bearer token dari `sessionStorage` bila deployment
  mengaktifkan guard.

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

Catatan authorization: guard ini adalah adapter token-per-workspace untuk MVP, bukan
identity provider/JWT production. Workspace project lama tanpa `workspace_id` tidak dapat
diakses ketika mode strict diaktifkan sampai dimigrasikan.

### M9 — Fixture dan verifikasi acceptance criteria

Status: **Sebagian selesai — prioritas P1/P2**

Progress:

- Test suite bertambah dari 24 menjadi 56 Python tests.
- Test baru mencakup canonical model typed refs, graph invalidity, zone cycle, multi-boundary threat mapping, request/response, fixture crossing, DFD persistence, SVG escaping, threat schema validation, dan redaction.
- Synthetic customer-registration source/model fixture tersedia; full acceptance coverage AC01–AC20 masih belum selesai.

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
| Canonical semantic DFD | Partial: contract, adapter, persistence, evidence/assertions, hash/revision, validator, editable graph; import demo masih banyak unknown/inferred |
| Stable typed node/flow model | Partial: typed node/flow/data/boundary refs, request/response, feature projections/port lint, add/edit/remove editor; automated mutation coverage belum lengkap |
| Ownership/scope/exposure separation | Partial: independent fields, unknown questions, semantic crossing, reviewer/editor resolution; evidence-backed classification masih incomplete |
| Nested and logical boundary | Partial: ancestor crossing, common-parent guard, logical reviewer crossing, zone/boundary editor, add/remove, dan question resolution; full logical boundary workflow belum ada |
| Same-zone analysis | Partial: same-zone flows retained and analyzed; full UI coverage belum ada |
| Threat traceability | Partial: explicit DFD refs, unmapped state, cross-boundary fan-out fixed, threat-to-DFD focus action |
| STRIDE coverage model | Partial: prompt, validated output, deterministic element/category coverage, revision tracking; engine-backed coverage masih reviewable |
| LINDDUN PRO-aligned model | Partial: canonical labels/aliases, sender-flow-receiver prompt, non-compliance guard; lifecycle metadata analysis belum lengkap |
| Editable DFD dan layout persistence | Partial: add/edit/remove node/flow/data/zone/boundary, inventory, I-P-O/store inspector, layout persistence, undo/redo, impact preview; automated UI mutation test belum ada |
| Regenerate diff/revision conflict | Partial: revision conflict, candidate proposal, dan explicit apply sudah ada; dismiss/section review UI belum ada |
| JSON round-trip/SVG export | Partial: schema-validated JSON import/export dan SVG export; visual QA boundary/label belum lengkap |
| Authentication/project isolation | Partial: configurable token-per-workspace guard + cross-workspace resource check; IdP/JWT production integration belum ada |
| Synthetic DFD fixture | Partial: customer-registration source/model tersedia; Postman-only fixture inline test |
| Automated verification sesuai AC01–AC20 | Partial: 56 Python tests + JS regression + Playwright UI smoke-test + access-control helper tests; end-to-end/UI/failure criteria belum lengkap |

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
- 2026-09-19: Added secret redaction, AI threat/coverage validation, canonical LINDDUN labels with legacy aliases, direct `affected_refs` mapping, and reviewable DFD-tied fallbacks.
- 2026-09-19: Added semantic ancestor/logical crossing calculation, request/response graph flows, evidence/assertion/lifecycle metadata, canonical DFD persistence API, revision conflict handling, canonical context canvas projection, and escaped SVG export.
- 2026-09-19: Added human-edited DFD preservation, regeneration proposal diff, and pending-proposal stale guard.
- 2026-09-19: Added explicit proposal apply endpoint/UI, canonical DFD inventory, node/flow metadata editor, layout persistence hook, feature port mapping lint, evidence reference validation, privacy metadata questions, and schema-validated JSON DFD import/export.
- 2026-09-19: Added DFD proposal section selection, canonical Context/System/Feature level rendering, feature process selector, and undo/redo history.
- 2026-09-19: Added zone/boundary metadata editors, backend deletion impact preview, and threat-card focus navigation to canonical DFD targets.
- 2026-09-19: Added deterministic graph coverage completion, process I-P-O/store/data-object inspectors, question resolution, canonical add/remove UI, and duplicate display/reference validation.
- 2026-09-19: Added configurable workspace authorization guard, cross-workspace resource isolation, frontend workspace headers, and access-control regression tests.
- 2026-09-19: Verification: 56 Python unit tests, JavaScript analysis visibility regression, JS syntax checks, Python compilation, diff whitespace checks, and Playwright UI smoke-test passed; favicon route returns 200.

## Progress rule

Setiap milestone hanya boleh ditandai selesai bila:

- deliverables implementasinya tersedia;
- unit/integration test terkait lulus;
- tidak ada fallback/mock yang disamarkan sebagai hasil produksi;
- acceptance criteria terkait sudah diverifikasi;
- limitation yang masih ada tercatat di file ini.
