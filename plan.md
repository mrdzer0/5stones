# Alignment Plan — DFD dan Threat Analysis

## Baseline

- Acuan: `DFD_Feature_AI_Agent_Prompt.md`
- Status project saat ini: **grounded threat-modeling MVP dengan DFD visualization**.
- Target akhir: **semantic DFD modeling feature** yang menjadi source of truth untuk canvas, inventory, export, STRIDE, dan LINDDUN.
- Verifikasi branch saat ini: 129 test Python lulus setelah remediation F07, 1 regression test JavaScript lulus, syntax/diff checks lulus, dan Playwright smoke-test UI/API lulus.
- Branch enhanced/revamp: `codex/dfd-threat-model-alignment`.
- Checkpoint fondasi: `77db35f Add canonical DFD semantic model foundation`.
- Audit core terbaru: **2026-09-19**, terhadap commit `d6b8111` dan report demo revision 5. Gunakan bagian **Audit core function dan optimasi** serta milestone **C0–C6** sebagai urutan pekerjaan berikutnya; M0–M9 tetap menjadi peta alignment historis.

## Goal

Align project dengan dokumen acuan, dengan fokus pada:

1. Canonical semantic DFD yang tervalidasi dan tersimpan.
2. Trust zone, ownership, scope, exposure, logical boundary, dan crossing yang benar.
3. Evidence, assertion, unknown, conflicting information, question, dan revision lifecycle.
4. STRIDE/LINDDUN yang menganalisis model DFD yang sama dan memiliki traceability ke node/flow/boundary/data.
5. UI DFD yang editable, dapat direview, disimpan, diekspor, dan dapat ditelusuri ke threat.
6. Isolation, redaction, schema validation, dan proteksi untrusted document.

## Audit core function dan optimasi — 2026-09-19

### Kesimpulan dan batas penilaian

Project **sebagian selaras dengan praktik threat modeling, tetapi belum konsisten untuk handoff end-to-end ke Developer/QA**. DFD canonical, evidence, taxonomy, dan review lifecycle merupakan fondasi yang dapat dipakai untuk assisted review. Kelemahan utama ada pada kualitas input analisis, konsistensi revisi, applicability rekomendasi kontrol, serta kelengkapan dan pembuktian hasil test.

Tidak ada satu standar threat modeling universal yang menjadikan pemakaian label STRIDE/LINDDUN sebagai sertifikasi. Audit memakai empat tahap OWASP—modeling, identifikasi/prioritisasi ancaman, mitigasi, review/validasi—sebagai pembanding proses; Microsoft untuk STRIDE; LINDDUN PRO untuk privacy; ASVS/WSTG untuk kebutuhan kontrol dan pengujian. Schema DFD dan AC01–AC20 di dokumen project adalah kontrak produk, bukan schema wajib resmi framework. [OWASP Threat Modeling](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)

Scope sesi ini adalah inspeksi kode, report tersimpan, pemeriksaan UI dengan Playwright, reproduksi helper di memori, dan pembaruan plan. Tidak menjalankan ulang provider berbayar, mengganti data report, menjalankan security test terhadap target, atau mengimplementasikan perbaikan runtime.

### Referensi metode dan penerapannya

| Referensi resmi | Yang dipakai dalam audit / target implementasi |
|---|---|
| [Microsoft STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) | Enam kategori ancaman untuk menyusun skenario spesifik; kategori bukan bukti vulnerability atau skor severity. |
| [LINDDUN PRO](https://linddun.org/pro/) | Evaluasi interaksi sender–transfer–receiver secara sistematis, memakai applicability mapping dan threat trees; daftar tujuh kategori saja belum cukup. |
| [LINDDUN threat types](https://linddun.org/threat-types/) | Privacy mencakup pemrosesan sah, linking/inference, attribution, data berlebih, dan kemampuan individu mengendalikan data. Pisahkan dampak individu dari dampak sistem. |
| [OWASP ASVS](https://owasp.org/projects/asvs) | Referensi requirement kontrol aplikasi; versi stabil yang diperiksa: **5.0.0**. Simpan version + requirement ID + URL bila applicability terbukti. |
| [OWASP WSTG](https://owasp.org/projects/web-security-testing-guide) | Referensi prosedur pengujian web; versi stabil yang diperiksa: **4.2**, sedangkan 5.0 masih pengembangan. Mapping hanya untuk test yang relevan; privacy lifecycle memerlukan skenario tambahan. |

Mapping ke ASVS/WSTG adalah pilihan desain untuk traceability dan handoff, bukan syarat resmi agar analisis boleh disebut STRIDE atau LINDDUN. Versi internal `stride-v1`/`linddun-v1` saat ini perlu disertai sumber taxonomy/mapping yang dipin; jangan dipresentasikan sebagai versi publikasi resmi.

### Bukti kondisi saat audit

Report sampel: `11c22c23-7517-4fd5-944a-a38f53cd7768`, `generated_at=2026-09-19T14:15:06.784063`, canonical revision **5**. Angka berikut adalah snapshot satu project, bukan benchmark semua project.

| Data / proses | Hasil pemeriksaan |
|---|---|
| DFD | 20 nodes, 14 data objects, 8 flows, 4 zones, 2 boundaries. `valid=true`, `semantic_ready=false`; 13 node tanpa flow dan zone Customer terisolasi. |
| STRIDE / LINDDUN | 19 STRIDE + 3 LINDDUN tersimpan; 14 threat tanpa `analyzed_revision`, termasuk satu STRIDE tanpa `threat_category`. Hasil lama dan baru bercampur. |
| Coverage STRIDE | 264 pasangan element/category: 43 candidate, 0 reviewed-no-candidate, 221 insufficient-information. |
| Coverage LINDDUN | 308 pasangan: 27 candidate, 1 reviewed-no-candidate, 280 insufficient-information. Ini matriks internal aplikasi, bukan bukti seluruh interaksi PRO sudah diperiksa. |
| Controls | Retry terbaru **sukses AI**, menghasilkan 12 controls. Sebanyak 11 berstatus `Missing` dan semuanya tanpa `verification_evidence_refs`; status ini belum membuktikan absence runtime. Error JSON sebelumnya bersifat intermittent, tidak lagi status controls terbaru. |
| Tests | Masih fallback karena `KeyError: threat_category`; 10 test seluruhnya mengarah ke STRIDE, tidak ada test untuk tiga LINDDUN dalam snapshot. |
| Review | DFD proposal 35 perubahan masih pending; seluruh downstream stage masih stale. Readiness context 75/100 bukan ukuran completeness graph atau mutu hasil analisis. |
| Verifikasi repository | 82 Python tests + regression JavaScript lulus ulang. Acceptance pipeline yang ada men-stub controls/tests menjadi list kosong; kelulusan suite belum membuktikan kualitas kedua generator tersebut. |
| Playwright | Diagram, coverage/partial/stale banners, Controls, Tests, dan expand scenario dapat diakses; 0 console error. Desktop 1440×900 dan Controls/Tests 390×844 setelah resize stabil tidak overflow halaman. Overflow awal 534 px bersifat sementara saat transisi, bukan defect persistent yang terkonfirmasi. |

### Gap prioritas berdasarkan kode dan perilaku

| ID / prioritas | Temuan dan dampak | Bukti utama / hasil yang diperlukan |
|---|---|---|
| F01 · P0 | Threat legacy tidak divalidasi sebelum downstream. STRIDE menghapus hanya fallback lama, sementara LINDDUN menghapus semua hasil framework sebelum merge: malformed/stale STRIDE bisa bertahan, review LINDDUN berisiko hilang. | **Remediasi selesai pada sesi ini.** [analysis.py](backend/routers/analysis.py) melakukan quarantine sebelum stage downstream; validator menolak missing/duplicate ID, unsupported category/taxonomy/status, malformed/dangling refs, missing/mismatched revision, dan menyimpan alasan audit. Reconcile per framework mempertahankan snapshot lama saat fallback/partial dan mempertahankan keputusan reviewer saat finding tidak muncul pada rerun valid. Regression malformed STRIDE + reviewed LINDDUN lulus. |
| F02 · P0 | Generator STRIDE/LINDDUN menolak `threats=[]` walaupun coverage bisa valid reviewed-no-candidate. Status AI sudah `ok=true` sebelum validasi candidate, sehingga semua output yang gugur berpotensi tetap tampak sukses. | **Remediasi selesai pada sesi ini.** `valid_empty` dinormalisasi dan tidak memicu fallback; provider contract/structured-response failure menjadi `invalid` dengan quarantine reason; partial/invalid/fallback tetap warning dan tidak clear stale; `ai_status.ok` dihitung setelah normalisasi + validasi. Zero finding tetap bukan proof of safety. |
| F03 · P0 | Konteks DFD yang dikirim ke engine kehilangan atribut inti: flow `data_object_ids`, `protocol`, `authn/authz`, process identity/privilege/transformation, zone membership/assumptions tidak diserialisasi lengkap. Controls menerima ringkasan threat, Tests tidak menerima canonical DFD maupun hasil control mapping. | **Remediasi selesai pada sesi ini.** `format_dfd_analysis_context()` menjadi canonical snapshot bersama untuk STRIDE/LINDDUN/Controls/Tests dan kini memuat semantic hash/provenance, identity/operator/knowledge, process metadata, data fields/lineage, lifecycle, crossings, boundary controls, evidence, dan review questions. Controls menerima threat/evidence/DFD refs; Tests menerima DFD snapshot + mapped controls. Threat/control/test dipin ke revision dan semantic hash yang sama. |
| F04 · P0 | Respons controls hanya diparse sebagai JSON dan dicek nonempty; schema Control/TestScenario belum ditegakkan pada jalur generation. `finish_reason`/usage tidak dicatat dan budget stage hardcoded. Error malformed JSON belum dapat dibedakan dari output terpotong. | **Remediasi selesai pada sesi ini.** [ai_service.py](backend/services/ai_service.py) kini menyimpan model, provider attempts, `finish_reason`, usage, parse status, retry reason, response shape, dan membedakan malformed/non-JSON/truncated output; truncated JSON tidak diterima oleh repair. [generation_contracts.py](backend/services/generation_contracts.py), [control_service.py](backend/services/control_service.py), dan [test_service.py](backend/services/test_service.py) menegakkan envelope, item, enum, foreign key threat/control/DFD/evidence, serta menghasilkan `complete`/`partial`/`fallback` dengan warning. Budget Controls/Tests memakai nilai provider yang dibatasi stage cap. `ai_status` menyimpan metadata dan error code, bukan hanya `ok=true`. |
| F05 · P0 | Fallback controls memakai keyword seluruh threat lalu menghubungkan setiap match ke `threats[:3]`; jika tidak match memilih tiga controls pertama. `_related_threats_by_text()` juga dapat mencocokkan string kosong. Hubungan mitigasi dapat keliru walau ID valid. | **Remediasi selesai pada sesi ini.** [control_service.py](backend/services/control_service.py) sekarang melakukan matching per-threat dengan exact category/alias applicability atau minimal dua keyword bermakna; tidak ada generic first-three fallback. Setiap mapping menyimpan `threat_mappings`, matched signals, score-derived rationale, dan `mapping_basis`. Threat tanpa match mendapat record eksplisit `mapping_status=unassigned`/`no_catalog_applicability_match`. [posture_service.py](backend/services/posture_service.py) menolak empty/substring/one-token inference dan mempertahankan status unassigned saat enrichment. |
| F06 · P0 | Controls dapat membawa `Missing`/`Implemented` dari AI tanpa dasar implementasi terverifikasi. AI prompt tidak mendapat implementation evidence catalog yang memadai. Catalog mencampur consent dengan transparansi dan mapping TLS→Linkability terlalu luas untuk risiko inference saat data sedang diproses. | **Remediasi selesai pada sesi ini.** [control_service.py](backend/services/control_service.py), [posture_service.py](backend/services/posture_service.py), dan [schemas.py](backend/models/schemas.py) memisahkan `implementation_status`, `implementation_state` (`unknown`, `planned`, `documented`, `runtime_verified`), implementation evidence requested/collected, runtime verification refs, verification status, recommendation status, dan review status. Status non-`Unknown` dari AI/API diturunkan ke `Unknown` atau ditolak bila evidence yang sesuai tidak ada; verification-only tidak dianggap implementation proof. [controls_catalog.json](backend/data/controls_catalog.json) sekarang memiliki applicability/evidence requirements/verification method, TLS tidak memitigasi Linkability, dan consent dipisah dari privacy notice/individual control. UI Analysis/Report menampilkan state dan evidence lifecycle. |
| F07 · P0 | Tests memakai indexing wajib yang crash pada legacy record, membatasi input AI ke 15 threat dan fallback ke 10 pertama. Template Spoofing otomatis menjadi webhook; fallback tidak memiliki template canonical LINDDUN lengkap. | **Remediasi selesai pada sesi ini.** [test_service.py](backend/services/test_service.py) memproses seluruh active threat ber-ID tanpa slicing, memperlakukan non-dict/missing category/unsupported category/provider omission sebagai `Blocked` dengan alasan dan menjaga coverage denominator. Normalizer aman terhadap legacy record; AI item/DFD/control/evidence refs tetap tervalidasi. Spoofing memakai identity/authentication scenario umum dan hanya memakai template webhook bila evidence menyebut webhook/callback/HMAC. Fallback memiliki template seluruh tujuh kategori LINDDUN canonical. Applicability terlihat di Analysis, Report, dan Markdown export. |
| F08 · P0 | Staleness di-clear berdasarkan stage yang diminta, bukan hanya hasil current-revision yang sukses dan tervalidasi. Full analysis UI membuat request terpisah per stage sehingga tidak ada immutable run snapshot bersama; API multi-stage memberi semua stage durasi total yang sama. | [analysis.py](backend/routers/analysis.py), `runAnalysis()` di [analysis.js](frontend/js/analysis.js). Run manifest berisi model/source revision, stage dependencies dan state; kegagalan tidak menggantikan verified history atau meng-clear stale; ukur durasi tiap stage. |
| F09 · P1 | `semantic_ready` hanya merangkum subset topology issues. Model kosong direproduksi `valid=true, semantic_ready=true`; warning flow tanpa process/data label dan unresolved crossing tidak semuanya memengaruhi readiness. Detector zone memakai membership langsung sehingga parent container dapat mendapat false-positive isolation. | `validate_dfd_model()` di [dfd_model_service.py](backend/services/dfd_model_service.py). Pisahkan structural validity, topology coverage, knowledge completeness, dan reviewer acceptance; draft kosong boleh disimpan tetapi belum analysis-ready. Gunakan ancestor dan scope untuk menentukan connectivity yang relevan. |
| F10 · P1 | DFD generation masih memakai heuristic type→zone dan label seperti `Internal Trusted` / `Sensitive Internal Store`. Seluruh external system bisa digabung satu zone meskipun control party berbeda. Alias helper belum mempertimbangkan environment/tenant sebagai bagian identitas. | `_entity_zone()`, `_same_entity_name()` di [trust_boundary_service.py](backend/services/trust_boundary_service.py). Jadikan grouping inferred/reviewable, gunakan evidence identitas/ownership/control party untuk split/merge; semantic boundary bukan otomatis ownership group. |
| F11 · P1 | Coverage semua element×category tidak mempunyai applicability/not-applicable rationale atau manifest interaksi PRO. Non-compliance guard hanya menurunkan status bila obligation **dan** evidence sama-sama kosong. Salah satu kosong lolos—terkonfirmasi via helper. LINDDUN juga default `data_classification=PII` ketika field dihilangkan engine. | [threat_validation_service.py](backend/services/threat_validation_service.py), [linddun_service.py](backend/services/linddun_service.py). Validasi kedua kebutuhan secara terpisah, pertahankan classification unknown, dan simpan interaction/mapping/threat-type refs. Classification/security/privacy tidak boleh dipromosikan menjadi fakta dari default. |
| F12 · P1 | Risk summary menjumlah label AI tanpa likelihood/impact rationale atau residual-risk method; review preservation untuk controls/tests belum konsisten saat regenerate karena replacement list dan UUID baru. | [analysis.py](backend/routers/analysis.py), [posture_service.py](backend/services/posture_service.py). Risk rubric yang terdokumentasi, owner/decision/rationale dan stable control/test identity. Jangan menyamakan confidence, completeness, atau jumlah finding dengan risiko. |
| F13 · P1 | Catalog 15 controls tidak memiliki versioned standard references. Test menyimpan `related_control` sebagai teks, belum control IDs, execution status, actual result, environment/build atau verification evidence. UI Tests tidak menampilkan `evidence_needed`, link DFD/threat, atau aksi hasil eksekusi; header accordion berupa `div onclick` tanpa keyboard semantics. Markdown export hanya ringkasan test. | [schemas.py](backend/models/schemas.py), [controls_catalog.json](backend/data/controls_catalog.json), `renderControls()/renderTests()` di [analysis.js](frontend/js/analysis.js), [export.py](backend/routers/export.py). Handoff perlu traceability, acceptance criteria, status dan evidence; UI harus membedakan recommendation/review/implementation/execution. |

### Optimasi data dan processing yang disarankan

Urutan target: **ingest/version → normalize/evidence → validate/review DFD → freeze analysis snapshot → STRIDE & LINDDUN → reconcile findings → controls → verification plan → review/execution evidence**. Model parsial tetap dapat dianalisis, tetapi scope, omitted context, asumsi, dan coverage yang belum diperiksa harus terlihat.

| Lapisan | Kondisi sekarang | Optimasi dan kriteria keberhasilan |
|---|---|---|
| Ingestion dokumen | Generic AI parser hanya membaca `safe_content[:8000]`, meminta maksimum 12 evidence items. Detail akhir dokumen berisiko tidak ikut diekstrak. | Chunk berdasarkan section/locator dengan coverage manifest, dedupe evidence berdasarkan source revision/hash; tampilkan bagian yang belum dibaca. Fixture penting setelah karakter ke-8000 harus terambil atau eksplisit deferred. |
| Evidence/context | Prompt evidence mengambil 28 item pertama; canonical evidence mengikutkan 96 item catalog pertama sebelum handling refs tambahan. DFD prompt memasukkan semua questions, termasuk yang sudah resolved. | Index evidence per element/interaction, retrieve yang relevan untuk setiap batch, laporkan truncation/omission, simpan full evidence di model. Resolved questions diringkas tanpa menghilangkan keputusan reviewer. |
| Analysis contract | Serializer tekstual kehilangan semantics penting; tiap stage membangun context sendiri. | Typed `AnalysisSnapshot` berisi project/model/source hash, relevant nodes/flows/data/store/assertions/controls, valid IDs, privacy context dan scope. Persist prompt/schema/taxonomy/provider-model versions + result provenance untuk reproduksi. |
| Budget dan structured output | Token hardcoded: STRIDE 4000, LINDDUN 3000, controls 3000, tests 3500; nilai provider `max_tokens` dibaca tetapi tidak dipakai sebagai budget stage ini. | Effective budget di bawah policy cap, hitung perkiraan ukuran dan batch per interaction/threat/control; catat usage, finish reason, validation outcome, retry reason dan latency. Benchmark dahulu sebelum menetapkan target latency/cost. |
| Scheduling | UI serial menjalankan stage dengan POST lalu GET report penuh; catalog/evidence/review enrichment berulang. | Setelah snapshot immutable tersedia, STRIDE dan LINDDUN dapat berjalan paralel terbatas lalu join sebelum controls/tests. Cache context/catalog dalam run; retry hanya stage gagal dan dependent stages yang invalid. Jangan memparalelkan penulisan file report shared saat ini. |
| Incremental update | Semantic hash dan stale flags tersedia, tetapi belum cache per scope analisis. | Cache key minimal workspace/project + model/source/evidence hash + framework/prompt/schema/model version + policy. Invalidasi neighborhood/data lifecycle terkait saat berubah; layout-only tidak memicu AI. Keputusan reviewer tetap diaudit. |
| Graph processing | Validator berulang membuat `set(all_ids)` dan mencari flow/boundary via linear scan; coverage menghasilkan semua pasangan tanpa applicability. | Index node/flow/boundary/ancestor sekali, batch refs, applicability-aware coverage dan pagination inventory. Ukur 50/250/1000 nodes dengan connected/isolated/nested fixtures sebelum optimasi renderer lebih besar. |
| Persistence | JSON project/report cukup untuk MVP; status, model, findings dan hasil stage menulis shared report. | Stage output dan execution evidence diberi revision/run IDs, atomic save dan conflict check. SQLite transactional merupakan opsi tahap awal; perubahan database diputuskan setelah concurrency benchmark, bukan prasyarat audit. |

Tidak ada benchmark p95 latency, token cost, concurrency, atau kualitas lintas banyak project pada sesi ini. Durasi UI 22 detik atau snapshot stage bukan bukti bottleneck spesifik dan tidak dipakai menjanjikan peningkatan persentase.

### Usability dan kemudahan implementasi

Untuk Security/Architect, diagram, inventory, inspector dan unresolved warnings sudah membantu review. Untuk pengguna baru, readiness 75/100, stale proposal, candidate count dan insufficient-information tampil bersamaan tanpa satu langkah berikutnya yang jelas. Untuk Developer/QA, hasil controls/tests masih perlu interpretasi manual sebelum menjadi task yang dapat dikerjakan.

Target alur: **Review model → Review threats → Plan controls → Prepare tests → Record evidence**. Tiap tahap menampilkan satu next action, readiness yang spesifik, dan label draft/AI/fallback/stale/verified. Tampilkan fallback pada item dan export, bukan hanya banner run; jangan menutup draft karena evidence belum lengkap.

Control card perlu menunjukkan: threat/flow yang ditangani, applicability/rationale, lokasi implementasi, prioritas dan owner, requirement reference bila relevan, implementation status terpisah dari review status, serta evidence yang diperlukan. Test card perlu control/threat/DFD links, setup/role/data, langkah, expected/actual result, evidence, serta status not-run/pass/fail/blocked. Semua aksi utama dan accordion harus dapat dipakai via keyboard.

Perubahan validation/legacy handling dapat dibuat pada service yang sudah ada dengan kompleksitas rendah–sedang. Snapshot bersama, stable identities, interaction coverage, serta execution evidence memerlukan migrasi schema dan integrasi beberapa modul (sedang–tinggi). Pertahankan backend/frontend yang ada; tidak perlu mengganti stack untuk menutup gap inti ini. Kemudahan pengguna belum diuji melalui studi pengguna independen atau screen reader; Playwright hanya memverifikasi jalur interaksi/DOM yang diperiksa.

### Milestone core berikutnya — sumber status aktif

Status **Belum selesai** berarti deliverable berikut belum lolos acceptance; fondasi yang sudah ada tidak dihapus dari M0–M9. Urutan kerja C0 → C1 → C2 → C3 → C4, lalu C5/C6; perbaikan kecil UX boleh berjalan setelah kontrak datanya stabil.

| Milestone / prioritas / kompleksitas | Sudah tersedia | Belum selesai / acceptance penutup | Dependensi / pemetaan |
|---|---|---|---|
| C0 — Validated report & recovery · P0 · sedang | New-threat schema, run state, retry dan fallback labels; **F01/F02/F04 quarantine, assessment classification, dan structured control/test contracts selesai** | F08: stale hanya clear untuk hasil valid revisi aktif; durable run snapshot, dependent-stage retry, dan recovery masih perlu ditutup. | Pertama; M6/M7/M8/M9 |
| C1 — DFD semantic input & review · P0/P1 · sedang | Canonical graph, editing, crossing dan proposal; **F03 snapshot propagation selesai** | F09/F10: empty graph tidak ready; nested zone scope-aware; isolated nodes punya resolve/defer reason; alias lintas tenant/vendor tidak salah merge. | C0; M1–M5 |
| C2 — STRIDE/LINDDUN assessment · P1 · sedang–tinggi | Taxonomy, candidate refs, privacy metadata dan coverage | F02/F11/F12: applicable STRIDE checks, PRO interaction manifest + mapping refs, validated no-candidate, guard obligation/evidence lengkap, risk rationale, version pin dan review preservation. | C0/C1; M6/M7 |
| C3 — Evidence-based control recommendation · P0/P1 · sedang | Catalog, ownership/checklist, typed DFD target refs; **F05 per-threat applicability dan explicit unassigned mapping selesai; F06 evidence-backed lifecycle selesai** | F13: stable control IDs, versioned ASVS refs bila relevan, privacy-specific choices dan implementable acceptance criteria. | C0/C1, selaras C2; M7 + perluasan |
| C4 — Actionable verification scenarios · P0/P1 · sedang | Scenario draft, steps/expected result, UI accordion, all-scope threat coverage, explicit applicability status/reason, dan canonical LINDDUN fallback templates | F13: stable control IDs, setup/assertions/evidence, execution status dan revision, WSTG refs bila relevan. Tidak ada default webhook tanpa evidence; execution workflow dan richer handoff masih perlu. | C3; M7/M9 + perluasan |
| C5 — Processing efficiency & observability · P1/P2 · sedang–tinggi | Hash/revision dan beberapa resource caps | Section chunking, evidence retrieval, effective token budget, per-stage usage/latency, server run snapshot, selective retry/cache, concurrency-safe persistence. Benchmarks terukur tanpa penurunan coverage/quality. | Kontrak C0–C4 stabil; M4/M8 |
| C6 — Usability & acceptance release · P1 · sedang | Tabs, inspector, DFD focus, stale/fallback banners, export | Guided next-action, item provenance/status, keyboard accordion, implementation/execution evidence workflow, lengkap export handoff, end-to-end failure/retry/edit/reload serta studi tugas Developer/QA. | C0–C5; M5/M7/M9 |

Checklist pencapaian sesi audit:

- [x] Inspeksi empat core function dan doc DFD; snapshot kondisi existing dicatat.
- [x] Referensi resmi STRIDE, LINDDUN PRO, ASVS dan WSTG diperiksa.
- [x] Regresi existing 126 Python + JavaScript dijalankan; UI inspected dengan Playwright.
- [x] Reproduksi di memori: empty-DFD readiness, wrong fallback control links, dan partial Non-compliance guard.
- [ ] C0–C6 diimplementasikan dan acceptance masing-masing lulus. Audit ini tidak menandai runtime fix sebagai selesai.

### Skenario pengujian yang harus ditambahkan

Tabel ini adalah acceptance backlog untuk **produk threat-modeling**; test yang nantinya dihasilkan untuk aplikasi pengguna harus disesuaikan dengan evidence target, bukan dieksekusi otomatis dari dokumen.

| ID / core | Fixture / trigger | Expected result dan evidence verifikasi |
|---|---|---|
| CT01 · lifecycle | Report legacy mengandung threat tanpa kategori, wrong enum, duplicate IDs atau dangling refs; rerun/retry | Invalid record masuk quarantine dengan alasan dan dapat diaudit; stage lain tidak crash; reviewed findings dan model lama tetap tersedia. |
| CT02 · STRIDE/LINDDUN | JSON valid `threats=[]` dengan coverage no-candidate; lalu kasus semua candidate gagal validasi | Kasus pertama valid assessment; kasus kedua partial/failed yang eksplisit. Tidak dibuat fallback threat hanya untuk mengisi daftar. |
| CT03 · provider | Prose, markdown JSON, truncated JSON, wrong shape, empty content, timeout, rate-limit dan invalid control/test FK | Output typed + refs valid saja dipersist; bounded retry, reason terstruktur, no silent truncation success, previous verified results dipertahankan. |
| CT04 · DFD | Empty graph, same-zone valid flow, isolated actor, nested ownership container, unresolved membership, flow tanpa process/data label | Draft bisa disimpan; readiness sesuai issue; parent container tidak dipaksa punya artificial flow; tidak ada invented store/edge. |
| CT05 · DFD/input | Authn/authz, process identity, privilege, data-object association dan source evidence berbeda pada dua snapshot | Prompt/context yang diuji mengandung perbedaan aktual; graph IDs dan source revision konsisten sampai controls/tests. Layout-only tidak mengubah assessment hash. |
| CT06 · STRIDE | Same-zone authorization transition, tenant crossing, request/response, negative case dengan kontrol evidenced | Setiap applicable check punya assessment/rationale, candidate spesifik dan affected refs; tidak wajib enam finding per node; risk didukung rationale. |
| CT07 · LINDDUN | Data sah namun berlebih, identifier linking, vendor sharing, store retention/deletion, awareness/control individu, audit attribution | Sender–transfer–receiver dan lifecycle diperiksa, impact individu dicatat; mitigasi tidak berhenti pada TLS/authentication. |
| CT08 · LINDDUN evidence | Obligation saja, evidence saja, keduanya, atau tidak keduanya; classification tidak ada | Missing salah satu konteks tidak dipromosikan menjadi supported Non-compliance claim; unknown tidak menjadi PII/consent secara default. |
| CT09 · controls | Threat relevan di posisi ke-4/ke-20; kategori kosong; unrelated webhook; recommended vs implemented control | Mapping tidak bergantung urutan; alasan applicability dan valid links tersedia; Unknown bila implementation evidence tidak memadai; review decision bertahan saat regenerate. |
| CT10 · test coverage | Lebih dari 15 threat, dua framework, threat prioritas tinggi di akhir daftar, controls bersama beberapa threat | Semua threat in-scope memiliki test atau explicit not-applicable/blocked reason. Test→control→threat→DFD dapat ditelusuri; privacy tidak terlewat karena slicing. |
| CT11 · scenario applicability | Spoofing pada UI/API tanpa webhook; retention unknown; data isolation dua user/tenant; legitimate request | Tidak membuat webhook fiktif; retention test blocked jika policy belum diketahui; setup, positive/negative assertion, data cleanup, expected evidence spesifik. Untuk load/rate-limit test, budget dan environment ditetapkan sebelum execution. |
| CT12 · lifecycle/concurrency | Semantic edit saat run, source proposal pending, retry stage gagal, model sama dengan layout berubah | Commit hasil tidak menimpa revision baru; stale tidak clear karena fallback; retry memakai snapshot yang diketahui; hasil lama dan reviewer decision tetap bisa dipulihkan. |
| CT13 · QA handoff | Pilih threat → control → test → catat hasil/evidence → reload/export | Status recommendation/implementation/execution terpisah; test berisi build/environment/actual result; seluruh ID dan evidence links valid; Markdown/JSON menyertakan langkah dan limitation. |
| CT14 · processing | Dokumen dengan detail penting setelah 8000 karakter; >28 evidence; 50/250/1000-node graph | No silent omission; chunk/coverage manifest lengkap; ukur latency, usage, retries, memory dan identical-snapshot consistency. Target p95 ditetapkan setelah baseline, bukan diasumsikan. |
| CT15 · usability/E2E | Project baru dari fixture serta report legacy; desktop/narrow, keyboard navigation, provider failure/retry | Generate → review → edit → analyze → reload → export selesai; next action dan partial/fallback jelas; test accordion dapat dioperasikan keyboard. Studi tugas Dev/QA mencatat waktu, kesalahan dan bantuan yang diperlukan. |

Kriteria release core: CT01–CT13 dan CT15 lulus untuk jalur terkait; CT14 mempunyai baseline dan tidak menunjukkan regression coverage. Setiap active threat memiliki assessment revision dan coverage/mitigation disposition; setiap executable test memiliki setup, expected result dan traceability valid. Jumlah test lulus saja tidak cukup untuk menyatakan seluruh hasil sesuai praktik industri.

## Gap analysis terhadap `DFD_Feature_AI_Agent_Prompt.md`

Bagian berikut mempertahankan peta fondasi M0–M9. Audit core di atas memperinci gap
runtime yang ditemukan setelah checkpoint sebelumnya; bila ada perbedaan status,
gunakan temuan F01–F13 dan acceptance C0–C6 sebagai acuan terbaru.

| Area acuan | Kondisi saat ini | Gap yang perlu ditutup | Prioritas |
|---|---|---|---|
| Canonical DFD sebagai source of truth | Model typed, revisioned, persisted, dan dipakai oleh canvas/prompt | Hasil import masih banyak `unknown`/`inferred`; perlu workflow resolve/approve metadata sebelum confidence tinggi | P0 |
| Graph semantics | Dangling/duplicate/cycle, request-response, data labels, feature ports, crossing metadata, duplicate display IDs, serta isolated zone/node divalidasi | `semantic_ready` masih false pada demo karena Customer dan beberapa komponen/provider belum punya evidenced flow; mutation integration test belum lengkap | P0 |
| Trust zone dan boundary | Alias endpoint dinormalisasi, tipe store/external dari deklarasi diprioritaskan, cross-zone flow serta zone boundary dihasilkan dari evidence; ancestor/logical crossing dan reviewer metadata tersedia | Customer interaction dan provider-level flow yang belum didokumentasikan perlu evidence/review; logical/identity/tenant boundary workflow belum lengkap | P0 |
| Data privacy/lifecycle | Data-object privacy assertions/questions, store lifecycle unknowns, deterministic privacy assessment, LINDDUN context annotation, dan inspector metadata tersedia | Resolusi metadata privacy/lifecycle masih manual dan belum menjadi legal/compliance decision engine; evidence source untuk setiap field masih perlu dilengkapi | P1 |
| Evidence dan provenance | Evidence catalog, redaction, assertion status, evidence validation, conflict/question records, per-attribute assertion refresh, dan evidence-reference editor tersedia | Pipeline review/resolution lintas semua atribut dan UI evidence browser belum lengkap; source edit tetap perlu evidence yang valid | P1 |
| STRIDE/LINDDUN | Prompt menerima canonical snapshot; output/taxonomy/refs/coverage/revision divalidasi; deterministic graph coverage melengkapi pasangan element/category; fallback ditandai candidate-only | Demo masih memiliki banyak metadata unknown/inferred; accepted finding/control lifecycle dan engine-backed coverage review belum lengkap | P0/P1 |
| Threat traceability | Threat dapat menarget typed node/flow/boundary/data object, tombol focus membuka elemen DFD, dan controls membawa `location_ref`/`target_refs` | Highlight lintas semua projection dan control verification evidence workflow masih perlu ditutup | P1 |
| Revision/staleness | Semantic vs layout revision, stale marking, conflict, proposal diff/apply/dismiss, section review, persisted run state, dan retry endpoint tersedia | Cancellation/job progress server-side, durable proposal audit/recovery lintas process, dan richer partial-review audit masih belum tersedia | P1 |
| Safety/isolation | Redaction, schema checks, configurable workspace guard, provider URL allowlist, `local_only`, token/timeout/retry limits, dan safe failure state tersedia | Production IdP/JWT integration, outbound resource quotas, serta full untrusted-document integration test belum ada | P0/P1 |
| Export/import/reviewability | JSON schema-validated round-trip, SVG export, inventory, accessible text alternative, dan UI delete impact preview tersedia | Visual QA boundary/label clipping dan full destructive-flow integration test belum lengkap | P1 |

Bukti Playwright pada project demo (`11c22c23-7517-4fd5-944a-a38f53cd7768`): Context,
System DFD, Feature DFD, inventory, canonical add-element form, data-object inspector
dengan privacy fields dan evidence references, tombol `Focus affected DFD elements`,
serta proposal apply/dismiss berhasil dirender; request API project/report/DFD merespons
200 dan `privacy_assessment` tersedia dengan status `unknown` serta unresolved metadata.
Console smoke-test terbaru tidak memiliki error/warning. Bukti ini
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

Status: **Selesai untuk core contract/persistence — prioritas P0**. Semantic completeness,
boundary classification, dan input extraction tetap dilacak oleh M2–M4/C1; status M1
tidak berarti setiap project otomatis memiliki topology lengkap.

Progress pada branch `codex/dfd-threat-model-alignment`:

- `backend/models/dfd.py` menambahkan canonical typed DFD contract.
- `backend/services/dfd_model_service.py` menambahkan deterministic adapter dan semantic hash/revision.
- Analysis report menyimpan `dfd_model` dan `dfd_validation`.
- Model DFD menjadi input prompt STRIDE/LINDDUN dan membawa revision/hash untuk stale detection.
- Endpoint `GET/PUT /api/projects/{project_id}/dfd` menyimpan model canonical dengan schema validation dan optimistic revision check.
- Model memiliki `layout_revision` terpisah dari semantic `revision`.
- Model evidence, per-attribute unknown assertions, process metadata, store metadata, dan feature projections tersimpan.
- Data-object privacy metadata mencakup direct/indirect identifiers, linkability, notice, individual control, dan documented legal basis; store metadata mencakup evidence refs dan lifecycle assertions.
- `refresh_attribute_assertions()` menyelaraskan status documented/inferred/unknown setelah human edit tanpa menghapus unmanaged conflict/flow assertions.
- Evidence refs pada canonical elements sekarang harus resolve ke `model.evidence`; source/manual/flow refs tetap dipertahankan sebagai evidence envelope.
- Canonical model sekarang juga disimpan eksplisit di `backend/data/dfd_models/{project_id}.json`, terpisah dari report analysis; project deletion menghapus keduanya.
- Loader canonical melakukan migration envelope legacy camelCase/default fields ke `dfd-v1`, mengisi model identity hanya saat project context tersedia, dan menolak schema version future yang tidak didukung.
- GET/save/import/proposal menggunakan loader schema yang sama; canonical storage dipulihkan dari report lama secara lazy sehingga report legacy tetap dapat dibuka tanpa kehilangan evidence envelope.
- Validator menolak schema version unsupported, orphan assertion, invalid view position refs, dan evidence ref zone; empty model tetap boleh disimpan sebagai draft tetapi `semantic_ready=false`.

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
- Model tersimpan di canonical storage yang dapat dibaca ulang tanpa bergantung pada field derived report.
- Legacy envelope yang didukung dapat dimigrasikan deterministik; schema future ditolak dengan error yang dapat ditindaklanjuti.
- M1 regression coverage lulus untuk migration, empty readiness, orphan metadata, revision-safe save, export/import, dan lazy legacy hydration.

### M2 — Graph integrity dan DFD semantics

Status: **Selesai untuk core graph integrity dan semantic validator — prioritas P0**. Gap topology
yang benar-benar belum didukung evidence tetap dilaporkan sebagai `semantic_ready=false`;
model tidak mengarang process, data object, atau edge untuk memaksa status hijau.

Progress:

- Validator sudah mendeteksi duplicate ID, dangling reference, invalid parent process, missing zone/data/boundary refs, dan zone cycle.
- Validator memisahkan blocking graph errors dari reviewable warnings.
- Regression tests untuk typed refs dan invalid graph sudah ditambahkan.
- Crossing metadata, projection mappings, store readers/writers, data labels, and question refs ikut divalidasi.
- OpenAPI/Postman operation metadata menghasilkan flow request/response terpisah bila response fields tersedia.
- Flow tanpa process/data label tetap tersimpan sebagai review warning; tidak dibuatkan process fiktif.
- Feature view menyimpan dan memvalidasi input/output flow port mappings terhadap parent process.
- Zone connectivity memakai ancestor-expanded membership sehingga parent container tidak false-positive terisolasi hanya karena node berada di child zone.
- Process input/output metadata, data-object lineage/transformation refs, dan store reader/writer relationships sekarang dicek terhadap graph aktual.
- Direct entity-to-store/store-to-store flow diberi review issue yang spesifik; flow tanpa data object atau hanya berlabel protokol menurunkan semantic readiness tanpa menghapus graph.
- Generic process labels dan reverse boundary/flow references diberi warning/error yang dapat ditindaklanjuti.
- Context STRIDE/LINDDUN membawa node zone/parent, process purpose/identity/privileges, flow data IDs/protocol/authn/authz/evidence, zone hierarchy, dan boundary rationale.
- Request/response projection hanya dibuat dari canonical operation yang relevan dengan endpoint flow; authn tidak lagi dipromosikan dari project-wide default ke semua flow.

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

- Unit test untuk graph integrity, same-zone flow, invalid flow, duplicate ID, dangling reference, nested parent connectivity, process metadata, lineage, direct transfer, dan analysis context.
- Postman-only input tidak menghasilkan database atau topology internal yang tidak terdokumentasi.
- Synthetic nested fixture lulus dengan `semantic_ready=true`; incomplete topology tetap menghasilkan issue yang dapat ditindaklanjuti.

### M3 — Ownership, scope, exposure, zone, dan boundary crossing

Status: **Selesai untuk core classification/crossing contract — prioritas P0**. Nilai yang belum
didukung evidence tetap `unknown` dan menghasilkan kebutuhan review; sistem tidak mengubah
heuristic zone/trust label menjadi fakta ownership atau exposure.

Progress:

- Canonical model sekarang memiliki field terpisah untuk scope, ownership, dan exposure dengan default `unknown`.
- Threat mapping tidak lagi fan-out ke seluruh boundary ketika tidak ada match.
- Regression test multi-boundary unmapped threat sudah ditambahkan.
- Crossing dihitung dari membership node dan ancestor zone dengan guard agar common ancestor tidak dihitung sebagai crossing.
- Logical reviewer crossing dapat dipertahankan pada same-zone flow; membership unknown menghasilkan `crossing_status=unresolved`.
- Synthetic customer-registration fixture mencakup nested organization/application/restricted-data zones serta vendor reverse flow.
- Project input sekarang dapat membawa `entity_metadata`, `zone_metadata`, dan `boundary_metadata` sebagai sumber klasifikasi/review eksplisit.
- Entity registry dan canonical builder memisahkan scope, ownership, exposure, operator/control party, serta stable zone membership; metadata alias dinormalisasi tanpa menggabungkan tenant/vendor secara longgar.
- Nested zone parent, ownership group, trust assumptions, dan evidence refs diproyeksikan ke canonical DFD; ownership group tidak dibuat sebagai boundary otomatis.
- Boundary types hanya diambil dari metadata flow/boundary yang eksplisit (`network`, `identity`, `privilege`, `tenant`, `organization`); tanpa evidence hasilnya `unknown`.
- Boundary candidate deduplication mempertahankan evidence, rationale, type, crossing flow IDs, dan model fingerprint; label matching threat memakai word boundary agar near-match tidak salah terhubung.

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
- Test explicit classification, nested zone metadata, unknown-preservation, boundary type evidence, same ownership group, dan near-match mapping.
- Scope/ownership/exposure yang tidak memiliki evidence tetap tampil sebagai `unknown`/review question, bukan dipromosikan menjadi fakta.

### M4 — Source, evidence, assertion, dan ingestion pipeline

Status: **Core remediation complete — hardening pipeline observability remains P1**

Sudah ada:

- Artifact hash/revision.
- Verifikasi snippet evidence terhadap source content.
- Reconciliation dan conflict record sederhana.
- Redaction secret diterapkan pada structured parser, generic AI parser, dan evidence/use-case verification.
- Fallback parser juga memakai konten redacted ketika provider AI gagal.
- Canonical model mengubah evidence catalog menjadi `DfdEvidenceRef` dengan document revision/hash dan redacted excerpt.
- `DfdEvidenceRef` sekarang juga menyimpan `evidence_type`, source, topics, document identity, revision, hash, locator, dan redacted excerpt; upload menautkan evidence item ke artifact ID.
- Confident fact tidak dipromosikan dari unknown classification; unknown lifecycle fields menghasilkan questions/assertions.
- Unknown privacy metadata pada data object juga menghasilkan assertions/questions untuk kebutuhan LINDDUN.
- Validator menolak duplicate evidence ID, documented/conflicting assertion tanpa evidence, inferred assertion tanpa reason, unknown assertion yang membawa nilai, question source/evidence ref yang tidak ada, dan answered question tanpa resolution.
- Conflict record dipertahankan sebagai satu assertion `conflicting` per source/value, sehingga reviewer dapat melihat kedua klaim dan provenance-nya.
- Postman parser menyimpan unresolved variable names, inherited/request auth source, safe saved-response shape/field metadata, dan script-count warning; response body/value tidak dipersist dan pre-request/test script tidak dieksekusi.

Hardening tersisa:

- Persist audit event per stage: ingest → extract → normalize → validate → review → analyze → persist.
- Expose locator terstruktur dan evidence provenance lengkap pada UI review/export.
- Tambahkan end-to-end acceptance untuk privacy readiness dan editing evidence reference lintas seluruh elemen DFD.

Definition of done:

- Test secret redaction, prompt-injection text, conflicting evidence, unresolved variables, saved response examples, assertion/question provenance, dan script non-execution.
- Core test coverage sudah tersedia; stage audit dan UI evidence review tetap menjadi P1 hardening.
- Hardening tersisa: persist stage-level ingest/extract/normalize/validate/review/analyze/persist audit event dan expose structured locator pada UI review.

### M5 — DFD views dan UI editing lifecycle

Status: **Core view/layout remediation complete — automated UI mutation coverage remains P1**

Progress:

- Canonical context/system views dan per-process feature projections tersedia di model.
- Context canvas memilih canonical DFD sebagai source of truth ketika model tersedia.
- Flow request/response ditampilkan sebagai edge terpisah dengan data label, interaction kind, crossing, evidence, dan unknown status.
- Canonical SVG export tersedia dan sudah diuji terhadap escaping.
- Canonical DFD inventory dapat dinavigasi dari canvas, dan inspector dapat mengedit metadata node/flow melalui revision-safe API.
- Drag pada canonical context menyimpan posisi sebagai layout-only revision.
- Posisi System/Feature tidak lagi selalu ditimpa auto-layout setelah reload; view menyimpan dan memulihkan `x`, `y`, dan `scale` viewport.
- Backend menyelaraskan Context/System projection dan Feature input/output ports setelah import, add/edit/delete, dan proposal apply; presentation state tetap dipertahankan.
- Validator memeriksa viewport, collapsed-group references, dan duplicate feature port flows.
- Inventory menyediakan collapse/expand per zone; projection visual memakai group node dan mengagregasi flow tanpa mengubah canonical semantic graph, sementara `collapsed_groups` tersimpan pada view yang aktif.
- Toolbar canonical DFD menyediakan undo/redo history untuk semantic maupun layout snapshot.
- Level UI canonical memisahkan Context, System DFD, dan Feature DFD dengan pemilihan parent process.
- Regeneration proposal memiliki candidate model yang dapat diterapkan eksplisit tanpa menghapus layout manual.
- Regeneration proposal memiliki section-level review dan aksi dismiss yang menyimpan resolution history tanpa mengubah canonical model.
- Canonical renderer sekarang memakai topology-aware layout, directed flow labels, dynamic nested zone containers, dan lane terpisah untuk node tanpa flow agar graph tetap terbaca tanpa mengarang koneksi.
- System DFD sekarang memusatkan graph pada node dengan evidenced flow, menempatkan zone terkait di sekitar hub, serta menyediakan tombol untuk menampilkan node terisolasi; banner menampilkan semantic issues dari validator.
- Alias entity dari component/flow/declared external/store digabung secara konservatif. Boundary zone yang sama mengelompokkan beberapa evidenced flow; regeneration proposal juga mengikutsertakan store metadata agar review tidak membuang lifecycle mapping.
- SVG export memakai fallback layout dan zone containers yang sama secara semantik, termasuk label flow dan dashed boundary semantics; legacy evidence refs di-hydrate saat read/export agar report lama tetap dapat divisualisasikan.
- Canonical DFD JSON export/import telah ditambahkan melalui schema validation dan optimistic revision check.
- Inventory sekarang mencakup zone; boundary inspector dapat mengubah status, tipe,
  transition scope, dan rationale; zone inspector dapat mengubah parent dan trust assumptions.
- Backend `impact-preview` menghitung dependent node/flow/view/boundary/zone/question/threat
  sebelum deletion, dan UI delete menampilkan konfirmasi dependency sebelum mutasi.
- Control mapping sekarang menyimpan implementation status terpisah dari review status,
  menormalisasi `location_ref`/`target_refs` terhadap canonical DFD, dan menolak verification
  evidence refs yang tidak ada.

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
- Proposal dapat di-apply per section atau di-dismiss; dismiss menyimpan resolution metadata dan hanya meng-clear stale pada alasan source-context yang sesuai.
- Inspector semantic edit dapat menyimpan evidence references; logical/mixed crossing wajib memiliki origin reviewer dan rationale.

Definition of done:

- Drag node tidak mengubah semantic membership secara diam-diam.
- Reload memulihkan model dan layout.
- Perubahan layout saja tidak membuat threat analysis stale.
- System/Feature layout dan viewport tersimpan pada view yang benar, bukan fallback Context view.
- Import atau edit tidak dapat meninggalkan projection/port mapping yang stale.
- Collapse/expand zone hanya memengaruhi projection visual dan dapat dipulihkan saat reload.

### M6 — Graph-driven STRIDE dan LINDDUN

Status: **Core remediation complete — graph/assessment contract aligned; downstream control/test hardening remains in M7/M9**

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
- Privacy readiness dipersist sebagai `privacy_assessment`; setiap threat LINDDUN diberi privacy context status/missing fields dan metadata yang belum ada menghasilkan `needs_context`, bukan klaim aman atau non-compliance.
- Prompt LINDDUN menerima lifecycle/privacy assessment dan secara eksplisit membedakan missing information dari legal conclusion.
- Validasi AI menolak shape list yang salah, memfilter evidence/DFD IDs dangling, menambahkan title/scenario/controls/mitigations, serta menandai `analyzed_revision`.
- Provider envelope sekarang membedakan `complete`, `valid_empty`, `partial`, `invalid`, dan `fallback`; `threats=[]` dengan envelope valid tidak lagi berubah menjadi fallback.
- Candidate tanpa canonical DFD target, candidate dengan seluruh refs dangling, dan mapping refs yang tidak dikenal ditolak serta dicatat pada `analysis_quarantine` dengan summary aman dan alasan.
- Legacy/stale report threats divalidasi sebelum controls/tests; item tanpa revision aktif, revision berbeda, framework/category/description invalid, atau target DFD hilang dipindahkan ke quarantine tanpa meng-upgrade diam-diam ke revision baru.
- Rerun mengganti snapshot per framework dan mempertahankan `status`, owner, review notes/time, evidence, dan stable threat ID untuk fingerprint yang sama; framework lain tidak ikut terhapus.
- Status stage ditulis setelah validasi. Output partial/invalid atau fallback menjadi warning dan tidak dapat meng-clear stale secara implisit; hasil valid empty menjadi assessment yang berhasil tetapi tidak dipromosikan sebagai bukti aman.
- Coverage sekarang menyimpan `applicability`, rationale untuk `not_applicable`, dan `mapping_refs`; summary memisahkan applicable/not-applicable/unknown applicability.
- Guard LINDDUN `Non-compliance` membutuhkan obligation **dan** evidence yang valid; salah satu hilang tetap `needs_context`/`Needs Info` dengan assertion `unsubstantiated`.
- Classification LINDDUN yang tidak disediakan engine dipertahankan sebagai `Unknown`, bukan default `PII`; schema canonical menerima uncertainty tersebut secara eksplisit.

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

M6 verification / definition of done:

- Valid empty STRIDE/LINDDUN tidak memicu fallback dan tetap menghasilkan graph coverage yang terlihat sebagai `insufficient_information` bila coverage belum lengkap.
- Malformed/stale candidate tidak masuk ke controls, tests, risk summary, atau active threat list; alasan dan item recovery tersimpan di `analysis_quarantine`.
- Candidate aktif selalu pinned ke canonical DFD revision dan memiliki minimal satu canonical `affected_ref` yang tervalidasi.
- LINDDUN tidak mengeluarkan klaim non-compliance tanpa dua sisi pembuktian, dan missing classification tidak dipromosikan menjadi PII.
- Rerun framework tidak kehilangan keputusan reviewer untuk finding semantik yang sama.
- Verification: 103 Python tests, JavaScript syntax/regression, `git diff --check`, dan Playwright UI/API smoke pada report demo (HTTP 200, DFD/coverage/threat sections ter-render, 0 console error pada sesi baru).

### M7 — Threat traceability, controls, dan stale analysis

Status: **Core remediation complete — traceability/stale contract aligned; external execution workflow remains M9**

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
melalui Playwright pada demo report; privacy assessment dan evidence-reference inspector
juga ter-render. Controls/tests sekarang menampilkan implementation/execution state,
threat/control/DFD links, dan evidence handoff pada UI.

M7 remediation:

- Control AI menerima daftar valid canonical DFD IDs; output malformed/non-array dikategorikan sebagai stage warning dan masuk fallback terlabel.
- Fallback control melakukan matching per-threat berbasis kategori/keyword, menggunakan stable catalog IDs, dan tidak lagi menghubungkan control ke `threats[:3]` atau memilih tiga control generik tanpa basis.
- Control mapping menyimpan `mapping_status`, `mapping_basis`, `control_origin`, `recommendation_status`, `location_ref`, `target_refs`, `analysis_revision`, dan `dfd_revision`.
- Status `Implemented`, `Partial`, atau `Missing` tidak dianggap fakta implementasi tanpa `verification_evidence_refs`/implementation evidence; status dikembalikan ke `Unknown` dengan alasan review.
- Test generator memproses seluruh active threat set, memakai safe access untuk legacy records, memiliki template LINDDUN, dan memvalidasi FK `threat_id`, `related_control_id`, DFD refs, serta execution evidence refs.
- Test scenario menyimpan `execution_status`, `actual_result`, `execution_evidence_refs`, `verification_status`, stable fingerprint/`test_id`, dan active DFD revision.
- Rerun controls/tests mempertahankan stable control/test identity, review fields, implementation evidence, dan execution result jika semantic fingerprint tetap sama.
- Propagasi target refs sekarang menambahkan target threat tanpa menghapus explicit control/test location refs.
- Stale stages hanya dibersihkan setelah stage menghasilkan current validated result; fallback atau invalid output tetap mempertahankan stale warning.

M7 verification / definition of done:

- Tidak ada control fallback fan-out lintas threat yang tidak punya basis mapping.
- Tidak ada test scenario aktif tanpa threat FK; seluruh test aktif membawa DFD target refs dan status `Not Run` sampai ada execution evidence.
- Existing/recommended status terpisah, dan implementation status tanpa evidence tidak dipresentasikan sebagai implemented/missing fact.
- Rerun mempertahankan reviewer/execution state, sementara fallback tidak meng-clear stale.
- Verification: 109 Python tests, JavaScript syntax/regression, `git diff --check`, dan Playwright pada Controls/Tests (HTTP 200, stable cache `analysis.js?v=20260919i`, evidence/traceability fields ter-render, 0 console error).

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
- Analysis run menyimpan state `running`, `failed`, `completed_with_warnings`, atau
  `completed`; kegagalan menyimpan error redacted dan retryable state tanpa mengganti report
  lama, sedangkan UI menampilkan status dan retry action.
- Provider URL, local-only selection, token budget, timeout, dan retry count melewati policy
  validation sebelum outbound request.

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

- Test suite bertambah dari 24 menjadi 65 Python tests.
- Test suite branch saat ini berjumlah 86 Python tests, termasuk privacy assessment,
  pipeline acceptance, assertion provenance refresh, proposal dismiss, dan logical
  reviewer-boundary coverage.
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
| Canonical semantic DFD | **Core contract complete**: typed schema, explicit canonical storage, migration loader, evidence/assertions, privacy/lifecycle metadata, hash/revision, validator, editable graph; semantic completeness/import demo masih banyak unknown/inferred dan dilacak M2–M4 |
| Stable typed node/flow model | **Core graph integrity complete**: typed node/flow/data/boundary refs, request/response, ancestor-aware connectivity, process metadata/lineage validation, feature projections/port lint; automated mutation coverage UI belum lengkap |
| Ownership/scope/exposure separation | **Core contract complete**: independent fields, explicit `entity_metadata`, unknown preservation, operator/control party, nested zones, semantic crossing, reviewer/editor resolution; extraction UI/evidence collection lanjutan masih incomplete |
| Nested and logical boundary | **Core crossing complete**: ancestor crossing, common-parent guard, nested zone metadata, logical/mixed reviewer crossing dengan rationale, zone/boundary editor, add/remove, proposal review, dan question resolution; full logical boundary workflow belum ada |
| Same-zone analysis | **Core validator complete**: same-zone flows retained, tidak dianggap crossing, dan tetap masuk scope; full UI mutation coverage belum ada |
| Threat traceability | Partial: explicit DFD refs, unmapped state, cross-boundary fan-out fixed, threat-to-DFD focus action, typed control locations/evidence refs |
| STRIDE coverage model | Partial: prompt, validated output, deterministic element/category coverage, revision tracking; engine-backed coverage masih reviewable |
| LINDDUN PRO-aligned model | Partial: canonical labels/aliases, sender-flow-receiver prompt, privacy/lifecycle assessment, `needs_context` annotation, non-compliance guard; evidence-backed lifecycle resolution belum lengkap |
| Editable DFD dan layout persistence | Partial: add/edit/remove node/flow/data/zone/boundary, inventory, I-P-O/store inspector, privacy fields, evidence-reference editor, topology-aware zone layout, layout persistence, undo/redo, impact preview; automated UI mutation test belum ada |
| Regenerate diff/revision conflict | Partial: revision conflict, candidate proposal, explicit apply, per-section review, dan dismiss history sudah ada; durable job/recovery belum ada |
| JSON round-trip/SVG export | Partial: schema-validated JSON import/export dan zone-aware SVG export; visual QA boundary/label lintas ukuran layar belum lengkap |
| Authentication/project isolation | Partial: configurable token-per-workspace guard + cross-workspace resource check; IdP/JWT production integration belum ada |
| Failure/retry/provider safety | Partial: persisted analysis run state, retry endpoint/UI, URL allowlist, local-only policy, and bounded token/timeout/retries; server-side cancellation/quota belum ada |
| Synthetic DFD fixture | Partial: customer-registration source/model tersedia; Postman-only fixture inline test |
| Automated verification sesuai AC01–AC20 | Partial: 129 Python tests + JS regression + Playwright DFD/report/privacy/proposal smoke-test + access-control/provider/failure helper tests; F07 coverage/legacy/applicability regression sudah lulus, tetapi full end-to-end/UI mutation criteria belum lengkap |

## Prioritas implementasi

1. **P0 — C0:** report legacy, schema seluruh stage, empty assessment yang sah, serta retry/staleness yang tidak merusak hasil review.
2. **P0/P1 — C1:** input canonical lengkap, readiness yang benar, dan evidence-based DFD review.
3. **P1 — C2:** applicability/coverage STRIDE dan LINDDUN PRO, evidence guard dan risk rationale.
4. **P0/P1 — C3:** control mapping per threat, implementation evidence, dan actionable recommendation.
5. **P0/P1 — C4:** scenario generation tanpa crash/silent omission, privacy coverage, serta verification evidence workflow.
6. **P1/P2 — C5:** observability, chunking/retrieval, budget/batching, run snapshot dan selective retry/cache.
7. **P1 — C6:** guided review/handoff, keyboard usability, export lengkap dan acceptance end-to-end.

P0 pada C3/C4 dapat dikerjakan setelah kontrak C0/C1 siap, tanpa menunggu seluruh
penyempurnaan C2. Pekerjaan authorization/deployment M8 tetap tercatat, tetapi bukan
fokus audit empat core function ini. Jangan mendahulukan redesign canvas atau pergantian
database atas perbaikan data/hasil yang sudah terbukti salah.

## Change log

- 2026-09-19: Added core-function industry-practice audit against Microsoft STRIDE, LINDDUN PRO, OWASP threat modeling, ASVS 5.0.0 and WSTG 4.2. Recorded report revision 5, F01–F13 findings, C0–C6 delivery milestones, data/processing optimizations and CT01–CT15 acceptance backlog. Re-ran 82 Python tests and JS regression; inspected DFD/Controls/Tests with Playwright and reproduced three validation/mapping issues in memory. The audit gaps remain tracked for C0–C6; M1 hardening is recorded in the next entry.
- 2026-09-19: Completed M1 core contract hardening: explicit per-project canonical DFD storage, legacy envelope migration, supported-schema gate, empty-draft readiness state, orphan assertion/layout/evidence validation, and report-to-canonical lazy hydration. Verification: 82 Python tests, JavaScript regression, Playwright GET `/dfd` status 200 with `dfd-v1` revision 5, 20 nodes/8 flows/90 evidence/226 assertions, `valid=true`, and expected `semantic_ready=false` topology warnings.
- 2026-09-19: Completed M2 core graph remediation: ancestor-aware zone connectivity, process metadata and lineage reference validation, actionable direct-transfer/data-label checks, operation-scoped request/response projection, and complete DFD analysis context. Verification: 86 Python tests, JavaScript regression, Playwright GET `/dfd` status 200 with `valid=true`, `semantic_ready=false` only for the active demo's evidenced topology gaps, and zero console errors.
- 2026-09-19: Completed M3 core ownership/scope/exposure remediation: explicit entity/zone/boundary metadata inputs, unknown-preserving classification, nested zone projection, evidence-backed boundary types/rationale, same-ownership-group separation, and word-boundary-safe threat mapping. Verification: 89 Python tests, JavaScript regression, Playwright GET `/dfd` status 200 with `valid=true`, and zero console errors.
- 2026-09-19: Remediated M4 evidence/assertion/ingestion findings: structured evidence provenance (type/source/topics/document identity/revision/hash), per-source conflicting assertions, multi-conflict preservation during assertion refresh, semantic assertion/question provenance validation, Postman unresolved-variable and saved-response shape metadata, and explicit non-execution warnings for pre-request/test scripts. Verification: 94 Python tests, Python compilation, JavaScript regression, and Playwright API/UI smoke passed with HTTP 200, `dfd-v1`, `valid=true`, and zero console errors.
- 2026-09-19: Remediated M5 view/layout lifecycle findings: backend projection synchronization for Context/System/Feature views, feature port rebuilding after import/edit/proposal, viewport validation and persistence, restoration of saved System/Feature layouts, layout-only acceptance coverage, and persisted zone collapse/expand projection with flow aggregation. Verification: 96 Python tests, JavaScript regression, syntax/diff checks, and Playwright smoke passed with HTTP 200, `valid=true`, all three DFD levels visible, 13 valid feature views, collapse/expand round-trip restored, and zero console errors.
- 2026-09-19: Remediated M6 graph-driven STRIDE/LINDDUN findings: valid-empty assessment contract, explicit partial/invalid/fallback stage status, revision-pinned threat quarantine, per-framework snapshot reconciliation with reviewer preservation, strict canonical DFD target validation, LINDDUN applicability/mapping metadata, complete obligation+evidence non-compliance guard, and explicit `Unknown` privacy classification. Verification: 103 Python tests, JavaScript syntax/regression, diff checks, and fresh Playwright smoke passed with HTTP 200, DFD/coverage/threat UI rendered, and zero console errors.
- 2026-09-20: Remediated F01 P0 legacy-threat safety gap: active report findings are validated before STRIDE/LINDDUN and downstream stages; malformed, duplicate, unsupported, unpinned, stale, mismatched, and dangling findings are quarantined with recoverable audit reasons; fallback/partial provider output cannot replace a valid framework snapshot; unmatched reviewed findings survive valid reruns; empty preserved results are recorded in quarantine. Verification: 112 Python tests, including malformed legacy STRIDE and reviewed LINDDUN fallback preservation, compilation and diff checks, plus Playwright smoke with analysis page HTTP 200, project/report API HTTP 200, and zero console errors.
- 2026-09-20: Remediated F02 P0 assessment classification gap: structured provider/schema failures now become explicit `invalid` results with quarantine evidence instead of being mislabeled as deterministic fallback; valid empty list-compatible results normalize to `valid_empty`; contradictory/unknown result statuses are rejected; `ai_status.ok` is evaluated only after result normalization and candidate validation. Verification: 115 Python tests, JavaScript syntax/regression, compilation and diff checks; Playwright smoke with analysis page and project/report API HTTP 200 and zero console errors.
- 2026-09-20: Remediated F03 P0 DFD context propagation gap: expanded the canonical DFD formatter with model provenance, semantic hash, identity/operator/knowledge, process/data/lifecycle metadata, crossing rationale/origin, boundary controls, evidence and review decisions; passed the same snapshot to Controls and Tests alongside threat/evidence/control mappings; pinned threat/control/test outputs to the active DFD revision and semantic hash. Verification: 117 Python tests, JavaScript syntax/regression, compilation and diff checks; Playwright smoke with analysis page and project/report API HTTP 200 and zero console errors.
- 2026-09-20: Remediated F04 P0 structured-generation gap: added provider response metadata (`finish_reason`, usage, model, attempts, parse status, response shape, retry reason), bounded stage budgets, strict Control/TestScenario envelopes and item contracts, enum/foreign-key/DFD/evidence validation, list-compatible complete/partial/fallback results, and explicit malformed-vs-truncated JSON classification. Truncated payloads are no longer accepted through repair; `ai_status` preserves stage metadata and error codes. Verification: 121 Python tests, compilation, JavaScript regression, diff checks, and final Playwright UI/API smoke passed: report HTTP 200, DFD/Controls/Tests rendered, desktop/mobile widths stable, and zero console errors.
- 2026-09-20: Remediated F05 P0 control applicability gap: deterministic fallback now matches each threat independently using exact category/alias applicability or a two-signal keyword threshold, records per-threat mapping rationale/signals, emits explicit unassigned review records for unsupported threats, and preserves `mapping_status=unassigned` through enrichment. Text inference now rejects empty, substring-only, and one-token matches. Verification: 123 Python tests, compilation, JavaScript regression, diff checks, and Playwright UI/API smoke passed with Controls/Tests rendered and zero console errors.
- 2026-09-20: Remediated F06 P0 control-evidence lifecycle gap: controls now separate recommendation/review state from implementation status and evidence state (`unknown`, `planned`, `documented`, `runtime_verified`); implementation/runtime refs are validated, verification-only evidence cannot assert implementation, non-Unknown status patches require matching evidence, and requested/collected evidence is persisted. Expanded the catalog with applicability, evidence requirements, verification methods, separate consent vs notice controls, and removed TLS→Linkability applicability. Verification: 126 Python tests, catalog JSON validation, compilation, JavaScript regression, diff checks, and Playwright UI/API smoke passed with control lifecycle fields rendered and zero console errors.
- 2026-09-20: Remediated F07 P0 verification-scenario coverage gap: removed unsafe legacy indexing and all threat-count slicing, retained every active threat with a valid ID, converted missing-category/unsupported/provider-omitted records into explicit blocked scenarios with reasons, added applicability fields to generation/schema/UI/export, guarded webhook templates behind callback/webhook/HMAC evidence, and completed fallback templates for all seven canonical LINDDUN categories. Verification: 129 Python tests including legacy/provider omission, webhook applicability, and full LINDDUN coverage regressions; compilation, JavaScript regression, diff checks, and Playwright UI/API smoke passed with zero console errors.
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
- 2026-09-19: Added persisted analysis run state/retry boundary, provider URL/data-policy/resource validation, and typed control locations/verification references.
- 2026-09-19: Added privacy readiness/lifecycle assessment, data-object LINDDUN context annotation, privacy fields in canonical model/prompt/inspector, and per-attribute assertion refresh after human edits.
- 2026-09-19: Added proposal dismiss resolution history, logical/mixed crossing reviewer rationale validation, and evidence-reference editing across canonical DFD element inspectors/create forms.
- 2026-09-19: Aligned canonical DFD rendering with the Mermaid reference pattern: topology-aware node placement, visible directed flow labels, dynamic nested zone containers, isolated-node evidence lane, cache-busted assets, and zone-aware SVG export.
- 2026-09-19: Verification: 76 Python unit tests, JavaScript analysis visibility regression, JS syntax checks, Python compilation, diff whitespace checks, and Playwright DFD/report/privacy/proposal smoke-test passed; favicon route returns 200.
- 2026-09-19: DFD visual verification: Playwright confirmed 23 canonical nodes, 8 labeled edges, 4 visible zone containers, SVG export 200 with zones/flows, and zero console errors.
- 2026-09-19: Fixed canonical topology in the active demo: 20 nodes after evidence-based alias merge, 8 flows, 4 cross-zone flows, 2 zone boundaries, and 1 store with lifecycle metadata. `semantic_ready=false` correctly reports the isolated Customer zone and 13 nodes without evidenced flows; no relationship was invented. Added proposal coverage for stores and a connected System DFD view with review toggle. Python tests: 79 passing.

## Progress rule

Setiap milestone hanya boleh ditandai selesai bila:

- deliverables implementasinya tersedia;
- unit/integration test terkait lulus;
- tidak ada fallback/mock yang disamarkan sebagai hasil produksi;
- acceptance criteria terkait sudah diverifikasi;
- limitation yang masih ada tercatat di file ini.
