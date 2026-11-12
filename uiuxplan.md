# UI/UX Review & Revamp Plan — 5STONES

Status: **IN PROGRESS — automated core remediated 2026-09-24.** Deep visual audit menemukan shell/sidebar tidak canonical, lifecycle navigation tidak konsisten, metric `Scored risk` pecah pada mobile, serta beberapa accessibility/manual-review gaps. Runtime shell, shared workflow navigation, metric layout, keyboard/mobile journeys, dan release gate sudah diperbaiki; formal UX sign-off tetap menunggu screen-reader/contrast review dan moderated novice/expert evidence.

Branch: `codex/dfd-threat-model-alignment`

Audit date: 2026-09-24

Audit target terbaru: Analysis, Model, Findings, Action Plan, Evidence, Report; inspeksi tambahan Dashboard, New Project, Settings. Project **Hacktiv8 Commerce**.
Browser terbaru: Playwright Chromium deep visual audit pada 1440×900 dan 390×844, termasuk sidebar, filter open/closed, sticky rail, nested scrolling, typography, Report chrome, console, dan API traffic. Paket G matrix 390/768/1280/1440 serta axe-core 4.10.3 tetap menjadi regression evidence historis.
Evidence terbaru: tidak ada console/API failure. Gate M6 terbaru mencakup workflow/sidebar open state, Model sheet, filter/inspector state, retry/preserved result, deferred-only report, serta large fixture; tidak ditemukan overflow atau fixed overlay pada state yang diuji.

Latest remediation 2026-09-24:

- Sidebar runtime sekarang memakai satu canonical renderer. Global menu hanya `Dashboard`, `New project`, dan `Settings & BYOK`; lifecycle project dipindahkan ke shared workflow navigator sehingga tidak ada variasi `Analysis`/`Overview`, `DFD Model`/`DFD model`, atau `Report`/`Report & sign-off` antar route.
- Markup fallback statis pada enam workspace route juga sudah dinormalisasi ke sections dan label yang sama, sehingga tidak ada menu `Current Project` atau `New Project` lama yang muncul saat JavaScript belum selesai memuat.
- Semua project route memiliki `Overview → DFD model → Findings → Action plan → Evidence → Report & sign-off` di bawah topbar. Desktop memakai links; mobile memakai current-stage picker; project/run/filter/selection tetap melalui UIState route contract.
- `analysis.html` tidak lagi merender navigator `analysis-workflow` legacy. Detail subview (Diagram, Boundary review, STRIDE/LINDDUN, Controls/Tests, dan Gaps) tetap diakses melalui workspace route dan tab yang relevan, sehingga lifecycle navigation tidak muncul dua kali.
- Analysis `Scored risk` sekarang memisahkan total scored dari detail Critical/High. Kartu tidak lagi memaksa string severity panjang ke kolom angka; summary grid memakai tiga kolom untuk tiga kartu yang benar-benar ada, tanpa sel kosong setelah `Evidence gaps`. M6 memverifikasi responsive 2 kolom mobile/3 kolom desktop, nol empty cell, dan tidak ada text overflow.
- `Project Context` dan `Threat model lifecycle` sekarang berada pada satu content rail penuh dengan left/right edge yang sama. Layout tidak lagi memakai sidebar 300px versus results fluid, sehingga alignment desktop konsisten dan mobile tetap satu kolom.
- H0 target gate sekarang `canonical_ready=true`; H1 shell/workflow contract dan M6 Chromium release gate menjadi evidence implementasi, sedangkan inventory lama tetap disimpan sebagai baseline drift historis.

**Mulai dari [deep visual re-audit dan plan terbaru §22](#22-deep-visual-re-audit-dan-consistency-remediation-plan--2026-09-24).** Bagian 1–13 menyimpan baseline; §14–21 menyimpan requirement dan riwayat implementasi sebelumnya. §22 menjadi acuan release terbaru saat ada perbedaan. Checklist implementasi historis tidak membuktikan acceptance UX telah lulus.

Koreksi utama: waktu skrip U7 **157 ms / 30,708 detik bukan hasil usability test peserta novice/expert**. Angka report **39.316 px** adalah baseline historis; setelah Paket E, default report fixture Hacktiv8 menjadi **2.531 px pada mobile 390×844** dan **1.873 px pada desktop 1440×900**, dengan appendix collapsed. Detail, requirement, owner, dependensi, dan bukti penutupan masing-masing temuan tersedia di bawah.

## 1. Outcome yang dituju

`analysis.html` harus berubah dari halaman yang menampilkan hampir seluruh data sekaligus menjadi workspace yang membantu pengguna mengambil keputusan berikutnya.

Prinsip utamanya:

1. **Decision first** — tampilkan status, risiko, dan satu tindakan utama sebelum detail teknis.
2. **Detail on demand** — data audit tetap tersedia, tetapi dibuka melalui drill-down, drawer, atau halaman khusus.
3. **Satu lifecycle yang konsisten** — Context → DFD → Findings → Remediation → Verification → Sign-off.
4. **Satu model data untuk semua persona** — pengguna awam memakai guided review; expert memakai table/compact view dan deep link tanpa hasil yang berbeda.
5. **Tidak menyembunyikan uncertainty** — status evidence, deferred risk, assumption, dan sign-off blocker tetap terlihat, tetapi diringkas dan dapat ditelusuri.

## 2. Ringkasan audit baseline sebelum pemisahan workspace

Catatan histori: angka dan temuan pada bagian ini berasal dari baseline terdahulu. Jangan memperlakukannya sebagai ukuran UI terbaru; lihat §14 untuk pengukuran ulang setelah U0–U7.

### 2.1 Baseline terukur

| Area | Desktop | Mobile 390×844 | Dampak |
|---|---:|---:|---|
| Navigasi hasil | 7 tab setara | 1 select berisi 7 section | Mental model mengikuti tipe data, bukan journey review |
| Halaman aktif Tests | 945 kata, 32 kontrol interaktif, 33 card, tinggi 2.995 px pada viewport 1444×633 | tinggi 11.209 px | Scanning dan orientasi sulit |
| Diagram | 294 kata, 56 tombol, panel 1.404 px | dokumen 4.173 px | Kanvas DFD tidak menjadi fokus utama |
| STRIDE | 15 item, 381 kata, panel 1.440 px | dokumen 4.524 px | Filter hanya kategori; review tetap linear |
| LINDDUN | 15 item, 395 kata, panel 1.542 px | dokumen 4.485 px | Masalah sama dengan STRIDE |
| Controls | 1.725 kata, panel 4.646 px | dokumen 11.513 px | Semua rekomendasi terbuka sekaligus, tanpa search/filter |
| Tests | 30 item, panel 2.436 px | dokumen 11.209 px | Header membesar pada mobile; 30 row tidak keyboard-accessible |
| Gaps & Assumptions | 2.648 kata, panel 6.972 px | dokumen 14.046 px | Pertanyaan penting tenggelam dalam daftar panjang |
| Report keseluruhan | 10.502 kata, tinggi 27.186 px | tinggi 56.263 px | Output formal sulit direview end-to-end |
| Report threat section | 30 scenario, 3.747 kata, tinggi 10.767 px | setiap row sekitar 715–739 px | Report berubah menjadi workbench panjang |
| Report assumptions | 30 item, 2.967 kata, tinggi 6.472 px | ditumpuk sebagai cards | Assumption penting tidak mudah diprioritaskan |

Tidak ditemukan horizontal overflow atau console error saat audit. Responsiveness secara teknis bekerja, tetapi vertical density dan cognitive load tetap sangat tinggi.

### 2.2 Temuan prioritas

#### UX-01 · P0 — Information architecture tidak mengikuti workflow

Tujuh tab (`Diagram`, `Trust Boundaries`, `STRIDE`, `LINDDUN`, `Controls`, `Tests`, `Gaps`) memiliki bobot visual yang sama. Pengguna harus memahami domain threat modeling sebelum mengetahui langkah berikutnya.

Status: **Fixed — 2026-09-22**

Implementasi:

- Navigasi utama diubah menjadi workflow berurutan: `Context → Model → Findings → Action plan → Evidence → Sign-off`.
- Diagram/Trust Boundaries, STRIDE/LINDDUN, dan Controls/Tests menjadi subview dari tahap yang relevan; hanya subview tahap aktif yang ditampilkan.
- Counts dan readiness ringkas tampil pada setiap tahap tanpa menduplikasi detail panel.
- Context menjadi tahap eksplisit; pada mobile context dipindahkan ke depan ketika dipilih sehingga pengguna tidak perlu melewati result list panjang.
- Sign-off mengarah ke `report.html` dengan project ID yang sama.
- Hash lama seperti `#analysis-stride` tetap bekerja dan otomatis mengaktifkan tahap Findings.
- Pilihan subview terakhir dipertahankan selama pengguna berpindah tahap pada session page yang sama.
- Keyboard Arrow Left/Right/Home/End tetap bekerja di subview aktif.

Validation:

- Playwright desktop 1440×900 dan mobile 390×844: seluruh tahap, subview, context reorder, legacy hash, dan responsive overflow lulus.
- RI4 Analyze-click browser E2E lulus dengan workflow navigation baru.
- 240 backend/integration tests lulus.
- Tidak ada browser console warning/error pada journey yang diuji.

#### UX-02 · P0 — DFD bukan lagi pusat threat modeling

Pada viewport desktop 1440×900, kanvas belum terlihat. Area sebelum kanvas berisi sign-off warning, overview, tab, dua baris command, dan coverage metadata. DFD mempunyai 56 tombol visible ketika section aktif; fungsi utama dan fungsi administrasi bercampur.

#### UX-03 · P0 — Halaman merangkap terlalu banyak pekerjaan

Context, artifact ingestion, run orchestration, DFD editing, boundary review, threat triage, controls, tests, gaps, dan sign-off readiness berada di satu document. Sticky sidebar context mengambil 300 px lebar kerja, sedangkan tab hasil tetap overflow pada desktop.

#### UX-04 · P0 — Daftar tidak mendukung triage skala nyata

STRIDE/LINDDUN hanya mempunyai filter kategori; tidak ada search, sort risk/confidence/status, owner, evidence state, atau quick queue. Controls dan Gaps tidak mempunyai filter. Semua control card ditampilkan expanded sehingga 15 control menghasilkan 1.725 kata.

#### UX-05 · P0 — Journey mobile kehilangan konteks

Pada lebar ≤1050 px, `results-area` dipindahkan sebelum context sidebar. Tombol **Update context** dapat membawa pengguna jauh ke bagian bawah setelah panel hasil yang sangat panjang. Lebar aman, tetapi journey tidak efisien.

#### UX-06 · P0 — Aksesibilitas dasar belum lengkap

- Tidak ada `<h1>` pada halaman.
- Header 30 test scenario memakai `div onclick`, tanpa `button`, `tabindex`, `aria-expanded`, atau `aria-controls`.
- Sejumlah filter dan input reviewer tidak memiliki label programatik.
- Tombol kembali di mobile hanya berupa ikon tanpa accessible name.
- Struktur heading pada list dan detail tidak cukup untuk navigasi screen reader.

#### UX-07 · P1 — Ringkasan mengulang angka tetapi belum menjelaskan konsekuensi

Angka candidate, reviewed, insufficient information, needs review, evidence gaps, dan sign-off gates muncul di beberapa tempat. Pengguna awam belum mendapat jawaban ringkas: “Apakah hasil ini dapat dipercaya?”, “Apa yang harus saya lakukan?”, dan “Apa yang belum dapat disimpulkan?”.

#### UX-08 · P1 — Detail finding terlalu panjang dalam accordion inline

Satu STRIDE finding yang dibuka menambah sekitar 1.012 px. Evidence, DFD mapping, review status, risk audit, override, abuse case, control, assumption, dan missing info berada dalam satu card. Pengguna kehilangan posisi terhadap daftar.

#### UX-09 · P1 — Terminologi belum memiliki progressive explanation

Label seperti `deferred`, `candidate`, `context signal`, `unmapped`, dan `insufficient information` penting bagi expert tetapi berat bagi pengguna awam. Saat ini penjelasan tersebar dan mengambil ruang permanen.

### 2.3 Gap assessment `report.html`

`report.html` sudah mempunyai fondasi yang berguna: global search dengan shortcut `/`, sticky table of contents, readiness/sign-off summary, framework/risk filter, semantic tables, serta export MD/CSV/JSON. Komponen ini harus dipertahankan dan tidak dibangun ulang di `analysis.html`.

#### RP-01 · P0 — Report dan analysis memiliki ownership yang tumpang tindih

Report menampilkan readiness, sign-off blockers, trust boundaries, findings, controls, tests, gaps, dan assumptions yang sama dengan Analysis. Selain membaca output, pengguna juga dapat mengubah status 30 threat langsung dari report. Akibatnya report bukan snapshot formal dan pengguna tidak tahu apakah harus melakukan review di Analysis atau Report.

Remediation:

- `analysis.html` menjadi operational overview dan mengarahkan pekerjaan yang belum selesai.
- Workspace Model/Findings/Action Plan/Evidence menjadi tempat perubahan data.
- `report.html` menjadi read-only review, sign-off, traceability, dan export.
- Tombol pada report berupa **Open in Findings/Model/Action Plan**, bukan inline mutation.

#### RP-02 · P0 — Report sangat panjang dan seluruh corpus dirender sekaligus

Report Hacktiv8 Commerce berisi 10.502 kata dengan tinggi 27.186 px pada desktop dan 56.263 px pada mobile. Threat section sendiri setinggi 10.767 px; pada mobile satu scenario membutuhkan sekitar 715–739 px.

Remediation:

- Default web report memakai executive summary + collapsed sections.
- Section besar memakai pagination atau list-summary/detail drawer.
- **Print/export mode** tetap dapat menghasilkan seluruh isi tanpa pagination.
- Jangan membangun seluruh hidden detail DOM pada initial load.

#### RP-03 · P0 — Risk summary dapat disalahartikan sebagai “tidak ada risiko”

Empat risk pills menampilkan `0 Critical`, `0 High`, `0 Medium`, dan `0 Low`, sementara terdapat 30 scenario berstatus `needs_context` dengan final risk `Unknown/deferred`. Pengguna awam dapat menyimpulkan sistem aman, padahal assessment belum cukup bukti untuk scoring.

Remediation:

- Tampilkan `0 scored / 30 deferred` sebagai status utama.
- Pisahkan **Scored risk distribution** dari **Scenario severity**.
- Tambahkan label eksplisit: “No final risk can be concluded yet”.
- Jangan gunakan zero-state berwarna seperti hasil selesai bila coverage belum ready.

#### RP-04 · P0 — Report belum menjadi artefak sign-off yang auditable

Readiness sudah terlihat, tetapi belum ada identitas reviewer/approver, keputusan, timestamp, report revision, canonical DFD revision/hash, source revision, risk-method version, atau signed snapshot yang immutable.

Remediation:

- Definisikan state `Draft`, `Ready to sign`, `Signed`, dan `Superseded`.
- Signed report harus immutable; perubahan project membuat draft revision baru.
- Simpan reviewer, role, decision, rationale, timestamp, model revision, source manifest, methodology/version, dan quality-gate result.

#### RP-05 · P0 — DFD tidak tersedia di report

Report memiliki trust-boundary section tetapi tidak menampilkan diagram, scope model, level DFD, atau revision yang menjadi dasar seluruh finding. Ini memutus traceability threat-model berbasis DFD.

Remediation:

- Tambahkan DFD snapshot ringkas, level yang digunakan, legend, canonical revision, dan model-health summary.
- Setiap finding mempunyai link/deep link ke primary DFD interaction.
- Export formal menyertakan diagram dan model revision yang sama dengan signed snapshot.

#### RP-06 · P1 — Navigasi mobile menghabiskan viewport dan dapat tidak sinkron

Pada 390×844, topbar setinggi 144 px, commandbar sticky 120 px, dan TOC sticky 59 px. Kombinasi sticky layer memakai sekitar 34% viewport dan area commandbar/TOC saling overlap. Saat deep link ke Threat scenarios, content sudah terlihat tetapi TOC sempat tetap menandai Trust boundaries.

Remediation:

- Mobile hanya memakai satu compact sticky bar: section selector + search icon.
- Search dibuka sebagai overlay/drawer.
- Hitung sticky offset dari elemen aktual, bukan angka CSS terpisah.
- Active section harus mengikuti target deep link secara deterministik sebelum observer aktif.

#### RP-07 · P1 — Search kuat tetapi hasil belum menjelaskan match

Search `webhook` berhasil mempersempit 115 indexed items menjadi empat hasil lintas empat section. Namun matching memakai serialisasi seluruh object, tidak menyorot field yang cocok, dan tidak menyediakan daftar hasil/jump target. Match dari metadata tersembunyi dapat membingungkan.

Remediation:

- Pertahankan shortcut `/` dan cross-section search.
- Indeks field eksplisit serta tampilkan match reason/snippet.
- Sediakan grouped search results sebelum pengguna melompat ke section.

#### RP-08 · P0 — Semantic heading dan contrast belum memenuhi baseline

Tidak ada `<h1>` sampai `<h6>` yang visible; judul dan section title menggunakan `div`. Back button tidak mempunyai accessible name. Teks muted pada report header memakai warna `rgb(69,123,157)` di atas `rgb(29,53,87)`, dengan contrast sekitar 2,69:1.

Remediation:

- Gunakan satu `<h1>` untuk report title dan `<h2>` untuk setiap section.
- Tambahkan accessible name pada back dan export actions.
- Naikkan contrast teks normal minimum 4,5:1.
- Pertahankan table semantics dan search label yang sudah baik.

## 3. Information architecture yang direkomendasikan

Gunakan lifecycle sebagai navigasi utama. `analysis.html` menjadi overview dan orchestrator, bukan container seluruh hasil.

| Page | Tujuan utama | Isi default | Detail yang dipindahkan |
|---|---|---|---|
| `analysis.html` | Menjawab status dan next action | Readiness, progress run, top blockers, risk summary, next-action queue | Tidak memuat daftar penuh DFD/threat/control/test |
| `model.html` | Memvalidasi model sistem | DFD canvas, level switcher, boundary review queue, selected-element inspector | Inventory dan advanced editor di drawer |
| `findings.html` | Triage STRIDE + LINDDUN | Unified list/table, filters, selected finding detail | Framework tetap field/filter, bukan dua workspace terpisah |
| `action-plan.html` | Merencanakan remediation dan verification | Control backlog dan test backlog yang terhubung ke finding | Detail implementation/checklist di side panel |
| `evidence.html` | Mengelola sumber dan uncertainty | Artifacts, coverage, missing info, assumptions, unresolved evidence | Upload dan locator details di drawer |
| `report.html` | Read-only sign-off dan export | Executive summary, DFD snapshot/revision, readiness gate, unresolved exceptions, approval, export | Hilangkan inline editing; gunakan signed revision |

Jika penambahan page harus dilakukan bertahap, urutan minimumnya adalah:

1. Pisahkan `model.html` lebih dahulu karena DFD membutuhkan workspace visual.
2. Pisahkan `findings.html` agar triage tidak bercampur dengan diagram.
3. Gabungkan Controls + Tests pada `action-plan.html`.
4. Pindahkan Context + Gaps + Assumptions ke `evidence.html`.

Semua page membaca canonical project/report state yang sama. Jangan membuat duplikasi data atau state khusus UI.

### Batas tanggung jawab Analysis dan Report

| Concern | Analysis/Workspace | Report |
|---|---|---|
| Menjalankan/retry analysis | Ya | Tidak; hanya menampilkan run provenance |
| Memperbaiki DFD/boundary | Ya, di Model | Link ke Model |
| Mengubah finding status/risk override | Ya, di Findings | Read-only + link ke finding |
| Menetapkan controls/tests | Ya, di Action Plan | Read-only traceability |
| Menambah evidence/resolve gap | Ya, di Evidence | Read-only unresolved exception |
| Readiness | Ringkas, action-oriented | Formal gate result dan alasan |
| Sign-off | Menunjukkan next action | Approval, revision, dan immutable snapshot |
| Export | Opsional data working set | MD/CSV/JSON/PDF dari revision yang dipilih |

Readiness boleh muncul pada Analysis dan Report karena konteksnya berbeda, tetapi harus memakai shared component dan source state yang sama. Analysis menjawab “apa yang harus dikerjakan”; Report menjawab “apa yang telah dinilai dan apakah dapat ditandatangani”.

## 4. Journey yang diusulkan

### 4.1 Pengguna awam — Guided review

1. Buka Overview.
2. Lihat status sederhana: **Ready**, **Needs review**, atau **Blocked** dengan satu kalimat penyebab.
3. Klik satu primary action, misalnya **Review 2 trust boundaries**.
4. Sistem membuka item pertama dengan penjelasan plain language dan opsi keputusan yang terbatas.
5. Setelah keputusan disimpan, tampilkan item berikutnya dan progress `1 of 2`.
6. Kembali ke Overview secara otomatis ketika queue selesai; primary action bergerak ke fase berikutnya.
7. Sign-off hanya aktif saat gate terpenuhi; blocker dapat dibuka tanpa membaca seluruh report.

Aturan guided review:

- Maksimum satu primary CTA per viewport.
- Maksimum lima item pada “Needs attention”; sisanya melalui **View all**.
- Istilah teknis mempunyai tooltip/help text, bukan paragraf permanen.
- Jangan menyatakan absence-of-evidence sebagai vulnerability.

### 4.2 Expert IT — Compact workbench

1. Masuk langsung melalui sidebar/deep link ke Model, Findings, Action Plan, atau Evidence.
2. Gunakan search dan multi-filter: framework, category, risk, status, confidence, evidence state, DFD element, owner.
3. Pilih row; detail muncul pada right-side inspector tanpa mengubah posisi scroll.
4. Gunakan next/previous finding dan keyboard shortcut untuk triage cepat.
5. Buka linked DFD interaction, controls, dan tests dari detail finding tanpa mencari ulang.
6. Simpan filter/view dalam URL agar dapat dibagikan dan direproduksi.

## 5. Rancangan tiap page

### 5.1 Overview — `analysis.html`

Urutan layar:

1. Project title + compact lifecycle indicator.
2. Run state: idle/running/partial/stale/complete, termasuk fase aktual dan ETA jika running.
3. Readiness card dengan satu status, satu alasan, satu CTA.
4. “Needs attention” queue maksimal lima item.
5. Ringkasan risiko dan coverage sebagai informasi sekunder.
6. Riwayat run/catatan teknis collapsed.

Hapus dari default overview:

- Full project context.
- Artifact uploader.
- Full result tabs.
- Full DFD toolbar/canvas.
- Full finding/control/test/gap lists.

Tetap sediakan **Run analysis**, tetapi gunakan label sesuai keadaan: `Run`, `Refresh affected stages`, atau `Retry failed stages`. Jangan menampilkan beberapa tombol Run yang melakukan pekerjaan serupa.

### 5.2 Model Workspace — `model.html`

Layout desktop:

- Top: breadcrumb, model level, health badge, save/revision state.
- Center: DFD canvas minimal 55% tinggi viewport dan terlihat above the fold.
- Left rail: level (`L0/L1/L2`), feature selector, legend.
- Right inspector: selected node/flow/boundary, evidence, linked findings.
- Bottom drawer: inventory dan validation findings.

Toolbar default hanya menampilkan:

- Level selector.
- Fit.
- Reflow.
- Undo/redo saat applicable.
- `More` untuk show unconnected, style mode, import/export, fullscreen, dan format export.

Coverage diringkas menjadi satu badge **Model health**. Detail STRIDE/LINDDUN coverage dan privacy metadata dibuka dalam panel. Boundary candidates tampil sebagai queue, bukan tab setara dengan DFD.

Mobile menggunakan canvas fullscreen-first; inspector menjadi bottom sheet. Jangan menumpuk canvas, 56 kontrol, inventory, dan coverage pada satu vertical page.

### 5.3 Findings Workspace — `findings.html`

Gabungkan STRIDE dan LINDDUN dalam satu workbench karena tindakan pengguna sama: review evidence, pastikan DFD mapping, tentukan status, dan lihat risk.

List row default hanya berisi:

- Severity/final-risk state.
- Framework + category.
- Judul singkat.
- Primary DFD interaction.
- Review status/confidence.

Detail panel berisi section yang dapat dilipat:

1. Decision & status.
2. DFD interaction dan trust boundary.
3. Evidence dan source locator.
4. Risk calculation/override audit.
5. Linked controls dan tests.
6. Assumptions/missing information.

Default sort: actionable first → scored risk → confidence → stable ID. Pisahkan state `risk deferred` dari severity scenario agar tidak terlihat seperti final risk.

### 5.4 Action Plan — `action-plan.html`

Sediakan dua view di dalam satu page:

- **Controls**: status, owner, priority, implementation evidence, linked threats, verification.
- **Tests**: priority, executable state, owner, execution status, linked control/finding.

Gunakan table/list ringkas dan side inspector. Checklist, implementation guidance, steps, expected result, dan evidence needed tidak ditampilkan sebelum item dipilih.

Tambahkan view **Unassigned/needs decision** agar warning control applicability mempunyai tujuan yang jelas.

### 5.5 Evidence Workspace — `evidence.html`

Kelompokkan berdasarkan tindakan, bukan tipe object:

- `Need an answer`: missing information.
- `Need validation`: assumptions.
- `Sources`: artifact + coverage manifest + unread/deferred section.
- `Context`: environment, actor, entry point, data, auth, external dependency.

Setiap gap mempunyai owner, status, source/locator, linked DFD/finding, dan aksi **Resolve**, **Defer with reason**, atau **Add evidence**. Hindari daftar pertanyaan tanpa workflow penyelesaian.

### 5.6 Formal Report — `report.html`

Pertahankan page yang sudah ada, tetapi ubah dari infinite editable document menjadi revision-aware formal review.

Urutan default:

1. Report state: `Draft`, `Ready to sign`, `Signed`, atau `Superseded`.
2. Executive summary: scope, assessment confidence, `scored/deferred` breakdown, dan top unresolved blockers.
3. DFD snapshot + canonical revision/model health.
4. Methodology: STRIDE/LINDDUN scope, deterministic risk method/version, source manifest, dan analysis run provenance.
5. Traceability summary: DFD interaction → finding → control → test.
6. Collapsed/paginated sections untuk boundaries, findings, controls, tests, gaps, dan assumptions.
7. Approval history dan export actions.

Web report default tetap ringkas. Tombol **View full appendix** membuka detail; export/print menghasilkan full appendix tanpa mengubah web page menjadi dokumen 56 ribu px.

Pertahankan:

- Search lintas section dan shortcut `/`.
- Table of contents dan counts.
- Framework/risk filter.
- MD/CSV/JSON export.
- Sign-off gate component.

Perbaiki atau pindahkan:

- Pindahkan status editing ke Findings Workspace.
- Ganti risk pills nol dengan `scored vs deferred` summary.
- Tambahkan DFD snapshot, revision, methodology, dan source/run provenance.
- Tambahkan PDF/print export dari selected signed/draft revision.
- Jadikan mobile TOC sebagai section selector tunggal dan search sebagai overlay.

## 6. Content hierarchy dan aturan density

### Above the fold

- Satu page title (`h1`).
- Satu status utama.
- Satu primary CTA.
- Maksimum dua secondary actions.
- Maksimum empat summary metrics.
- Tidak ada lebih dari satu warning banner; gabungkan blocker dan sediakan **View details**.

### Long lists

- Default 20–25 row per page atau virtualized list.
- Search selalu tersedia untuk Findings, Controls, Tests, dan Evidence.
- Filter aktif terlihat sebagai removable chips.
- Filter dan sort tersimpan pada query string.
- Detail item menggunakan side panel, bukan memperpanjang row lebih dari satu viewport.

### Status language

Gunakan dua layer label:

- Plain language: `Needs more evidence`, `Ready for review`, `Blocked from sign-off`.
- Technical detail: `candidate`, `deferred`, `interaction_mapping_status`, gate ID; tampil di tooltip/detail.

### Informasi yang jangan dihapus

- Source locator dan evidence strength.
- Canonical DFD references.
- Deterministic risk inputs dan override audit.
- Historical/stale/partial state.
- Applicability dan assignment controls.
- Test preconditions, steps, expected result, dan evidence needed.
- Assumption dan sign-off blocker.

Informasi tersebut dipindahkan ke tempat yang relevan dan tidak ditampilkan seluruhnya secara bersamaan.

## 7. Accessibility dan responsive requirements

### P0 accessibility

- Tepat satu `<h1>` per page dan heading hierarchy tanpa level yang dilewati.
- Semua expandable row adalah `<button>` dengan `aria-expanded` dan `aria-controls`.
- Semua input/select mempunyai `<label>` atau accessible name yang spesifik.
- Tombol ikon mempunyai `aria-label`; perbaiki back button mobile.
- Tab/stepper mendukung Arrow Left/Right, Home, End, dan fokus terlihat.
- Status dinamis memakai live region yang tidak mengumumkan seluruh page berulang kali.
- Target sentuh minimal 44×44 px pada mobile.
- Contrast dan state tidak bergantung pada warna saja.

### Responsive

- 390 px, 768 px, 1280 px, dan 1440 px tanpa horizontal overflow.
- Context/evidence editor menjadi drawer yang dapat dibuka dari mana saja; jangan dipindahkan ke bawah list panjang.
- Table expert berubah menjadi cards ringkas, sementara detail menjadi bottom sheet.
- DFD menyediakan fullscreen/bottom-sheet flow khusus mobile.
- Sticky header tidak menutupi target saat deep link atau focus navigation.

## 8. State yang wajib dirancang

Setiap page harus memiliki desain dan test untuk:

- No project/no analysis.
- Running per phase.
- Partial results/deferred references.
- Previous validated results preserved.
- Stale after context/DFD change.
- Provider failure/truncated/unstructured response.
- Empty because no grounded evidence.
- Empty because filters exclude all items.
- Sign-off blocked.
- Sign-off ready.
- Draft, signed, dan superseded report revision.
- Offline/network retry.

Error harus menyebut: apa yang masih aman digunakan, apa yang tidak valid, fase yang terdampak, dan aksi berikutnya.

## 9. Delivery milestones

### U0 · Baseline and contract — P0

- [x] Audit Chromium desktop/mobile pada Hacktiv8 Commerce.
- [x] Capture baseline density, navigation, responsive, dan accessibility issues.
- [x] Tetapkan route contract dan shared UI state (`project`, active run, filters, selection).
- [x] Tambahkan UX telemetry anonim untuk task completion, bukan isi dokumen sensitif.

#### Implementasi U0

- `id` adalah project key lintas halaman; `run`, `phase`, `view`, `f_framework`, `f_risk`, `f_stride`, `f_linddun`, `f_priority`, dan typed `selected` (`threat`, `boundary`, `zone`, DFD node/flow, control, test, gap) membentuk route state opsional. Nilai divalidasi terhadap allowlist sebelum dibaca/ditulis.
- `frontend/js/ui-state.js` adalah sumber bersama untuk parsing, update, dan route generation; API project helpers menggunakannya. Legacy `#analysis-<view>` deep links tetap dibaca deterministik dan ditulis ke query contract saat navigasi tab berikutnya. Report section anchors tetap memakai hash `#report-*`.
- State pencarian report (free text) sengaja tidak dimasukkan ke URL atau telemetry. State tab lokal lama tetap fallback jika URL tidak menyebut `view`; project/run canonical data tetap berasal dari API, bukan local storage.
- `frontend/js/ux-telemetry.js` hanya mengirim `task.completed` dengan task/surface/outcome, durasi bucket opsional, phase coarse, dan format export. Browser opt-out tersedia di Settings; Do Not Track menonaktifkan default. Request tidak memakai cookie, token, atau workspace headers.
- `backend/routers/ux_telemetry.py` menolak field tambahan dan menyimpan whitelist event secara lokal di `backend/data/ux_telemetry/`, terpisah dari audit log; log dihapus setelah 30 hari dan dibatasi 5 MiB per hari. Folder telemetry di-ignore oleh git.
- Instrumented completions: analysis run, threat review, trust-boundary review, semantic DFD edit, serta report export. Telemetry best-effort; gagalnya endpoint tidak mempengaruhi tugas pengguna.

Acceptance:

- Existing deep links mempunyai redirect/migration yang deterministik.
- Tidak ada perubahan canonical threat/DFD data contract hanya untuk kebutuhan layout.

### U1 · Lean Overview and global run status — P0

- [x] Ubah `analysis.html` menjadi lifecycle overview.
- [x] Satukan duplicate Run actions.
- [x] Buat next-action queue dan consolidated blocker banner.
- [x] Pertahankan progress fase aktual, retry affected stage, dan preserved-result state.

#### Implementasi U1

- Lifecycle overview ditampilkan sebagai landing state untuk project baru maupun hasil analisis; menampilkan status run, ringkasan severity, urutan next action, dan enam fase workflow.
- Tombol header adalah satu-satunya primary Run CTA. Tombol Run STRIDE/LINDDUN dan duplikat pada empty state dihapus; refresh/retry tetap tersedia sebagai aksi sekunder yang hanya mengulang affected phases.
- Daftar DFD, threats, controls, tests, dan gaps baru dibangun ketika pengguna membuka fase/detail workspace. Overview menghitung ringkasan tanpa memasukkan daftar penuh ke DOM.
- Progress memakai stage progress aktual yang sudah dipersist/poll (`active`, `completed`, warning/skipped), dengan elapsed, phase, dan estimasi yang tetap tersedia. Retry per-stage dan consolidated retry tetap menggunakan jenis stage yang terdampak.
- Satu blocker banner menggabungkan status stale, recovery/preserved-results, warning, dan sign-off blockers; banner menjelaskan data yang masih aman, fase terdampak, dan aksi retry bila tersedia.
- Deep link fase tetap membuka detail workspace; setelah run baru selesai, default kembali ke overview. Tombol Back to overview menutup detail tanpa mengubah report tersimpan.

Acceptance:

- Pengguna dapat menyebut status analysis dan next action dalam ≤10 detik.
- Hanya satu primary CTA di first viewport.
- Full result list tidak dirender pada overview.

### U2 · DFD Model Workspace — P0

- [x] Buat `model.html` dengan canvas-first layout.
- [x] Pindahkan boundary review ke queue/inspector.
- [x] Kelompokkan advanced commands ke `More`.
- [x] Sediakan responsive fullscreen/bottom sheet.

#### Implementasi U2

- `model.html` menjadi workspace DFD terpisah dengan canvas utama, Context/System/Feature level, status revision/readiness, dan inventory yang dapat dibuka sesuai kebutuhan.
- Boundary review dipindah ke queue di rail samping. Setiap item menampilkan state, basis, evidence refs, linked crossing flows, dan aksi Confirm/Reject/Reset; inspector boundary memperlihatkan metadata serta findings terkait.
- Inspector DFD menampilkan bukti dan flow terkait; finding yang ditautkan membuka report pada finding terpilih. Sebaliknya, target canonical pada report dan aksi “Focus affected DFD elements” membuka model dengan elemen terkait terseleksi.
- Perintah lanjutan (reflow, tampil/sembunyikan unconnected, undo/redo, export/import, mode visual) dikelompokkan di menu `More`; Fit dan Fullscreen tetap menjadi aksi langsung.
- Canvas diberi tinggi minimum 55vh (680px pada desktop) dan rail inspector responsif; pada layar kecil rail berubah menjadi bottom sheet yang dapat digulir. Layout canonical tetap menjalankan resolusi overlap dan Fit mencakup seluruh node yang terlihat.
- Navigasi Model tersedia dari Analysis, Report, workflow Model, queue boundary, dan tautan target DFD di report. State selection dibawa lewat shared route contract.

Acceptance:

- Kanvas terlihat above the fold pada 1440×900 dan memakai ≥55% tinggi viewport.
- Fit tidak overlap dan selected element tetap terlihat.
- Boundary, flow, evidence, dan linked finding dapat ditelusuri dua arah.

### U3 · Unified Findings Workspace — P0

- [x] Buat `findings.html` dengan unified STRIDE/LINDDUN list.
- [x] Tambahkan search, multi-filter, sort, URL state, dan list-detail inspector.
- [x] Pisahkan scenario severity dari final/deferred risk.
- [x] Implement keyboard-accessible triage.

#### Implementasi U3

- `findings.html` menjadi workspace khusus dengan satu list gabungan STRIDE/LINDDUN dan inspector detail yang tidak menggantikan list. Search, framework, severity, review status, finding state, mapping DFD, dan sort tersimpan dalam shared URL state (`q`, `ff`, `fs`, `fst`, `fstate`, `fi`, `sort`), sehingga deep-link dapat dibagikan tanpa isi dokumen mentah.
- Setiap row menampilkan dua nilai berbeda: `Scenario severity` sebagai sinyal skenario dan `Final` sebagai hasil penilaian deterministik. Finding yang belum memiliki hasil final ditampilkan sebagai `Deferred`, bukan sebagai vulnerability atau `Unknown` yang ambigu.
- Setiap finding menampilkan canonical primary DFD flow dan tautan dua arah ke `model.html`; finding tanpa flow ditampilkan sebagai `DFD interaction deferred` dengan alasan eksplisit. Inspector menyediakan pemilihan flow kanonis dan update review status.
- Triage memakai elemen button yang dapat difokuskan, Enter untuk membuka inspector, Arrow Up/Down untuk berpindah row, Escape untuk menutup, `/` untuk fokus search, dan mengembalikan fokus ke row sebelumnya setelah inspector ditutup. Scroll list tidak dirender ulang secara destruktif saat inspector dibuka.
- Entry point Analysis → Findings, workflow stage Findings, DFD Model, dan Report diarahkan ke workspace gabungan agar pengguna tidak kembali ke dua list framework yang terpisah.

Acceptance evidence:

- Search/filter menghasilkan URL state dan row target dapat dibuka langsung dari hasil list.
- Inspector adalah panel sibling terhadap list; membuka/menutup detail tidak menghapus list atau posisi scroll.
- Mapping DFD pada row/inspector selalu berupa flow kanonis atau status `DFD interaction deferred`.

Acceptance:

- Expert mencapai finding tertentu dalam ≤2 navigation actions setelah search/filter.
- Pengguna tidak kehilangan posisi list setelah membuka/menutup detail.
- Semua finding menampilkan canonical primary DFD interaction atau status deferred yang eksplisit.

### U4 · Action Plan Workspace — P1

- [x] Buat `action-plan.html` untuk Controls dan Tests.
- [x] Tambahkan Unassigned/needs applicability decision queue.
- [x] Gunakan side inspector untuk guidance, checklist, steps, dan evidence.
- [x] Tambahkan owner/status/priority/executable filters.

#### Implementasi U4

- `action-plan.html` menyatukan control dan test dalam satu queue; control unassigned dan test yang blocked/non-applicable atau belum memiliki control masuk ke decision queue yang dapat diklik.
- Side inspector menampilkan guidance, checklist, evidence, owner/status control, precondition, steps, expected result, evidence needed, execution/applicability state, serta traceability ke finding, canonical DFD target, dan test/control terkait.
- Search, type, priority, status, executability, owner, dan sort tersimpan sebagai URL state melalui shared route contract. Filter queue tidak membuat pengguna mencari ulang item terkait.
- Semua row menggunakan keyboard-accessible button dengan Arrow Up/Down, Enter, Escape, dan `/`; membuka inspector tidak menghilangkan list atau posisi scroll.
- Control card tidak expanded pada first render; detail hanya muncul setelah item dipilih di inspector.

Acceptance evidence:

- Control → threat → DFD → test dapat ditelusuri dari link inspector tanpa pencarian ulang.
- Test rows memiliki semantic button/role option dan dapat ditriage melalui keyboard.
- Decision queue memisahkan controls unassigned dan tests yang membutuhkan applicability review.

Acceptance:

- Control → threat → DFD → test dapat ditelusuri tanpa pencarian ulang.
- Semua test row keyboard-accessible.
- Tidak ada semua control card expanded secara default.

### U5 · Evidence Workspace — P1

- [x] Buat `evidence.html` untuk context, artifacts, gaps, assumptions, dan ingestion coverage.
- [x] Tambahkan workflow resolve/defer/add evidence.
- [x] Pastikan unread/deferred document sections terlihat.

#### Implementasi U5

- `evidence.html` menjadi workspace khusus dengan summary readiness, context editor, artifact intake, ingestion coverage, serta queue gabungan gap dan assumption.
- Context editor memakai native dialog pada desktop dan bottom-sheet pada mobile, sehingga dapat dibuka dari header maupun summary card tanpa memindahkan atau menutup result list.
- Setiap item evidence menampilkan owner, state, linked finding/DFD/project context, dan next action pada row maupun inspector. State `Open`, `Answered`, `Resolved`, dan `Deferred` disimpan melalui endpoint review evidence yang tervalidasi.
- Artifact coverage menampilkan jumlah chunk, status coverage, revision, serta daftar unread/deferred section secara terbuka. Bagian yang belum terbaca tidak disembunyikan di balik hasil analisis.
- Add evidence menggunakan artifact upload yang sudah ada, dengan batas ukuran dan accept type yang eksplisit, lalu me-refresh project/report agar coverage terbaru langsung terlihat.
- Search, multi-filter, sort, selection, deep-link, dan keyboard triage mengikuti shared URL contract (`eq`, `etype`, `est`, `eowner`, `esort`, `selected`).
- Navigasi dua arah ditambahkan dari Analysis, DFD Model, Findings, Action Plan, dan Report ke Evidence Workspace.

Acceptance evidence:

- Context dapat dibuka melalui `Update context` atau `Edit project context`; pada breakpoint kecil dialog berubah menjadi bottom-sheet dan tidak menggantikan queue evidence.
- Queue evidence menyimpan posisi list saat inspector dibuka/ditutup dan menyediakan Arrow Up/Down, Enter, Escape, serta `/` untuk keyboard triage.
- Unread/deferred sections dirender per artifact dari `coverage_manifest`, termasuk locator, chunk, dan alasan defer bila tersedia.
- Item unresolved selalu memiliki fallback yang eksplisit untuk owner, state, linked object, dan next action sehingga tidak tampil sebagai row tanpa aksi berikutnya.

Acceptance:

- Update context dapat dibuka dari semua breakpoint tanpa scroll melewati result list.
- Setiap unresolved item mempunyai owner, state, linked object, dan next action.

### U6 · Formal Report hardening — P0

**Re-audit:** read-only report dan metadata sudah tersedia. Acceptance keterbacaan, snapshot DFD visual, ukuran dokumen, dan sticky mobile dibuka kembali pada UX-R02/UX-R07. Klaim contrast/mobile berikut merupakan catatan implementasi terdahulu yang belum terbukti lulus pada tampilan sekarang.

- [x] Jadikan report read-only dan pindahkan inline finding update ke Findings Workspace.
- [x] Lengkapi DFD snapshot visual; revision, methodology, source manifest, dan run provenance sudah tersedia dan diregenerasi dari revision metadata.
- [x] Tampilkan scored/deferred summary dan unresolved blockers tanpa misleading zero risk.
- [x] Tambahkan draft/signed/superseded revision dan approval history.
- [x] Tuntaskan collapse/lazy sections dan full appendix print; pagination dan export data tersedia, default web report bounded, dan appendix tetap tersedia untuk export/print.
- [ ] Tuntaskan mobile sticky navigation dan contrast; semantic headings/back-label sudah diperbaiki, tetapi 36 target axe dynamic contrast masih memerlukan manual visual review.

#### Implementasi U6

- Report hanya menjadi projection read-only. Status finding tidak lagi diubah dari report; row mengarahkan pengguna ke Findings Workspace dengan selection dan route state yang sama.
- Metadata formal menampilkan report revision, canonical DFD revision/layout revision/semantic hash, analysis run, risk methodology, source manifest, dan approval state.
- Risk summary membedakan scored, deferred/needs-context, dan total. Jika `0 scored + N deferred`, UI menampilkan assessment deferred secara eksplisit dan risk pills tidak menampilkan kesan “clean”.
- Snapshot draft dan signed disimpan di `report_revisions/<project_id>`. Signed snapshot tidak dapat ditimpa. Perubahan persisted berikutnya menghasilkan state `superseded` pada current report dan revision baru.
- Sign-off hanya dapat dilakukan jika unified quality gate siap. Approval history menyimpan actor, timestamp, note, report revision, DFD revision, analysis run, dan source manifest.
- Web report memakai bounded pagination untuk boundary, threat, control, test, gap, dan assumption. Export Markdown/CSV/JSON memakai `scope=all` sehingga full appendix tetap tersedia.
- Mobile report memperbaiki wrapping topbar action, sticky TOC, overflow, semantic `h1`/`h2`, accessible back label, serta contrast pada metadata/status formal.

Acceptance evidence:

- Tidak ada `.report-status-select` atau inline mutation pada report; review diarahkan ke `findings.html`.
- Signed snapshot tersedia melalui `/api/projects/{id}/report/revisions/{revision_id}` dan endpoint mengembalikan snapshot immutable.
- Threat row menampilkan DFD revision aligned/stale secara eksplisit; metadata formal menampilkan canonical revision yang menjadi basis report.
- Mobile Chromium smoke test pada 390×844 memverifikasi report read-only, pagination bounded, provenance metadata, route Findings, dan tanpa horizontal overflow.

Acceptance:

- Report draft tidak mengubah canonical finding/control/test secara langsung.
- Signed report immutable dan dapat direproduksi dari revision metadata.
- Report menampilkan DFD revision yang sama dengan finding references.
- `0 scored + N deferred` tidak pernah tampil sebagai “tidak ada risiko”.
- Default mobile report tidak merender dokumen puluhan ribu px sekaligus.

### U7 · Accessibility, responsive, and usability validation — P0 release gate

- [x] Tuntaskan automated semantics/labels/focus order; initial labels, heading, canonical shell, inspector/sidebar focus lifecycle, dan mobile workflow sudah tervalidasi. Screen-reader/manual contrast review tetap menjadi sign-off evidence.
- [x] Lulus automated accessibility checks dan journey keyboard-only pada scope release gate; axe 24/24 page/viewport dan workspace keyboard journey lulus Paket G. Screen-reader/manual review masih terbuka.
- [x] Jalankan Playwright layout/screenshot pada 390, 768, 1280, dan 1440 px; hasil eksekusi bukan otomatis lulus acceptance.
- [ ] Uji minimal satu peserta novice dan satu expert; belum ada bukti sesi manusia.

**Status: AUTOMATED CORE PASS — FORMAL MANUAL SIGN-OFF PENDING.** M6 memperluas gate ke workflow/sidebar state, Model sheet, filter/inspector, recovery, deferred report, dan large fixture. Tidak ada overflow/fixed overlay pada state yang diuji; screen-reader/manual contrast review dan studi novice/expert tetap menjadi prasyarat formal.

#### Implementasi U7

- `frontend/analysis.html` memberi accessible name pada tombol kembali yang hanya berisi ikon dan pada input file artifact; ikon dekoratif ditandai `aria-hidden`.
- `frontend/js/sidebar.js` menyelaraskan drawer mobile dengan focus order: sidebar yang tertutup diberi `inert` dan `aria-hidden`, lalu keduanya dilepas saat drawer dibuka. Fokus keyboard tidak lagi masuk ke navigasi yang secara visual berada di luar viewport; Escape/outside-close mengembalikan fokus ke toggle dan Tab dibatasi di drawer.
- `frontend/js/focus-manager.js` menjadi shared contract untuk inspector: desktop memakai labeled `region` nonmodal, mobile memakai labeled `dialog` modal dengan background inert, focus trap Tab/Shift+Tab, dan focus return ke row pemicu.
- `frontend/js/analysis.js` menyatukan trace DFD dengan canonical flow/threat relation, menyediakan link langsung ke Findings, dan memastikan inspector model dapat ditutup dengan Escape pada mobile. Accessible DFD outline memakai action berbasis ID canonical, bukan teks statis.
- `frontend/js/findings.js`, `frontend/js/action-plan.js`, dan `frontend/js/evidence.js` memakai roving tabindex pada listbox, ArrowUp/Down untuk masuk/berpindah row, Enter untuk membuka inspector, serta Escape/Close untuk kembali ke posisi list.
- `frontend/js/ui-state.js` menyediakan `bindProjectLinks()` sehingga navigasi lintas workspace sudah memiliki `id` project sebelum request async selesai; sync setelah report tetap memperkaya `run` dan selection.
- `frontend/js/report.js` membuat DOM id row report unik walaupun area/label assumption atau gap berulang, sehingga anchor, label, dan navigasi section tidak bertabrakan.
- `tests/test_u7_accessibility.js` menjadi release-gate harness Playwright/Chromium. Audit otomatisnya memeriksa accessible name untuk interactive controls, duplicate id, referensi ARIA yang hilang, overflow horizontal, fokus keluar viewport, sticky/fixed overlay aktual berdasarkan hit-test, page/console error, serta screenshot pada matrix viewport. `tools/u7_release_gate.js` menambahkan axe-core strict gate; `tools/u7_package_b_gate.js` menguji action mobile, select naming, target size, heading, dan overflow; `tools/u7_package_c_gate.js` menguji state inspector/sidebar/context dengan keyboard Chromium. Screenshot disimpan ke temporary directory agar tidak membawa isi dokumen ke repository.
- Keyboard journey mencakup review boundary → finding untuk novice dan DFD → finding → action inspector untuk expert. Harness menunggu initializer async dan route contract siap sebelum melanjutkan, sehingga hasil tidak dipengaruhi state `Loading…` sementara.

#### Bukti U7 historis (2026-09-23)

- `node tests/test_u7_accessibility.js` dilaporkan lulus pada **24 kombinasi** untuk custom checks terbatas. Harness tidak memakai engine yang mengklasifikasi critical/serious; tidak mengukur contrast, dan pemeriksaan fokus programatiknya belum membuktikan keyboard-only journey atau bebas overlay di state inspector terbuka.
- Chromium screenshot matrix tersedia pada temporary directory `/var/folders/8k/0bq1js2d7ql4q5k5txckhwvr0000gn/T/u7-visual-uS2vTi` dan telah dilakukan visual spot-check untuk Model mobile serta Report desktop.
- Fixture `Hacktiv8 Commerce`: durasi skrip berlabel novice **157 ms** dan expert **30.708 ms**. Timer novice tidak meliputi boundary review. Skrip expert menunggu selector link yang tidak tersedia, fallback ke navigasi Action Plan, lalu memilih row pertama; tidak menguji identitas relasi end-to-end. Angka ini tidak digunakan sebagai evidence acceptance manusia atau traceability yang benar.
- Catatan ini adalah bukti historis sebelum M6 dan tidak menjadi release verdict tunggal; M6 adalah gate terbaru untuk stateful shell/journey.

#### Bukti Paket G (2026-09-24)

- `npm run u7:package-g` menggunakan Playwright Chromium pada **6 route × 4 viewport = 24 kombinasi** (390, 768, 1280, 1440 px). Semua route memiliki heading utama, tidak ada horizontal overflow, blank action, page error, atau failed API request. Screenshot 390/1440 tersedia sebagai artefak temporary run.
- DFD workspace lulus kontrak first viewport: canvas terukur `width=772`, `height=679`, intersection viewport `630.8 px` pada 1440×900, Fit tidak menghasilkan overlap node, dan accessible outline memiliki node/flow yang dapat dibuka.
- Findings, Action Plan, dan Evidence lulus keyboard-only search → row → inspector → Escape → focus return pada mobile. Progressive filter menjaga focus search, zero-match state menjelaskan langkah berikutnya, dan advanced filters hanya dibuka ketika diminta.
- Guided boundary/finding review menampilkan bahasa non-teknis dan pilihan `Belum tahu`; context/source disclosure, report appendix, dan document-first onboarding juga lulus pada Chromium.
- Synthetic exact-ID trace lulus: `flow-checkout-request → threat-stride-001 → control-input-integrity → test-replay-checkout`. Check memakai canonical ID dan URL selection, bukan urutan row atau kemiripan label.
- `npm run u7:baseline` lulus **24/24 axe page/viewport**, 0 violation, 0 serious/critical. Re-run Paket C lulus 6/6 journey. Ini adalah bukti automated Chromium, bukan pengganti studi manusia atau screen-reader review.

Acceptance:

- [x] Tidak ada critical/serious automated accessibility violation — **axe 24/24 page/viewport lulus Paket G; screen-reader review tetap manual/pending**.
- [x] Tidak ada horizontal overflow atau sticky overlay yang menutupi focused item — M6 matrix dan Model sheet/open-state check lulus; fixed occluder **0** dan horizontal overflow **0** pada 24 route×viewport.
- [ ] Novice menyelesaikan guided boundary/finding review tanpa bantuan istilah teknis — menunggu studi peserta.
- [x] Synthetic Chromium trace DFD → finding → control → test memakai exact ID dan lulus Paket G; **batas ≤60 detik untuk expert manusia masih menunggu studi peserta**.

### U8 · Performance and polish — P2

- [ ] Lazy-render page dan detail panel; jangan membangun seluruh hidden tab DOM.
- [ ] Pagination/virtualization untuk list besar.
- [ ] Saved views, keyboard shortcuts, dan shareable filters.
- [ ] Optimalkan DFD render, focus, dan resize.

Acceptance:

- Initial overview hanya mengambil data summary yang dibutuhkan.
- Interaksi filter/detail terasa instan pada corpus besar.
- Browser Back/Forward mempertahankan route, filter, dan selected item.

## 10. Playwright acceptance journeys

1. **Novice first review**: Overview → next action → review boundary → return to updated Overview.
2. **Expert traceability**: search finding → open primary DFD flow → inspect control → open executable test.
3. **Partial analysis**: stage gagal → previous results tetap terlihat → affected retry jelas → state tidak tercampur.
4. **Evidence resolution**: open gap → add evidence/defer → readiness count dan sign-off gate berubah konsisten.
5. **Mobile DFD**: open model → fullscreen canvas → select flow → bottom-sheet detail → back tanpa kehilangan selection.
6. **Keyboard-only**: navigate lifecycle, filters, list, detail, status update, dan close inspector.
7. **Large corpus**: ≥200 findings, ≥100 controls, ≥200 tests tanpa page height ekstrem atau render freeze.
8. **Draft report**: open report → pahami scored/deferred state → inspect DFD revision → jump ke unresolved finding di workspace.
9. **Signed report**: sign revision → ubah project context → pastikan signed snapshot tetap immutable dan draft baru berstatus stale/superseding.
10. **Report search**: cari istilah lintas section → lihat match reason → jump ke result → clear search tanpa kehilangan section.
11. **Mobile report**: search/section selector tidak overlap, focused heading terlihat, dan section aktif sinkron dengan deep link.

## 11. Success metrics

- Next action ditemukan ≤10 detik oleh pengguna baru.
- ≥80% guided tasks selesai tanpa kembali ke Dashboard atau membuka Report untuk orientasi.
- DFD visible above the fold pada desktop workspace.
- Default page tidak lebih dari 3 viewport height di luar virtualized/paginated list.
- Maksimum satu primary CTA dan dua secondary actions per first viewport.
- Expert traceability DFD → finding → control → test ≤60 detik.
- 100% expandable rows keyboard-operable.
- 0 critical/serious accessibility violations pada release gate.
- 0 horizontal overflow pada viewport target.
- Report first view menjelaskan scored/deferred assessment tanpa interpretasi “zero risk” yang keliru.
- Signed report dapat direproduksi dari report revision, DFD revision, source manifest, dan methodology version.
- Mobile sticky navigation memakai ≤20% tinggi viewport.

## 12. Risiko implementasi dan guardrail

- **Risiko kehilangan informasi:** gunakan progressive disclosure dan trace links; jangan menghapus data audit.
- **Risiko state antar-page tidak sinkron:** canonical report tetap source of truth; filters/selection hanya presentation state.
- **Risiko route migration:** pertahankan redirect dari hash lama seperti `#analysis-stride` menuju route/filter baru.
- **Risiko regressi recovery:** Overview wajib memakai persisted run state dan previous validated result yang sama dengan backend.
- **Risiko novice/expert bercabang:** jangan membuat dua hasil analisis; sediakan guided view dan compact view di atas data yang sama.
- **Risiko terlalu banyak page:** lifecycle navigation harus selalu terlihat dan menyediakan next/previous step serta breadcrumbs.
- **Risiko report dan workspace kembali bercampur:** report bersifat read-only; semua edit diarahkan ke workspace domain dan menghasilkan draft revision baru.
- **Risiko signed output berubah diam-diam:** snapshot yang signed harus immutable dan selalu menampilkan provenance/revision.

## 13. Definition of done

Revamp dianggap selesai ketika pengguna dapat memahami readiness, memperbaiki canonical DFD, meninjau finding, menentukan control, mengeksekusi test, dan mencapai sign-off tanpa harus membaca seluruh data dalam satu halaman—sementara seluruh evidence, uncertainty, mapping, dan audit trail tetap dapat ditelusuri. `report.html` menjadi output formal yang ringkas, read-only, revision-aware, menyertakan DFD provenance, dan menghasilkan signed snapshot yang dapat direproduksi.

## 14. Laporan tinjauan UI/UX terbaru

### 14.1 Kesimpulan dan goal

**Aplikasi sudah memiliki pembagian workspace yang masuk akal, tetapi belum memenuhi release gate aksesibilitas dan kemudahan penggunaan.** Kendala utamanya adalah informasi penting yang sukar dibaca, tindakan mobile yang kehilangan label, detail yang menutup fokus, dan relasi objek yang tidak dapat diikuti secara konsisten. Memisahkan halaman saja belum membuat tugas pengguna lebih mudah.

Goal perbaikan: pengguna dapat memahami status model, menemukan tindakan berikutnya, menelusuri DFD → finding → control → test, dan memahami ketidakpastian tanpa harus membaca seluruh report atau mengingat ID objek. Pengguna awam mendapat panduan keputusan; expert mendapat akses cepat ke evidence dan relasi yang sama.

Fondasi yang perlu dipertahankan:

- Overview, Model, Findings, Action Plan, Evidence, dan Report sudah terpisah; tidak perlu menambah page utama untuk menyelesaikan temuan saat ini.
- Findings menggabungkan STRIDE/LINDDUN dan sudah memisahkan scenario severity dari final risk.
- Controls dan Tests sudah mempunyai list-detail, filter, dan tautan balik di sebagian inspector.
- Context editor sudah memakai native dialog; ingestion coverage dan unread/deferred sections sudah tersedia.
- Report sudah read-only terhadap finding dan mempunyai metadata revision/source serta aksi snapshot/sign-off.
- Typed selection dan URL state, escaped rendering, serta preserved-result state menjadi fondasi yang harus tetap konsisten selama revisi desain.

Deliverable audit ini adalah requirement dan rencana perbaikan. Tidak ada perubahan kode aplikasi, rerun analisis LLM, atau keputusan review pada project produksi yang dilakukan untuk audit ini.

### 14.2 Metode, batas bukti, dan sumber

| Metode | Cakupan yang dilakukan | Batas kesimpulan |
|---|---|---|
| Inspeksi kode | HTML, CSS, JS workspace; wizard; sidebar; route state; harness U7 | Menemukan perilaku yang diimplementasikan; bukan bukti semua state sudah dijalankan |
| Browser Playwright | Enam workspace, project Hacktiv8 Commerce, 390/768/1280/1440 × 900 | Satu project yang sudah berisi data; bukan benchmark semua ukuran corpus |
| Axe-core 4.10.3 | 12 state halaman awal: enam workspace × 390/1440; tags `wcag2a`, `wcag2aa`, `wcag21aa`, `wcag22aa` | Temuan otomatis; `incomplete` tetap memerlukan review, bukan dianggap pass |
| Interaksi terarah | Buka evidence/finding inspector, Shift+Tab, pilih flow, periksa link, scroll Report | Tidak menyimpan review, upload, sign-off, atau mengubah data threat |
| Visual | Screenshot Report 1440 dan Model 390; pengukuran posisi kanvas, list, sticky bar, font | Bukan pixel-diff regression dengan baseline yang disetujui |
| Inspeksi tambahan | Dashboard, New Project, Settings pada desktop dan source terkait | Belum full responsive/a11y matrix untuk ketiga page ini |
| Usability manusia | **Belum dilakukan** | Keberhasilan novice, expert, dan batas waktu manusia tetap belum tervalidasi |

Tidak dilakukan sertifikasi WCAG, pengujian screen reader, atau pengujian signed-report lifecycle pada audit ini. Angka di bawah adalah observasi browser tanggal 2026-09-23; hasil dapat berubah bersama isi project/font/state UI. Tidak ditemukan overflow horizontal pada **document** dalam matrix layout; hal itu tidak berarti kanvas internal, sticky layer, dan nested scroll sudah nyaman dipakai.

Capture lokal pendukung: `.playwright-mcp/ux-review-report-1440.png` dan `.playwright-mcp/ux-review-model-390.png`. File ini berada pada folder tooling yang di-ignore; bukti tekstual penting sudah disalin ke tabel audit agar tidak bergantung pada keberadaan screenshot lokal. Untuk gate implementasi, pindahkan capture sintetis dan output mesin ke artifact CI yang dapat ditelusuri.

Praktik yang menjadi rujukan:

1. [WCAG 2.2 quick reference](https://www.w3.org/WAI/WCAG22/quickref/): pemetaan semantics, keyboard, name/role/value, dan status messages. Gunakan criterion yang relevan sebagai acceptance aksesibilitas.
2. [Contrast minimum](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html): teks biasa ≥4,5:1, teks besar sesuai definisi WCAG ≥3:1. Ukuran font kecil di aplikasi tidak mendapat pengecualian teks besar.
3. [Target size minimum](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html): target 24×24 CSS px atau memenuhi pengecualian seperti spacing. Target produk 44×44 untuk aksi sentuh utama adalah keputusan desain, bukan klaim minimum AA selalu 44 px.
4. [Focus not obscured](https://www.w3.org/WAI/WCAG22/Understanding/focus-not-obscured-minimum.html): fokus tidak boleh seluruhnya tersembunyi oleh konten buatan aplikasi. Gate produk di dokumen ini lebih ketat: label dan indikator fokus tugas utama harus terlihat penuh.
5. [Reflow](https://www.w3.org/WAI/WCAG22/Understanding/reflow.html): evaluasi lebar ekuivalen 320 CSS px; diagram dapat memerlukan ruang dua dimensi, tetapi toolbar, teks, form, dan navigasi tetap perlu reflow.
6. [WAI-ARIA modal dialog](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/): fokus masuk dialog, Tab tetap di dalamnya, Escape menutup, dan fokus kembali ke pemicu. Terapkan jika inspector mobile memang berperilaku modal.
7. [WAI-ARIA listbox](https://www.w3.org/WAI/ARIA/apg/patterns/listbox/): gunakan pola keyboard sesuai semantics, atau gunakan list dengan tombol/link native apabila item adalah tindakan membuka detail.
8. [Nielsen usability heuristics](https://www.nngroup.com/articles/ten-usability-heuristics/): status yang terlihat, bahasa pengguna, konsistensi, kontrol pengguna, pencegahan kesalahan, dan recognition menjadi dasar rekomendasi interaksi.
9. [WAI: selecting evaluation tools](https://www.w3.org/WAI/test-evaluate/tools/selecting/): automated tooling harus dilengkapi penilaian manusia; hasil nol violation dari satu tool tidak membuktikan seluruh aksesibilitas.

Ukuran seperti canvas ≥55%, first result ≤420 px, dan tugas ≤60 detik di bawah adalah **target produk yang diusulkan**, bukan persyaratan universal WCAG.

### 14.3 Baseline terbaru yang terukur

Semua viewport mempunyai tinggi 900 px. `y` berarti jarak dari atas viewport pada initial load, sebelum pengguna scroll. Angka dibulatkan; panel bisa mempunyai padding sendiri.

| Ukuran | 390 px | 768 px | 1280 px | 1440 px |
|---|---:|---:|---:|---:|
| Tinggi document Analysis | 2.457 | 1.972 | 1.004 | 965 |
| Posisi awal canvas Model (y) | 699 | 503 | 481 | 449 |
| Tinggi elemen canvas Model | 552 | 558 | 678 | 678 |
| Awal rail boundary Model (y) | 603 | 603 | 182 | 182 |
| Posisi awal list Findings (y) | 603 | 399 | 378 | 317 |
| Posisi awal list Action Plan (y) | 837 | 481 | 460 | 399 |
| Posisi awal queue Evidence (y) | 1.427 | 1.176 | 780 | 780 |
| Tinggi document Report | **39.316** | 21.467 | 21.376 | 19.196 |
| Overflow document horizontal | Tidak | Tidak | Tidak | Tidak |

Interpretasi yang harus digunakan saat membuat acceptance:

- Canvas desktop 1440 mempunyai tinggi CSS 678 px, tetapi bagian yang masuk viewport awal hanya sekitar `900 − 449 = 451 px` atau **50,1% viewport**, belum mencapai 55% area terlihat. Tinggi elemen tidak sama dengan area kerja yang tersedia tanpa scroll.
- Pada mobile, kanvas baru dimulai sekitar y=699, sementara rail boundary sudah menutup area y=603–900. Hit-test pada posisi (180,750) mengenai rail. Bagian awal kanvas yang masuk viewport terhalang.
- Shell kanvas mobile mempunyai lebar client sekitar 358 px tetapi scroll width 760 px. Ini bukan overflow document; tetap perlu membuktikan Fit/selection dapat dipahami dalam area tersebut.
- Toolbar/filter menunda daftar tindakan: Action Plan mobile hampir satu viewport penuh sebelum list; queue Evidence lebih dari satu viewport di bawah header.
- Pagination Report sudah membatasi jumlah row per section, tetapi semua section dan isi panjangnya masih dirender bersama. Hasilnya tetap puluhan ribu piksel.

### 14.4 Hasil accessibility engine

Angka pada kolom contrast/target adalah **jumlah node DOM yang dilaporkan**, bukan jumlah vulnerability atau jumlah criterion unik. Angka desktop/mobile tidak boleh dijumlahkan sebagai masalah unik.

| Page | Contrast serious 390 / 1440 | Temuan lain | Kesimpulan |
|---|---:|---|---|
| Analysis | 28 / 40 | `select-name` critical: `#artifact-type-select`, satu node pada masing-masing viewport | Gagal gate |
| Model | 29 / 36 | `target-size` serious: dua flow buttons desktop | Gagal gate |
| Findings | 12 / 25 | Perlu pemeriksaan manual fokus/semantics inspector | Gagal gate |
| Action Plan | 18 / 30 | Perlu pemeriksaan manual state control/test terbuka | Gagal gate |
| Evidence | 12 / 20 | Fokus tertutup inspector pada interaksi mobile, di luar audit initial-state | Gagal gate |
| Report | 557 / 560 | `target-size` serious: 40 node pada mobile | Gagal gate |

Contoh terverifikasi: metadata formal memakai teks putih di luar hero navy, di atas surface terang. Axe melaporkan label metadata sekitar **1,04:1**, value sekitar **1,06:1**, source/revision summary sekitar **1,32:1**. Root token `--text-faint: #7FA6B8` juga dipakai untuk informasi kecil di surface terang.

Daftar `incomplete` meliputi contrast dan sebagian `aria-prohibited-attr`; ini belum diklasifikasikan sebagai kegagalan pasti. Reviewer harus menilai kasusnya, bukan meniadakan rule agar gate terlihat hijau.

### 14.5 Mengapa bukti U7 sebelumnya tidak cukup

Sumber: `tests/test_u7_accessibility.js`.

- Accessible name dihitung dari `textContent` label tanpa algoritma accessible-name standar. Label yang membungkus search sekaligus tombol bisa lolos walaupun relasi programatik belum benar. `#artifact-type-select` terlewat karena fallback text option dianggap nama.
- Tidak ada contrast test atau engine severity, sehingga klaim “0 critical/serious” tidak berasal dari pengukuran yang sesuai.
- Pemeriksaan fokus memakai `.focus()` dan `scrollIntoView()` pada maksimal 80 elemen; tidak membuktikan urutan Tab alami. Fokus ke elemen inert bisa gagal tanpa assertion bahwa `activeElement === target`.
- Hit-test center dan filter `z-index >= 20` dapat melewatkan clipping, sticky header kecil, stacking context, atau fokus yang hanya tertutup sebagian.
- Journey novice menggunakan `.click()`/`.focus()`; kegagalan membuka boundary ditelan dengan `.catch(() => {})`, dan rail yang sudah visible cukup untuk pass. Timer mulai setelah langkah boundary.
- Journey expert mencari `.finding-action-link, .finding-control-link` yang belum ada, lalu fallback ke sidebar. Timeout ini menjelaskan sekitar 30 detik waktu skrip; tidak berarti pengguna berhasil melakukan trace secepat itu.
- Control dipilih dari row pertama, tanpa assertion bahwa threat/flow-nya sama dengan selection awal. Nama section dan keberadaan link tidak cukup untuk membuktikan integritas trace.
- Screenshot disimpan, tetapi tidak dibandingkan dengan baseline visual yang disetujui. Matrix audit halaman awal juga belum mencakup open inspector, loading, error, dan signed snapshot.
- Harness default menggunakan ID project lokal dan folder `tests` di-ignore. Reproduksibilitas lintas mesin/CI belum terjamin tanpa fixture versioned dan test yang benar-benar masuk repository.

Hasil lama tetap berguna sebagai smoke check. Status acceptance release harus mengacu pada bukti baru dan protokol §20.

## 15. Backlog prioritas dan requirement

### 15.1 Cara membaca prioritas

**P0**: menghalangi tugas utama, mengaburkan informasi untuk keputusan, atau gagal gate aksesibilitas yang sudah disepakati. Tutup sebelum menyatakan release U7 lulus. **P1**: tugas masih mungkin tetapi memerlukan pencarian/scroll/pengetahuan domain berlebih atau rawan salah keputusan. **P2**: efisiensi, konsistensi, dan skala setelah jalur utama dapat diandalkan.

Ukuran S/M/L adalah kompleksitas relatif, bukan janji durasi. Owner adalah peran yang perlu ditetapkan tim, bukan orang yang telah ditugaskan.

| ID | Pri. | Masalah | Outcome | Owner utama | Ukuran |
|---|---|---|---|---|---|
| UX-R01 | P0 | Gate dan bukti U7 memberi kesimpulan terlalu kuat | Bukti pass dapat direproduksi dan sesuai acceptance | QA + Frontend | M |
| UX-R02 | P0 | Contrast rendah dan teks terlalu kecil | Status/evidence/provenance terbaca | Design + Frontend | M |
| UX-R03 | P0 | Aksi mobile kosong/tidak dikenal | Semua aksi utama dapat ditemukan | Frontend | S |
| UX-R04 | P0 | Fokus inspector/sidebar tidak mengikuti overlay | Semua tugas dapat diselesaikan keyboard | Frontend + QA | M |
| UX-R05 | P0 | Trace DFD → finding → control → test putus | Pengguna mengikuti objek yang sama tanpa mencari ulang | Frontend + Backend | M |
| UX-R06 | P0 | Coverage/rail mengalahkan canvas | Diagram langsung dapat dibaca dan dipakai | Frontend + Design | M |
| UX-R07 | P0 | Report terlalu panjang, sticky overlap, snapshot kurang jelas | Report ringkas, terbaca, revision-aware | Frontend + Backend | L |
| UX-R08 | P1 | Filter dan queue summary mendorong list ke bawah | Pengguna mulai bekerja dari first viewport | Design + Frontend | M |
| UX-R09 | P1 | Guided review belum menjadi tugas yang bisa diikuti awam | Keputusan yang benar tanpa jargon wajib | Product/UX + Frontend | M |
| UX-R10 | P1 | Navigasi/state/error belum konsisten pada transisi | Pengguna tidak kehilangan konteks atau pekerjaan | Frontend + Backend | M |
| UX-R11 | P1 | Evidence workflow masih berpusat pada form/coverage | Pertanyaan → sumber → keputusan terhubung | Frontend + Backend | M |
| UX-R12 | P1 | Onboarding meminta istilah teknis sebelum dokumen | Informasi minimal cukup untuk mulai dengan uncertainty eksplisit | Product/UX + Frontend | M |
| UX-R13 | P1 | Semantics list, label, dan heading belum lengkap | Screen reader dan keyboard mengikuti struktur yang jelas | Frontend + QA | M |
| UX-R14 | P1 | Report search/deep link belum menemukan objek di luar page aktif | Hasil pencarian langsung membuka target yang benar | Frontend | M |
| UX-R15 | P2 | Pola UI/CSS dan render list terduplikasi | Perubahan konsisten dan corpus besar tetap responsif | Frontend | L |

### UX-R01 · P0 — Jadikan release gate berbasis bukti

**Masalah dan dampak:** lihat §14.5. False pass membuat masalah yang nyata dinyatakan selesai dan meningkatkan risiko regresi antar-milestone.

**Requirement:**

- R01.1: pisahkan hasil automated a11y, keyboard-only, visual regression, relasi data, dan studi peserta; masing-masing mempunyai status sendiri.
- R01.2: gunakan fixture sintetis versioned dengan expected `flow_id → threat_id → control_id → test_id`, satu deferred case, satu unassigned control, dan lebih dari satu page hasil.
- R01.3: gunakan axe-core versi terkunci; simpan rule, impact, selector, state, viewport, engine version, dan jumlah node. Rule suppression hanya melalui rationale yang direview.
- R01.4: assert page data siap, bukan hanya container HTML ada; jangan menelan kegagalan langkah wajib atau fallback ke row pertama.
- R01.5: keyboard journey tidak memakai `.click()`/`.focus()` untuk melompati navigasi setelah task dimulai. Setup test boleh mengatur URL dan fixture awal.
- R01.6: simpan hasil CI tanpa teks dokumen produksi. Test dan fixture harus dilacak git; runner harus gagal bila fixture/dependensi tidak tersedia.

**Acceptance:** test sengaja gagal ketika label select dilepas, focus terkunci di belakang sheet, relasi control salah, atau source metadata tidak terbaca. Seluruh gate memiliki bukti sendiri. Human success tidak diisi memakai waktu skrip.

**Dependensi:** bisa dimulai pertama; kelulusan penuh menunggu UX-R02–R07/R13. Bukti penutupan: artifact test, fixture revision, baseline visual, dan laporan peserta.

### UX-R02 · P0 — Keterbacaan dan hierarchy warna

**Bukti awal dan remediasi:** §14.4, `frontend/css/style.css`, blok formal report dalam `frontend/css/pages.css`, struktur `.report-formal-meta` pada `report.html`. Sebelum Paket B, value putih berada di surface terang karena metadata bukan anak `.report-header`; Paket B memindahkannya ke surface terang dengan teks gelap dan token contrast yang lebih kuat.

**Reproduksi:** buka Report desktop, baca metadata di bawah hero; periksa juga caption boundary dan badge/list pada workspace lain.

**Requirement:**

- R02.1: definisikan token text primary/secondary/disabled dan pasangan surface terang/gelap. Metadata formal memakai card terang dengan teks gelap atau benar-benar berada di container gelap.
- R02.2: contrast normal ≥4,5:1; indikator visual kontrol dan fokus yang relevan ≥3:1. Tetap pakai label status, bukan warna saja.
- R02.3: target desain body 14–16 px desktop, 16 px mobile; metadata yang perlu dibaca 12–14 px. Ukuran ini target produk; WCAG tidak menetapkan satu minimum font universal.
- R02.4: batasi badge menjadi informasi keputusan: state evidence, final risk, dan status review. ID/hash panjang berada pada provenance detail dengan copy action, bukan mengambil lebar utama.
- R02.5: hierarchy judul → status/keputusan → deskripsi → detail pendukung. Text muted tidak digunakan untuk alasan blocker penting.

**Acceptance:** tidak ada serious contrast violation pada halaman awal dan inspector terbuka; reviewer dapat membaca revision, deferred state, dan alasan sign-off tanpa highlight teks. Uji teks 200% dan text spacing tidak memotong informasi.

### UX-R03 · P0 — Aksi mobile harus terlihat dan bernama

**Bukti awal dan remediasi:** `frontend/css/style.css` pada ≤640 px sebelumnya menetapkan `.topbar-actions .btn { font-size: 0; width: 38px; ... }`, sehingga action menjadi kotak kosong pada 390 px. Paket B menghapus aturan tersebut, mempertahankan label, wrapping, dan target minimum 40 px; custom Chromium gate menguji ulang kondisi ini sampai 320 px.

**Requirement:**

- R03.1: hilangkan aturan global yang menyembunyikan seluruh label. Tentukan tampilan mobile per action.
- R03.2: tampilkan satu action utama dengan label pendek; secondary actions masuk `More` yang dapat dibuka keyboard. Ikon tanpa teks hanya untuk aksi yang jelas, dengan accessible name.
- R03.3: target sentuh utama 44×44 px; target lain memenuhi 24×24 px/spacing yang relevan. Label dan loading state tidak berubah menjadi area kosong.
- R03.4: header compact tetap menyebut project dan workspace; tidak perlu baris kosong agar action muat.

**Acceptance:** pada 390 dan 320 CSS px tidak ada tombol aktif kosong, teks/action tidak clipped, dan Update context bisa ditemukan tanpa scroll. Disabled Sign report mempunyai alasan yang dapat dibaca tanpa hover.

### UX-R04 · P0 — Inspector dan focus lifecycle

**Bukti:** `openEvidenceItem()` memfokuskan row setelah membuka fixed inspector. Browser mobile mengonfirmasi titik tengah focused row tertutup. Inspector Findings tidak mempunyai dialog role; Shift+Tab dari tombol close keluar ke row di belakang sheet. Sidebar tertutup sudah inert, tetapi perilaku saat terbuka belum mengelola modal focus/return secara lengkap.

**Requirement:**

- R04.1: desktop inspector nonmodal memakai landmark berlabel; pengguna dapat berpindah list/detail dan kembali ke row yang sama.
- R04.2: mobile inspector yang menutupi workspace diperlakukan sebagai dialog modal: nama, fokus awal pada heading/close, background inert, Tab/Shift+Tab terkendali, Escape/Close mengembalikan fokus.
- R04.3: sheet hanya muncul setelah selection; membuka detail tidak mengubah posisi scroll list. Tutup sheet tidak membuang filter.
- R04.4: sidebar mobile mempunyai model interaksi eksplisit, termasuk penutupan, Escape, dan pengembalian fokus ke toggle; jangan menambah focus trap pada panel desktop yang nonmodal.
- R04.5: sticky header internal tidak boleh menutup input/action saat Tab atau membuka validation error. Hitung offset dari ukuran aktual bila diperlukan.

**Acceptance:** keyboard dapat membuka/membaca/mengisi/membatalkan detail pada tiga workspace; focus ring dan label terlihat. Uji open sheet + Shift+Tab + Escape + reopen, viewport resize ketika terbuka, serta browser Back. Jangan memakai programmatic scroll untuk menutupi bug pada pengujian keyboard alami.

### UX-R05 · P0 — Traceability harus membawa objek yang sama

**Bukti:** `modelFindingLinksHtml()` di `analysis.js` mengarah ke `report.html`; inspector Findings memiliki `Recommended control` sebagai teks tetapi nol link `action-plan.html`. `openActionItem()` mencari hanya di `actionVisible`, sehingga test terkait yang terfilter keluar berpotensi tidak dapat dibuka dari control. Dua perilaku pertama terkonfirmasi browser; kasus filter terakhir memerlukan regression case khusus.

**Requirement:**

- R05.1: flow/node inspector → Findings Workspace dengan `selected=threat:<id>`, project/run dan referensi model yang sesuai. Report tetap jalur sekunder untuk membaca hasil formal.
- R05.2: finding inspector menampilkan Controls dan Tests terkait sebagai tautan berlabel nama/state, berdasarkan foreign key yang ada; jangan mencocokkan berdasarkan kemiripan nama.
- R05.3: control inspector → test inspector yang tepat, termasuk ketika filter sedang `Controls only`. Target dibuka dengan pemberitahuan bahwa ia di luar filter, atau dengan perubahan filter yang terlihat dan dapat dikembalikan.
- R05.4: setiap detail menunjukkan breadcrumb objek singkat: flow → finding → control → test. Relasi yang tidak ada menampilkan `Belum ditautkan` plus next action, bukan memilih objek lain.
- R05.5: browser Back mengembalikan filter, selected row, dan scroll; link lintas workspace tidak membawa search yang menyebabkan destination kosong tanpa penjelasan.

**Acceptance:** fixture dengan dua flow berbeda, beberapa findings/controls, dan test terfilter harus memverifikasi kesamaan ID tiap perpindahan. Tidak boleh fallback ke sidebar atau row pertama untuk memenuhi test. Setiap hop tersedia dalam satu action dari detail; target expert ≤60 detik diukur terpisah pada peserta.

### UX-R06 · P0 — Canvas menjadi area kerja utama

**Bukti:** pengukuran §14.3, `model.html`, `.model-inspector-rail`, `.diagram-mapping-summary`, `renderGraphCoverageSummary()`. Rail mobile tampil sebelum pengguna memilih objek dan menutupi kanvas; coverage summary mengambil ruang permanen di atasnya.

**Requirement:**

- R06.1: urutan default header → level/toolbar compact → canvas. Coverage detail, daftar validator, inventory, dan semua boundary cards masuk panel yang dibuka sesuai kebutuhan.
- R06.2: tampilkan satu model-health chip dengan jumlah masalah dan `Review`; banner mendesak maksimum dua baris plus `Lihat rincian`.
- R06.3: pada 1440×900 kanvas **terlihat dan tidak tertutup ≥495 px**; target top ≤260 px. Ukur intersection dengan viewport dan occlusion, bukan CSS height saja.
- R06.4: mobile default tidak membuka rail. Tombol `Review batas (N)` membuka queue sheet; pemilihan satu item membuka inspector yang bisa ditutup/di-minimize.
- R06.5: Fit memperhitungkan area canvas aktual dan inspector. Target terpilih tetap terlihat; layout node, label, boundary, serta edge crossing diuji pada fixture standar dan padat.
- R06.6: outline/daftar flow keyboard menyediakan action untuk memilih elemen yang sama dengan canvas; static text alternative saja belum menyamai fungsi interaktif.
- R06.7: bedakan `Batas perlu konfirmasi` dari `Batas terkonfirmasi`; jangan memperbaiki keterbacaan dengan menambah koneksi atau mengubah status semantic tanpa evidence.

**Acceptance:** mobile first viewport memperlihatkan diagram atau tombol fullscreen yang jelas, tanpa sheet otomatis menutupnya. Keyboard dapat memilih flow dan membuka linked finding. Fullscreen/Escape mengembalikan viewport/selection. DFD yang belum valid tetap menampilkan alasan ringkas dan akses ke detail.

### UX-R07 · P0 — Report ringkas dan dapat dipercaya

**Bukti baseline historis:** document height 39.316 px mobile; pada scroll, topbar y=0–113, commandbar y=64–184, TOC y=132–191 saling menimpa. renderFilteredReport() membangun setiap section; pagination tidak mengurangi verbosity setiap row. Metadata revision tersedia, tetapi tampilan utama belum menyediakan snapshot visual DFD. Bukti terkini setelah Paket E dicatat pada §19.2.5.

**Requirement:**

- R07.1: default Executive summary berisi scope, revision, status draft/signed, `scored / deferred`, tiga blocker utama, dan next destination. Appendix collapsed dan di-render on demand.
- R07.2: distribusi risiko hanya untuk scored findings; jika 0 scored, letakkan `Risiko akhir belum dapat disimpulkan` sebelum distribusi dan jangan memakai empat pill kosong sebagai headline.
- R07.3: mobile menggunakan satu bar ringkas `Section + Search + More`; hapus ketergantungan offset 64/132 px yang tidak sesuai header aktual.
- R07.4: summary row hanya judul, state, dampak, primary interaction; bukti panjang dan audit calculation masuk detail. Pagination menjadi pelengkap collapse, bukan pengganti hierarchy.
- R07.5: tambahkan DFD snapshot/caption dari revision yang sama dengan finding references. Snapshot tidak boleh diam-diam menggunakan latest model untuk report lama.
- R07.6: tampilkan revision selector dan aksi baca snapshot signed. State draft, signed, superseded, actor/waktu, serta checksum/provenance dapat ditelusuri; hash teknis tetap pada detail.
- R07.7: export/print appendix lengkap memakai revision dan scope yang jelas; filter web tidak boleh menghilangkan bagian tanpa penjelasan pada export. Jangan menganggap native print otomatis lengkap ketika DOM dipaginate.
- R07.8: report review action tetap membuka workspace domain; membuka report lama tidak boleh memodifikasi canonical results.

**Acceptance:** initial report ≤3 viewport height pada fixture standar dengan appendix tertutup; metadata dan deferred statement terlihat tanpa membaca section lain. Sticky UI target produk ≤20% tinggi mobile dan tidak overlap. Snapshot, threats, controls, tests serta source manifest mempunyai revision-consistency assertion; old signed revision dapat dibaca tanpa mengambil current results sebagai pengganti.

### UX-R08 · P1 — Filter bertahap, daftar lebih cepat terlihat

**Bukti:** Findings mobile list y=603; Action Plan y=837; filter native multi-select selalu expanded. Queue cards dan heading menambah ketinggian sebelum row pertama.

**Requirement:**

- R08.1: search + satu quick filter prioritas + tombol `Filters (N)` menjadi toolbar default. Filter lanjutan berupa checkbox group berlabel pada popover/dialog.
- R08.2: tampilkan active filter chips yang dapat dilepas, jumlah hasil, dan `Reset`. AND antar dimensi, OR di dalam dimensi dijelaskan singkat jika diperlukan.
- R08.3: `All / Needs review / Deferred` menjadi preset Findings; `Controls / Tests / Needs decision` untuk Action Plan. Preset tidak mengubah canonical state.
- R08.4: tidak ada render ulang yang memindahkan keyboard focus saat mengetik. Jika search/filters mengosongkan hasil, jelaskan `0 cocok dari N item` dan reset yang relevan.
- R08.5: list row cukup menampilkan judul, final/deferred risk, state review, primary flow/explicit deferred, owner bila relevan; bukti lengkap berada di inspector.

**Acceptance:** first meaningful row di mobile target y≤420 px pada fixture standar; filter memakai input sentuh yang mudah dan tidak membutuhkan modifier Ctrl/Cmd. Setelah close detail, item dan scroll sama; search/filter membawa expert ke finding dalam ≤2 navigation actions setelah filter diterapkan.

### UX-R09 · P1 — Guided review yang membantu keputusan

**Bukti:** UI saat ini menampilkan `Candidate`, `canonical`, `trust transition`, `needs_context`, Confirm/Reject. Belum ada alur pertanyaan bertahap, progress item, atau bukti peserta awam memahami implikasinya.

**Requirement:**

- R09.1: Overview mengarahkan ke satu tugas: `Periksa 2 batas akses`. Panduan berbasis antrean yang sama dengan expert.
- R09.2: setiap langkah memperlihatkan siapa mengirim, siapa menerima, data apa, mengapa aturan akses mungkin berbeda, dan sumber yang mendukung.
- R09.3: gunakan jawaban `Ya, aksesnya berbeda`, `Tidak`, `Belum tahu`; jelaskan istilah trust boundary sebagai perbedaan aturan akses/kepemilikan. `Belum tahu` mempertahankan unresolved/deferred, tidak melakukan confirm atau reject otomatis.
- R09.4: tampilkan dampak keputusan, alasan yang perlu dicatat, `Simpan & berikutnya`, `Kembali`, dan progress `1 dari N`. Jangan melompat sebelum save terkonfirmasi.
- R09.5: finding review mengajukan `Apa yang mungkin terjadi?`, `Bukti apa yang tersedia?`, `Apa yang perlu dicek?`; status Reviewed tidak dianggap verified vulnerability.
- R09.6: technical detail dapat dibuka dalam konteks dengan pointer/keyboard/touch; tidak bergantung pada tooltip hover saja.

**Acceptance:** minimal satu novice menyelesaikan boundary dan finding review tanpa penjelasan terminologi dari fasilitator, dapat menjelaskan alasan keputusan serta makna deferred, dan tidak mengonfirmasi bukti yang memang tidak tersedia. Studi formatif berikutnya target lima peserta per persona untuk menemukan pola, bukan klaim statistik populasi.

### UX-R10 · P1 — State, navigation, dan recovery yang konsisten

**Bukti:** link project pada Model dipasang setelah fetch report selesai; link HTML awal belum membawa ID. Findings/Action Plan memakai pushState untuk selection, Evidence memakai replaceState. Beberapa load failure hanya menjadi text error/toast. Dukungan popstate sudah ada pada sebagian workspace dan harus dipertahankan.

**Requirement:**

- R10.1: bangun shared project links dari URL tervalidasi sebelum request data. Status loading tidak membuat quick navigation kehilangan project.
- R10.2: kontrak state membedakan selection, filter, run, dan revision. Navigasi umum boleh menghapus selection yang tidak relevan; relation link harus mempertahankan target/return context.
- R10.3: load error menampilkan `Retry load`, last successful data jika ada, waktu/revision, serta destination aman. No project, no report, no matches, dan request failed mempunyai pesan berbeda.
- R10.4: unsaved form mempunyai indikator dan pilihan simpan/buang saat meninggalkan editor. Existing autosave harus menampilkan Saving/Saved/Failed dan mempertahankan input ketika gagal.
- R10.5: concurrent revision conflict harus menampilkan data berubah dan opsi reload/compare; jangan menutup editor seolah save berhasil.
- R10.6: run status dan next CTA mengikuti kondisi: belum analisis, aktif, partial, stale, preserved, complete-but-not-ready, ready-to-sign. Retry hanya tahap terkait dan tidak membuat user mengira preserved results adalah hasil run baru.

**Acceptance:** uji slow API + navigasi langsung, 404/no report, offline/reconnect, refresh/back, filter lama, stale revision, dan save error. Selection tetap menunjuk ID yang sama atau explicit unavailable; tidak diam-diam dipindah ke row pertama.

### UX-R11 · P1 — Evidence sebagai alur penyelesaian pertanyaan

**Bukti:** queue Evidence baru mulai y=1.427 mobile; summary, upload form, dan coverage mendahuluinya. Coverage/owner/state sudah tersedia, tetapi detail sumber dan review bersaing untuk ruang default.

**Requirement:**

- R11.1: default `Needs attention` menampilkan pertanyaan yang memblokir review; Sources/Coverage menjadi subview di halaman yang sama. `Update context` dan `Add source` selalu mudah ditemukan.
- R11.2: unresolved item menampilkan owner/Unassigned, state, objek terkait, alasan relevan, dan satu next action. `Unassigned` adalah pekerjaan belum selesai, bukan dianggap ownership terpenuhi.
- R11.3: dari item pengguna dapat menautkan source evidence atau memilih defer dengan alasan, owner, dan tanggal tindak lanjut bila diperlukan. Unknown tidak boleh berubah resolved hanya karena form disimpan.
- R11.4: coverage card menjelaskan `Dibaca / Belum dibaca / Ditunda` beserta locator/revision dan alasan. Dokumen tanpa hash/coverage legacy diberi `Belum diverifikasi`, bukan 100% processed.
- R11.5: setelah tambah sumber, tampilkan dampak: source masuk, bagian terproses/deferred, context berubah, tahap yang perlu refresh, dan hasil lama yang masih tersimpan.

**Acceptance:** reviewer berpindah dari blocker → pertanyaan → source/locator → keputusan tanpa search ulang. Open context berhasil pada semua breakpoint dan tidak menutup queue. Uji unread section, upload parsial, source diganti, serta deferred yang belum mendapat owner.

### UX-R12 · P1 — Onboarding untuk informasi minimal

**Bukti:** wizard empat langkah meminta description dan setidaknya satu actor sebelum artifact di langkah terakhir; contoh input berisi JWT/HMAC/RBAC/PII. Labels tag input pada beberapa langkah tidak terhubung `for`. `validateStep()` memberi toast tanpa fokus error yang eksplisit. Settings mempunyai beberapa primary actions pada satu document.

**Requirement:**

- R12.1: awal menawarkan `Mulai dari dokumen` atau `Isi ringkasan`; keduanya menuju project model yang sama. Jelaskan minimum yang diperlukan dan estimasi langkah, bukan menjanjikan hasil lengkap dari informasi minim.
- R12.2: pertanyaan awal memakai bahasa pengguna: nama fitur, tujuan, pengguna utama, data penting. `Belum tahu` disimpan sebagai unknown bila kontrak backend mendukungnya; jangan membuat actor/scope palsu untuk melewati validasi.
- R12.3: jika doc upload diperlukan untuk mengisi informasi wajib, proses dalam draft/review state dengan preview hasil ekstraksi; jangan otomatis menganggap semua inferensi confirmed.
- R12.4: error ada di field dan ringkasan, `aria-invalid`/describedby, fokus ke input pertama yang perlu diperbaiki. Next/Back menyimpan draft input selama sesi tanpa mengekspos isi ke telemetry.
- R12.5: konfigurasi engine disajikan lewat status aktif, test connection, dan petunjuk pemulihan. Model name/API key/allowlist tetap technical settings yang tidak wajib dipahami untuk review hasil.

**Acceptance:** novice dapat memulai dari PRD tanpa mengisi istilah teknis yang tidak diketahuinya; app menyatakan missing context secara eksplisit. Keyboard menyelesaikan wizard, error field dapat ditemukan, file error tidak menyebabkan project duplikat.

### UX-R13 · P1 — Semantics dan pola keyboard seragam

**Bukti awal dan status:** Analysis sebelumnya tidak mempunyai h1 dan artifact type select tanpa nama menurut axe; Paket B sudah memperbaiki keduanya. New Project/Settings masih perlu inspeksi heading tambahan. Findings memiliki 30 buttons `role=option` yang semuanya tabbable dalam `role=listbox`; handler hanya mengelola sebagian arrow/Enter. Static accessible model outline belum memberikan action yang setara dengan canvas.

**Requirement:**

- R13.1: satu h1 yang menggambarkan tugas, h2 section, heading detail berlabel; sediakan skip-to-main dan landmark navigasi yang jelas. Ini konvensi struktur produk, bukan klaim jumlah h1 sendiri selalu violation WCAG.
- R13.2: semua input/select/textarea memiliki label eksplisit, help/error terhubung. Accessible name tidak mengandalkan placeholder atau option text.
- R13.3: pilih native list+button untuk item pembuka detail, atau implement listbox penuh dengan roving tabindex/active descendant, selection announcement dan keyboard yang sesuai. Hindari semantics selection yang tidak sesuai tindakan.
- R13.4: shortcut `/` dapat dinonaktifkan/remap atau dibatasi ke container aktif; tidak menangkap typing, contenteditable, maupun interaksi dialog.
- R13.5: loading/result-count/save status memakai live region singkat. Jangan membaca ulang seluruh inspector dengan setiap perubahan kecil.
- R13.6: diagram menyediakan daftar elemen/flow yang dapat dipilih, nama terstruktur sender → receiver + data, dan relasi boundary/evidence/finding yang sama dengan inspector visual.

**Acceptance:** screen reader dapat menemukan tugas utama, field error, list, selection, dialog title, dan save result. Tab tidak melewati puluhan item jika memakai composite listbox. Nama/role/state konsisten pada desktop/mobile. Critical label fix menjadi bagian P0 meskipun perbaikan struktur menyeluruh berada pada P1.

### UX-R14 · P1 — Search dan deep link deterministik

**Bukti:** `reportItemMatches()` menggunakan `JSON.stringify(item)`; hasil dapat cocok karena metadata yang tidak terlihat. `restoreSelectedReportThreat()` hanya mencari row pada page DOM aktif, tidak memilih page containing ID. `reportRowId()` sekarang unik per halaman tetapi berbasis index, sehingga bukan identifier permalink yang stabil antar-sort/filter.

**Requirement:**

- R14.1: indeks field yang dimengerti pengguna; tampilkan match reason/snippet dan kelompok hasil per jenis.
- R14.2: resolve selected ID terhadap corpus/revision, tentukan section/page, render, lalu fokus. Jika terfilter, jelaskan dan tawarkan `Tampilkan item` sambil menyimpan filter asal.
- R14.3: permalink berbasis canonical ID; duplicate label tidak menghasilkan duplicate ID. Index DOM bukan identitas objek.
- R14.4: pisahkan query workspace yang tidak relevan saat berpindah. Query/owner yang berpotensi sensitif tidak masuk telemetry; jelaskan scope link yang dibagikan bila query disimpan pada URL.

**Acceptance:** deep link ke finding ke-25 berhasil pada pagination size 20; Back mengembalikan state awal. Search dari metadata saja menjelaskan alasan match atau memang dikecualikan. Unknown/deleted/historical ID memiliki pesan eksplisit.

### UX-R15 · P2 — Konsistensi komponen dan performa

**Bukti:** sidebar/header/filter/inspector diulang lintas file; CSS mobile generik menimpa workspace-specific actions. Findings, Action Plan, dan Evidence membangun seluruh filtered list melalui `innerHTML`. Ini risiko skala berdasarkan kode; belum ada benchmark corpus besar pada audit ini.

**Requirement:**

- R15.1: definisikan shared shell, action bar, filter group, list row, inspector/dialog, empty/error state, dan status chip dengan kontrak yang sama. Tidak mensyaratkan migrasi framework baru.
- R15.2: desktop compact dan guided presentation memakai data canonical yang sama. Preference presentasi tidak mengubah severity atau evidence state.
- R15.3: pagination/lazy rendering diterapkan berdasarkan ukuran corpus; virtualisasi hanya bila fokus, screen-reader semantics, dan selected row dapat dipertahankan.
- R15.4: ukur input → hasil filter dan buka detail pada fixture ≥200 findings/100 controls/200 tests; target p95 UI lokal ≤200 ms setelah data tersedia. Pisahkan network latency dari render latency.
- R15.5: stable fonts/local assets dan reduced motion pada regression environment; tidak mengandalkan screenshot acak dari temporary directory sebagai baseline.

**Acceptance:** shared fix header berlaku pada semua page tanpa kembali menghasilkan tombol kosong. Corpus besar tidak freeze atau kehilangan selection; ukuran corpus, mesin/browser, dan hasil profiling tercatat sebelum klaim performa dibuat.

## 16. Arsitektur informasi, hierarchy, dan kontrak interaksi

### 16.1 Navigasi yang dituju

Pertahankan enam workspace utama. Nama tampilan disarankan memakai bahasa tugas: **Overview**, **System model**, **Findings**, **Action plan**, **Evidence**, **Report**. Istilah DFD/STRIDE/LINDDUN tetap tersedia sebagai label teknis dan filter. Pilihan bahasa produk perlu diputuskan sekali; contoh copy Indonesia pada dokumen ini adalah spesifikasi makna, bukan instruksi mencampur dua bahasa dalam satu UI.

| Page | Pertanyaan pengguna yang harus terjawab pertama | Primary action menurut state | Informasi yang dibuka belakangan |
|---|---|---|---|
| Overview | Sudah sampai mana, apa yang perlu saya lakukan? | Start / Review next item / Retry affected | Full context, run log, technical counts |
| Model | Siapa mengirim data ke siapa, apa yang perlu dikonfirmasi? | Review next boundary atau inspect selection | Coverage matrix, inventory, editor advanced |
| Findings | Skenario mana yang perlu saya pahami/putuskan? | Review selected finding | Risk calculation, hashes, supporting references |
| Action Plan | Apa yang harus diterapkan atau diverifikasi? | Resolve applicability / Open test / Save review | Full checklist dan evidence instructions |
| Evidence | Informasi apa yang masih dibutuhkan, dari sumber mana? | Resolve selected question / Add source | Full coverage manifest dan parsing diagnostics |
| Report | Apa kesimpulan dan keterbatasan revision ini? | Review blocker / Sign jika ready / Export | Appendix lengkap dan revision provenance |

Selalu tampilkan project identity, current workspace, serta run/revision bila relevan dengan hasil. Gunakan label `Kembali ke Findings` ketika kembali ke sumber trace, bukan generic `Back` yang destination-nya berubah tanpa konteks.

### 16.2 Hierarchy visual dan kepadatan

1. Header: identitas project dan workspace; tinggi target desktop 64–80 px, mobile 56–72 px untuk header utama.
2. Status: satu kalimat outcome + satu tindakan; maksimal tiga blocker awal, sisanya disclosure.
3. Area kerja: kanvas atau list; bukan deretan cards statistik.
4. Inspector: judul, makna, evidence, keputusan, lalu trace links.
5. Detail teknis: revision/hash/score breakdown/coverage grid dalam section yang dapat dibuka.

Gunakan spacing 8/12/16/24 px yang konsisten, border untuk mengelompokkan, dan satu accent utama untuk action. Status P0/Critical tidak memakai styling yang sama dengan label navigasi biasa. Informasi tidak dibuat ringkas dengan mengecilkan font sampai 9–10 px.

### 16.3 Kontrak status dan microcopy

| State data | Label pengguna yang disarankan | Penjelasan/action |
|---|---|---|
| candidate boundary | Batas akses perlu diperiksa | Bandingkan aturan akses/pemilik di kedua sisi |
| needs_context / deferred risk | Bukti belum cukup | Belum dapat menyimpulkan risiko akhir; buka pertanyaan terkait |
| scenario severity High | Potensi dampak: Tinggi | Sinyal skenario, belum berarti kerentanan terverifikasi |
| grounded | Didukung sumber | Evidence mendukung skenario; verification status ditampilkan terpisah |
| control unassigned | Control belum ditentukan | Tentukan kecocokan dengan finding, jangan eksekusi test seolah mapping selesai |
| test blocked | Belum siap diuji | Tampilkan prasyarat yang kurang dan tautan penyelesaiannya |
| preserved results | Hasil sebelumnya tersedia | Sebut run/waktu; tahap terbaru belum menghasilkan pengganti tervalidasi |
| stale | Konteks/model berubah | Sebut tahap terdampak dan refresh yang diperlukan |
| analysis complete, gate blocked | Analisis selesai; review masih diperlukan | Tidak tampil sebagai assessment siap ditandatangani |
| signed / superseded | Ditandatangani / Ada revision lebih baru | Jelaskan snapshot yang sedang dibaca dan akses revision berikutnya |

Tidak mengganti canonical enum hanya untuk copy UI. Implement translation/presentation mapping agar report, list, overview dan export menyampaikan makna yang konsisten.

### 16.4 Detail perilaku

- Selection membuka detail, bukan langsung mengubah data. Save mempunyai loading state, hasil, dan error yang melekat pada form.
- Row selected berbeda dari row keyboard-focused; keduanya terlihat dan tidak hanya dibedakan warna.
- Boundary Reject/Reset menjelaskan dampak pada visibility/hasil sebelum persist, dengan review note bila relevan.
- Filter view tidak boleh disalahartikan sebagai menghapus hasil atau menyelesaikan blocker.
- User dapat membatalkan editor tanpa mengubah report; dirty-state prompt hanya saat benar-benar ada input belum tersimpan.
- Setelah queue selesai, tampilkan ringkasan keputusan dan next task; jangan rerun model atau menandatangani report otomatis.
- Link sumber membuka locator jika tersedia; jika belum ada locator, sebut keterbatasan sumber dan kebutuhan review secara eksplisit.

## 17. Wireframe yang direkomendasikan

Wireframe berikut menggambarkan urutan informasi dan interaksi, bukan screenshot atau desain final. Angka N/X adalah placeholder, bukan hasil analisis aktual. Layout memakai komponen yang sudah ada; tidak memerlukan halaman ketujuh.

### W1 — Overview desktop dan mobile

```text
[Project ▾] / Overview                     [More: refresh, export]
─────────────────────────────────────────────────────────────────
Analisis selesai · Review diperlukan
N skenario belum dapat dinilai; X batas akses perlu konfirmasi.
[Periksa batas akses berikutnya]                         Primary

Progress: Model → Findings → Action plan → Evidence → Report

Perlu perhatian                         Ringkasan assessment
1. Batas akses belum dikonfirmasi        Scored: X | Deferred: N
2. Sumber belum dibaca seluruhnya        Final risk: belum lengkap
3. Control perlu keputusan              [Cara membaca hasil]
[Lihat semua pekerjaan]

▸ Riwayat run dan detail teknis
```

Mobile menggunakan urutan yang sama dalam satu kolom. Header memuat `Menu`, nama project, dan `More`; satu primary action berada pada status card. Saat running, card diganti phase aktif, elapsed, status antrean, serta tautan hasil sebelumnya. Tidak ada full uploader/list di bawahnya sebagai default.

### W2 — Model desktop

```text
[Project] / System model    rN · tersimpan           [More]
[Context ▾] [Cari elemen] [Fit] [Fullscreen] [Review batas (N)]
Health: N perlu review [Rincian]
┌─────────────────────────────────────────┬────────────────────┐
│                                         │ Tidak ada selection│
│     CANVAS DFD — ≥495 px TERLIHAT        │ Pilih flow atau     │
│     pada 1440×900                        │ mulai review        │
│                                         │                    │
│ [Aktor] → [Proses] → [Data store]       │ Setelah dipilih:    │
│     zona/boundary dan arah data jelas    │ Dari → Ke           │
│                                         │ Data / Aturan akses │
│                                         │ Evidence [Buka]     │
│                                         │ Findings [Lihat N]  │
└─────────────────────────────────────────┴────────────────────┘
▸ Outline yang dapat dinavigasi  ▸ Inventory  ▸ Coverage detail
```

Pada desktop tanpa selection rail boleh menampilkan petunjuk singkat atau queue ringkas; bukan seluruh evidence dan semua boundary card. Canvas selection dan outline selection memakai ID canonical yang sama.

### W3 — Model mobile dan guided boundary

```text
INITIAL                               SETELAH REVIEW DIPILIH
[☰] Project / Model [⋯]               [Tutup] Review batas 1/N
[Context ▾] [Fit] [Fullscreen]        ─────────────────────────
Health: perlu review [Detail]         Pengguna → Aplikasi
┌─────────────────────────────┐       Data: detail pesanan
│                             │       Apakah aturan akses atau
│         CANVAS              │       pemiliknya berbeda?
│                             │       Sumber: PRD §X [Buka]
│                             │       ( ) Ya  ( ) Tidak
└─────────────────────────────┘       ( ) Belum tahu
[Review batas (N)] [Outline]          Alasan / informasi kurang
                                      [Simpan & berikutnya]
```

Sheet hanya muncul setelah action. Pada layar pendek, sheet menjadi dialog penuh; background tidak bisa ditab. Menutupnya mengembalikan pengguna ke elemen/flow yang sama. Review dan fullscreen tidak membentuk dua overlay yang saling mengunci.

### W4 — Findings list-detail

```text
[Project] / Findings          Scored X · Deferred N
[Cari skenario / ID…] [Needs review ▾] [Filters (2)] [Sort ▾]
Filter aktif: STRIDE ×  Needs context ×               [Reset]
┌──────────────────────────────┬───────────────────────────────┐
│ Finding A                    │ Finding A                     │
│ Potensi Tinggi · Deferred    │ Apa yang mungkin terjadi?     │
│ Flow: User → Checkout        │ Ringkasan 2–3 kalimat         │
├──────────────────────────────┤                               │
│ Finding B                    │ Risiko akhir: belum dinilai   │
│ Scored Medium · Open         │ Bukti tersedia / yang kurang  │
│ Flow: API → Database         │ [Buka sumber] [Buka flow]     │
├──────────────────────────────┤                               │
│ Finding C …                  │ Terkait: Controls N | Tests N │
│                              │ Review status [Needs info ▾] │
│                              │ [Simpan review]               │
└──────────────────────────────┴───────────────────────────────┘
```

Mobile: list satu kolom; detail menggantikan area kerja melalui sheet/dialog berjudul. Search/quick filter tetap compact; filter lengkap dibuka dengan tombol. Detail tidak menghilangkan scroll list. Expert bisa membuka DFD/control/test lewat link objek langsung.

### W5 — Action Plan dengan control-test trace

```text
[Project] / Action plan
[Controls] [Tests] [Needs decision (N)]
[Search…] [Owner ▾] [Filters] [Sort]
┌────────────────────────────┬────────────────────────────────┐
│ Control: validate input    │ Control detail                 │
│ Owner: API team · Open     │ Mengatasi: Finding A [Buka]     │
│ Priority High              │ Flow: User → Checkout [Buka]    │
├────────────────────────────┤ Guidance                       │
│ Test: altered order total  │ ▸ Checklist                    │
│ Not run · Ready to execute │ [Buka test: altered total]     │
├────────────────────────────┤ Evidence yang diminta          │
│ Needs decision …           │ Owner [____] Status [____]     │
│                            │ [Simpan]                       │
└────────────────────────────┴────────────────────────────────┘
```

Memilih test dari inspector control membukanya walaupun tab Controls aktif, dengan chip `Dibuka dari Control X` dan return action. Bila test blocked, tampilkan alasan dan prasyarat lebih dahulu daripada langkah eksekusi. Status Not Run/Passed/Failed terpisah dari keputusan applicability; guidance lengkap tidak otomatis berarti test lulus.

### W6 — Evidence dan source coverage

```text
[Project] / Evidence         [Update context] [Add source]
[Needs attention (N)] [Sources & coverage] [Assumptions]
[Search…] [Owner ▾] [State ▾]
┌────────────────────────────┬────────────────────────────────┐
│ Siapa boleh memberi refund?│ Pertanyaan dan alasan penting  │
│ Owner: Unassigned · Open   │ Linked: Finding A / Flow B     │
│ Next: minta aturan akses   │ Owner [____]                    │
├────────────────────────────┤ [Tautkan evidence] [Defer]     │
│ Bagian dokumen belum dibaca│ Review note [______________]    │
│ PRD §X · Parsing deferred  │ [Simpan keputusan]             │
└────────────────────────────┴────────────────────────────────┘

Sources view:
PRD rN: Dibaca X | Belum dibaca Y | Ditunda Z
▸ Locator, alasan, dan next action per bagian
```

Upload form dan manifest tidak mengambil posisi awal seluruh halaman ketika tugas aktif adalah menyelesaikan pertanyaan. Context editor tetap dialog yang sudah ada, diperkuat fokus/validation-nya.

### W7 — Report desktop dan mobile

```text
[Project] / Report       [Revision rN ▾] [Export ▾] [More]
[Draft — belum siap ditandatangani]       [Review blocker]
Kesimpulan: risiko akhir belum dapat disimpulkan
Scored X | Deferred N | Verification: belum lengkap

Scope & assumptions penting     DFD snapshot rN [Buka model]
──────────────────────────────────────────────────────────
3 blocker utama [Buka di workspace terkait]
Provenance: sumber rN · run N · metode version [Detail]

▸ Findings (N)   ▸ Controls (N)   ▸ Tests (N)
▸ Sources/gaps   ▸ Approval & revision history
[Print/export full appendix]
```

Mobile: satu bar `Section ▾ / Search / More`, summary singkat, appendix tertutup. Membuka section merender subset yang diperlukan dan memfokuskan heading. Memilih signed revision mempertahankan badge immutable dan link `Lihat latest draft`, bukan mengganti isi diam-diam.

## 18. Kontrak responsive, aksesibilitas, dan state

### 18.1 Responsive dan area kerja

| Kondisi | Perilaku yang diwajibkan |
|---|---|
| 1440×900 | Sidebar penuh; list-detail; canvas ≥55% viewport benar-benar terlihat; tidak ada coverage panel besar di atas canvas |
| 1280×900 | Sidebar dapat diperkecil; rail 300–360 px bila ruang cukup; toolbar wrap tanpa menutup daftar |
| 768×900 | Sidebar drawer; inspector menjadi overlay jika dua kolom tidak terbaca; tidak memaksa fixed min-width desktop |
| 390×844 dan 390×900 | Satu kolom, filter compact, labeled actions; drawer/sheet dengan focus lifecycle lengkap |
| 320 CSS px / zoom 400% pada baseline 1280 | Teks/form/navigation reflow; diagram dapat pan dua dimensi di region terlabel dan menyediakan outline |
| Tinggi pendek / landscape / software keyboard | Save/Close tetap dapat dicapai, dialog bisa scroll, focused field terlihat, safe-area bottom diperhitungkan |

Ukuran kanvas/daftar memakai available viewport; tidak mengandalkan `height: 680px` sebagai satu-satunya pembuktian. Web report tidak dijadikan dokumen panjang untuk memenuhi kebutuhan export.

### 18.2 State yang wajib ada pada desain dan test

| State | Yang dilihat pengguna | Action dan evidence acceptance |
|---|---|---|
| No project / invalid ID | Project tidak ditemukan | Pilih project; tidak ada form kosong seolah siap edit |
| No analysis | Belum ada hasil | Add context / Start analysis sesuai kesiapan |
| Loading | Skeleton/status pada ruang yang stabil | Navigasi project tetap valid; controls belum siap disabled dengan alasan |
| Running | Fase aktual, waktu, fase lain antre | Previous result diberi run label; reload melanjutkan observasi |
| Partial/provider failure | Fase mana gagal, hasil mana preserved | Retry affected; info error mudah dibaca tanpa jargon provider wajib |
| Stale | Model/context sudah berubah | Re-analyze affected; previous revision tetap jelas |
| Zero matches | 0 sesuai filter dari N total | Clear relevant filter; bukan pesan tidak ada risiko |
| Zero scored, N deferred | Risiko akhir belum disimpulkan | Review evidence; hindari success/green all-clear |
| Unassigned control / blocked test | Applicability/prasyarat belum selesai | Open exact finding/control decision |
| Unsaved / saving / failed save | Input tetap tersedia dan status eksplisit | Retry atau discard; tidak hilang saat fetch gagal |
| Revision conflict | Ada perubahan dari reviewer lain | Reload/compare; tidak mengklaim saved |
| Sign-off blocked | Alasan, owner, destination blocker | Tidak hanya disabled button |
| Draft / signed / superseded | Revision dibaca, actor/time, scope | Open immutable snapshot / latest draft dengan label berbeda |

Mock/synthetic state dipakai untuk menguji error dan sign-off; tidak perlu memaksa kegagalan provider pada project produksi.

## 19. Rencana perbaikan yang dapat dieksekusi

### 19.1 Rekonsiliasi milestone lama

| Milestone | Sudah ada | Belum memenuhi goal / perlu diverifikasi | Temuan terkait |
|---|---|---|---|
| U0 | URL state, shared helpers, telemetry terbatas | Early navigation, identity trace, reproducible fixture | R01/R05/R10 |
| U1 | Overview dan progress/retry | Heading, mobile CTA, hierarchy keputusan, status lintas kondisi | R03/R09/R10/R13 |
| U2 | Halaman Model, canvas, queue, inspector, More | Canvas visible area, mobile overlay, keyboard parity, DFD→Findings | R04/R05/R06 |
| U3 | Unified list, filters, detail, risk-state separation | Mobile filter density, links control/test, composite keyboard semantics | R04/R05/R08/R13 |
| U4 | Controls/Tests workspace dan trace dari action | Link dari finding, target di luar filter, inspector accessibility | R04/R05/R08 |
| U5 | Evidence/context dialog/coverage | Queue priority, owner resolution, hidden focus, source-to-question trace | R03/R04/R11 |
| U6 | Read-only metadata, draft/sign backend foundation, pagination | Contrast, sticky overlap, long document, visual DFD/revision browsing | R02/R07/R14 |
| U7 | Chromium/axe Paket G, keyboard workspace, exact trace, guided flow | **Reopened:** UX-C01–C09, overlay/open-state visual matrix, screen reader, novice/expert study | §22 + P0 terkait |
| U8 | Beberapa search/URL/filter features tersedia | Ditahan sampai H0–H6 selesai; setelah itu corpus benchmark, lazy render, saved views | UX-C10/R15 |

Tidak menghapus progress yang sudah selesai. Status `Implemented` berarti kode tersedia; `Validated` memerlukan hasil test; `Accepted` memerlukan semua acceptance dan review produk yang relevan.

### 19.2 Paket kerja dan dependensi

| Paket | Urutan dan scope | Deliverable konkret | Peran | Exit gate |
|---|---|---|---|---|
| A — Baseline yang dapat dipercaya | Mulai; R01 | Fixture sintetis, expected trace map, axe runner, daftar state, snapshot baseline | QA + FE | Gagal pada bug yang diketahui; tidak ada fallback palsu |
| B — Readability dan mobile actions | Setelah baseline; R02/R03 + label critical R13 | Tokens contrast, formal metadata surface, labeled topbar, field labels | Design + FE | **Chromium validated:** contrast/name checks hijau; screenshot mobile terbaca |
| C — Focus dan shared interaction | Setelah B; R04/R13/R10 bagian navigation | Dialog/inspector contract, sidebar focus, list semantics, early route setup | FE + QA | Keyboard-only open/edit/cancel/return lulus |
| D — Trace dan canvas | Setelah A/C; R05/R06 | Direct object links, out-of-filter detail, canvas-first layout, accessible outline | FE + BE + Design | Exact ID trace lulus; ≥55% canvas visible desktop |
| E — Report review | Setelah B/D; R07/R14 | Executive view, collapsed appendix, snapshot/selector, compact mobile nav, deep-link paging | FE + BE | ≤3 viewport summary; revision-consistent read/export |
| F — Guided work | D/E core stabil; R08/R09/R11/R12/R10 sisa | Progressive filters, guided review, source-question flow, onboarding/recovery | Product/UX + FE + BE | **Chromium validated:** 7/7 guided-work checks pass; human novice study masih pending |
| G — Revalidation U7 | Setelah seluruh P0 dan journey terkait | Chromium matrix, axe report, keyboard/trace evidence | QA + UX + Product | Automated scope pass; **visual gate direopen oleh §22** |
| H — Superseded | Lihat H0–H6 pada §22.9 | Consistency remediation sebelum scale/polish | FE + QA + UX | Seluruh UX-C P0 selesai sebelum U8 dimulai |

Paket B dan persiapan peserta boleh berjalan paralel setelah baseline. Jangan mempercepat closing U7 dengan menonaktifkan rule atau mengurangi state yang gagal. Estimasi kalender baru dibuat setelah scope PR dan owner disepakati; relative size di §15 tidak menjamin durasi.

### 19.2.1 Implementasi Paket A — status dan bukti baseline

Paket A telah dibuat sebagai artefak yang dapat dijalankan ulang, tetapi **belum lulus exit gate**. Artefak yang ditambahkan:

- `fixtures/u7_release_gate_fixture.json`: fixture sintetis `u7-release-gate-v1` tanpa konten produksi. Fixture ini berisi 4 node, 3 flow lintas zone, 3 boundary (candidate dan confirmed), 25 finding STRIDE/LINDDUN, finding grounded dan deferred, control assigned/unassigned, test executable/blocked, source section deferred, gap tanpa owner, expected trace berbasis ID, serta daftar state loading/running/partial/stale/draft/signed/superseded.
- `tools/u7_release_gate.js`: runner Playwright + axe-core yang memvalidasi kontrak fixture sebelum membuka UI. Runner mengaudit `analysis`, `model`, `findings`, `action-plan`, `evidence`, dan `report` pada 390, 768, 1280, dan 1440 CSS px. Dengan `--screenshot-dir`, runner juga menyimpan snapshot viewport initial per page/width untuk review lokal; screenshot dari project non-sintetis tidak boleh diunggah sebagai CI artifact. JSON gate hanya menyimpan rule, impact, target, state, viewport, versi axe, dan hitungan; tidak menyimpan isi dokumen.
- `package.json` dan `package-lock.json`: dependency dev dikunci pada `axe-core 4.10.3` dan `playwright 1.57.0`. Runner gagal bila fixture atau dependency tidak tersedia.

Perintah baseline:

```bash
npm run u7:baseline -- --output /tmp/5stones-u7-baseline.json --screenshot-dir /tmp/5stones-u7-baseline-screens
```

Mode diagnosis yang tetap menghasilkan artifact tetapi tidak mengubah kegagalan menjadi pass:

```bash
npm run u7:baseline:report -- --output /tmp/5stones-u7-baseline.json
```

Baseline resmi terhadap project UI `9b3aeb5d-1e7b-4f62-809c-0f74b33a1510`: 24 page/viewport berhasil dimuat pada matrix 390/768/1280/1440, tidak ada error navigasi, tetapi ditemukan 62 rule violations dan 34 serious/critical occurrences. Screenshot initial tersimpan di `/tmp/5stones-u7-baseline-screens` untuk review lokal. Temuan kritis/serius utama adalah `select-name` pada Analysis, `color-contrast` pada seluruh workspace, `aria-prohibited-attr` pada Report, dan `scrollable-region-focusable` pada Report di tablet/desktop. Runner sengaja tetap merah; angka ini adalah baseline remediasi, bukan klaim bahwa U7 lulus.

Status requirement R01 setelah Paket A:

| Requirement | Status | Bukti / gap tersisa |
|---|---|---|
| R01.1 pisahkan evidence gate | **Implemented sebagian** | Automated axe dan fixture contract sudah terpisah; keyboard-only, visual diff, relation trace, dan human study masih gate terpisah yang belum dibuat penuh |
| R01.2 fixture versioned + expected trace | **Implemented** | Fixture memiliki ID trace lintas flow → finding → control → test dan kasus deferred/unassigned/blocked |
| R01.3 axe versi terkunci + metadata | **Implemented sebagian** | Versi dan target/impact/state/viewport tersimpan; suppression review dan seluruh interactive states belum dicakup |
| R01.4 page data ready, tanpa fallback palsu | **Implemented sebagian** | Fixture contract menolak link hilang; runner berikutnya harus menambahkan assertion readiness dan tidak memilih row pertama |
| R01.5 keyboard natural journey | **Belum** | Belum menggantikan smoke audit dengan Tab/Shift+Tab/Arrow/Enter/Space/Escape assertions |
| R01.6 artifact aman dan dependency wajib | **Implemented** | Fixture non-sensitive, dependency terkunci, missing dependency/fixture membuat runner gagal |

Paket A selesai secara implementasi dan siap menjadi baseline untuk Paket B/C. Paket A baru dapat dinyatakan `Validated` setelah state interaktif, keyboard-only, relation trace, visual snapshot, dan review incomplete findings ditambahkan tanpa menurunkan severity atau memakai fallback.

### 19.2.2 Implementasi Paket B — status dan bukti Chromium

Paket B telah diimplementasikan dan lulus validasi otomatis untuk initial page state. Perubahan yang dilakukan:

- Token `--text-muted`, `--text-faint`, dan `--blue` digelapkan agar teks metadata, caption, badge, navigation, dan filter tetap terbaca pada surface terang.
- Formal Report metadata, disposition, blocker, source manifest, dan revision history dipindahkan ke surface terang dengan teks gelap. Status draft/signed/superseded tetap dibedakan dengan label dan warna yang memenuhi contrast.
- Aturan mobile yang sebelumnya mengubah semua `.topbar-actions .btn` menjadi `font-size: 0` dihapus. Action sekarang tetap bernama, dapat wrapping, memakai target minimum 40 px, dan tetap mudah dibaca pada 320/390 px.
- `Analysis` memperoleh heading utama dan accessible label untuk artifact type, filter STRIDE, filter LINDDUN, dan filter test.
- Pagination Report diberi navigation landmark; table wrapper yang scrollable dapat menerima keyboard focus; toast diberi `role=status` dan `aria-live`.
- Instruction `Click` pada legenda DFD memakai warna merah gelap yang tetap memiliki contrast memadai.

Validasi Chromium:

```bash
npm run u7:package-b -- --output /tmp/5stones-u7-package-b-contract-final.json
npm run u7:baseline -- --output /tmp/5stones-u7-package-b-strict-final.json
```

Hasil:

- Package B custom gate: **30/30 page/viewport pass**, termasuk 320, 390, 768, 1280, dan 1440 px; 0 navigation error, 0 blank action, 0 undersized action, 0 unnamed select, 0 horizontal overflow, dan 0 missing h1.
- Axe strict gate: **24/24 page/viewport pass**, 0 violation, 0 serious/critical. Baseline sebelumnya 62 violation dan 34 serious/critical, sehingga penurunan dapat diaudit melalui artifact sebelum/sesudah.
- Screenshot Chromium terbaru untuk review visual initial tersimpan di `/tmp/5stones-u7-package-b-screens`; Report mobile dan Analysis mobile telah di-spot-check setelah wrapping action diperbaiki.

Batas validasi: ini membuktikan initial state dan kontrak mobile/readability. Inspector terbuka, filter menu terbuka, dialog context, dan keyboard-only kini direvalidasi Paket C/G; screen reader dan screenshot visual diff yang disetujui masih menjadi manual follow-up. Paket B sendiri tidak mengklaim seluruh U7 sudah lulus.

### 19.2.3 Implementasi Paket C — status dan bukti Chromium

Paket C telah diimplementasikan untuk memperbaiki lifecycle focus dan shared interaction pada tiga workspace utama:

- Inspector Findings, Action Plan, dan Evidence sekarang punya satu kontrak. Pada desktop inspector diberi labeled `region` nonmodal; pada breakpoint mobile inspector menjadi labeled `dialog` dengan `aria-modal`, background workspace `inert`, focus trap Tab/Shift+Tab, dan return focus ke row pemicu.
- Listbox memakai roving `tabindex`: Tab mencapai listbox, ArrowUp/ArrowDown masuk ke row dan berpindah antar-row, Enter membuka detail, sedangkan Escape/Close menutup detail tanpa kehilangan row/filter context.
- Mobile sidebar menyembunyikan drawer tertutup dari keyboard/assistive technology melalui `inert` dan `aria-hidden`, memindahkan fokus ke navigation saat dibuka, menjaga Tab tetap di drawer, dan mengembalikan fokus ke toggle saat Escape atau outside-close.
- Context editor Evidence menyimpan trigger dan mengembalikan fokus setelah Cancel/Escape; direct workspace links memiliki `id` project sejak awal sebelum request async selesai.

Gate yang ditambahkan:

```bash
npm run u7:package-c -- --output /tmp/5stones-u7-package-c.json --screenshot-dir /tmp/5stones-u7-package-c-screens
```

Hasil Chromium 2026-09-23: **6/6 journey pass**, 0 browser error: Findings, Action Plan, dan Evidence pada 390 px serta 1280 px. Assertion mencakup open → inspect → Shift+Tab containment (mobile) → Escape → focus return → reopen, desktop nonmodal inspector, mobile sidebar focus lifecycle, context dialog Cancel/Escape, dan screenshot first viewport. Screenshot tersimpan di `/tmp/5stones-u7-package-c-screens` dan telah di-review visual; tidak terlihat blank action, horizontal clipping, atau inspector yang menutupi first viewport sebelum dipilih.

Catatan evidence: Package C membuktikan core interactive scope, bukan seluruh release gate U7. Setup test boleh memfokuskan container/list trigger untuk mengisolasi kontrak keyboard; aksi setelah setup tetap native Chromium keyboard. Model canvas dan exact-ID trace kini divalidasi oleh Paket D dan Paket G; Report states, resize-while-open lintas halaman, serta guided/onboarding flow sudah direvalidasi Paket G. Screen reader dan novice/expert study tetap pending.

Status requirement setelah Paket C:

| Requirement | Status | Bukti / gap tersisa |
|---|---|---|
| R04 inspector/sidebar focus lifecycle | **Validated pada core workspace** | 3 workspace × 390/1280 pass; Model inspector dan resize-while-open masih perlu ditambahkan |
| R10 early route setup | **Implemented** | `UIState.bindProjectLinks()` terpasang sebelum async load; perlu assertion Back/Forward lintas semua route |
| R13 list semantics | **Implemented + Chromium validated** | Roving tabindex dan arrow/Enter/Escape pass; screen-reader announcement/manual audit masih terbuka |
| Keyboard open/edit/cancel/return | **Validated sebagian** | Inspector/context dialog pass; field editing/save error, Model boundary queue, dan full browser Back belum tercakup |

### 19.2.4 Implementasi Paket D — status dan bukti Chromium

Paket D menutup gap R05/R06 yang tersisa setelah Paket C:

- DFD flow inspector sekarang mengumpulkan finding dari canonical `target_refs`/boundary relation ketika edge tidak membawa daftar threat hasil projection. Link finding selalu menuju Findings Workspace dengan `phase` dan `selected=threat:<id>`, bukan Report legacy.
- Findings inspector menampilkan action trace berbasis foreign key aktual: `threat_id → control.threat_ids → test.threat_id/related_control_id`. Control dan test dibuka ke Action Plan menggunakan `selected=control:<id>` atau `selected=test:<id>`; tidak ada pemilihan berdasarkan posisi row atau kemiripan label.
- Accessible model outline pada Context/System/Feature DFD berisi button untuk node dan flow. Aktivasi button memilih elemen canvas yang sama, membuka inspector, dan memperbarui URL selection dengan canonical ID.
- Canvas desktop dipadatkan menjadi urutan header → compact toolbar/health surface → canvas. Coverage summary yang redundant tidak lagi mendorong canvas keluar first viewport; Fit menjalankan resolusi overlap canonical sebelum viewport dihitung. Mobile model inspector memakai shared dialog contract dan Escape mengembalikan fokus.
- `tools/u7_package_d_gate.js` menambahkan fixture-aware Chromium gate; geometry diukur pada 1440×900, bukan hanya berdasarkan CSS height. Gate juga memeriksa exact-ID navigation dan mobile modal behavior.

Command:

```bash
npm run u7:package-d -- --output /tmp/5stones-u7-package-d.json --screenshot-dir /tmp/5stones-u7-package-d-screens
```

Hasil Chromium 2026-09-23 terhadap **Hacktiv8 Commerce**: **3/3 checks pass**, 0 browser error, 1 screenshot desktop. Trace aktual yang diverifikasi adalah `flow-566389ca64134acd → threat 904461ba-0cca-49d5-ba48-505670ecc84b → control CAT-ctrl-011 → test TM-6884FA24B2`. Check pertama mengukur canvas pada first viewport dengan visible intersection memadai, tidak tertutup, Fit tanpa overlap node, dan outline keyboard yang memilih flow. Check kedua membuka seluruh trace lintas workspace dengan ID tersebut. Check ketiga memvalidasi outline → inspector modal pada 390×844 dan Escape/focus restoration. Threshold release yang lebih realistis dan terukur kemudian dikonsolidasikan di Paket G.

Status requirement setelah Paket D:

| Requirement | Status | Bukti / gap tersisa |
|---|---|---|
| R05 traceability | **Validated pada fixture standar** | Exact-ID flow → finding → control → test lulus; kasus filter out-of-filter, browser Back/scroll restoration, dan corpus besar masih perlu revalidation |
| R06 canvas-first DFD | **Validated pada 1440×900 + 390×844** | Canvas visibility, Fit overlap, interactive outline, boundary rail, dan mobile inspector pass; resize-while-open, fullscreen/Escape, dense corpus visual diff, dan screen-reader review masih terbuka |
| U2 model workspace | **Implemented + Paket D gate pass** | Human novice guided boundary review dan full viewport matrix tetap menjadi bagian U7/G |

Paket D tidak menutup release gate U7 secara keseluruhan: axe pada seluruh state interaktif, visual diff semua breakpoint, screen reader, serta novice/expert usability study tetap wajib.

### 19.2.5 Implementasi Paket E — status dan bukti Chromium

Paket E mengubah Report menjadi surface review yang bounded, revision-aware, dan tetap read-only:

- Overview mempertahankan scope, risk disposition, sign-off blocker, next action, provenance, dan canonical DFD snapshot; readiness detail dipadatkan dan gate components tetap tersedia melalui disclosure.
- Enam appendix (`Trust boundaries`, `Threat scenarios`, `Controls`, `Tests`, `Information gaps`, `Assumptions`) collapsed by default. Tombol appendix mempunyai `aria-expanded`/`aria-controls`, dan TOC/deep-link otomatis membuka section yang dituju tanpa merender seluruh detail pada initial view.
- Snapshot DFD menampilkan zone, node, flow, revision, jumlah object, dan link dua arah ke Model workspace. Caption memakai revision canonical yang sama dengan report/finding references.
- Revision reader menyediakan selector, status immutable read-only, aksi kembali ke current projection, dan menonaktifkan Save draft ketika revision lama sedang dibaca. Report lama tidak mengubah canonical finding/control/test.
- Export JSON/Markdown/CSV menerima `revision_id`; ketika revision dipilih, export memakai report snapshot dan formal metadata revision tersebut, bukan mengambil DFD/source manifest terbaru secara diam-diam.
- Mobile command bar tetap sticky, TOC tidak lagi sticky di bawah offset header, dan report tidak memiliki horizontal overflow. Spacing overview dipadatkan agar first summary bounded tanpa menghilangkan blocker/deferred statement.

Artefak implementasi utama: `frontend/report.html`, `frontend/js/report.js`, `frontend/js/api.js`, `frontend/css/pages.css`, `backend/routers/export.py`, dan `tools/u7_package_e_gate.js`.

Command validasi:

```bash
npm run u7:package-e -- --output /tmp/5stones-u7-package-e.json --screenshot-dir /tmp/5stones-u7-package-e-screens
```

Hasil Playwright Chromium 2026-09-24 terhadap **Hacktiv8 Commerce**: **3/3 checks pass**, 0 browser error, 2 screenshot. Bukti terukur:

| State | Hasil | Kontrak yang lulus |
|---|---:|---|
| 390×844 mobile | **2.531 px document height** | ≤3 viewport (2.532 px), 0 horizontal overflow, 6 appendix collapsed, snapshot DFD visible, TOC `static` |
| 1440×900 desktop | **1.873 px document height** | 0 horizontal overflow, appendix collapsed, snapshot DFD visible, TOC/commandbar tidak overlap |
| Deep-link | **Pass** | `selected=threat:<canonical-id>` membuka appendix dan row yang tepat serta memberi `route-selected` |
| Revision/export | **Pass** | immutable reader menonaktifkan draft action; JSON export mempertahankan `formal_report.revision` dan `dfd_revision` snapshot |

Status requirement setelah Paket E:

| Requirement | Status | Bukti / gap tersisa |
|---|---|---|
| R07 report bounded/revision-aware | **Validated pada fixture standar** | Chromium gate pass untuk mobile/desktop, collapsed appendix, snapshot, deferred summary, revision reader, dan export; signed/superseded human approval review serta print/PDF visual diff masih terbuka |
| R14 deterministic deep-link/paging | **Validated pada threat deep-link page 2** | Canonical threat ID setelah page size 20 membuka appendix, page 2, dan row yang benar; deep-link lintas control/test, filter retention, Back/Forward, dan corpus >25 masih perlu matrix penuh |
| U6 formal report hardening | **Implemented + Paket E gate pass sebagian** | Read-only surface, DFD/source provenance, revision selector, immutable export pass; signoff production approval dan full print appendix masih perlu diverifikasi |

Paket E tidak menutup release gate U7 keseluruhan. Full axe, keyboard-only lintas workspace, dan route/viewport matrix kini sudah direvalidasi Paket G; screen reader, approved visual diff, serta novice/expert task study tetap menjadi pekerjaan manual setelah Paket G.

### 19.2.6 Implementasi Paket F — status dan bukti Chromium

Paket F mengubah workspace dari permukaan teknis yang padat menjadi alur kerja bertahap. Prinsip implementasinya adalah: jalur cepat harus cukup untuk memulai review, detail lanjutan tetap tersedia melalui disclosure, dan ketidakpastian harus memiliki tindakan eksplisit tanpa dipromosikan menjadi kerentanan.

Perubahan yang dilakukan:

- Findings, Action Plan, dan Evidence memakai progressive filters: search + quick view (`Needs review`, `Deferred`, `Needs decision`, `Needs attention`) terlihat lebih dahulu; multi-filter, sort, owner, state, dan interaction dipindahkan ke `More filters`. Active filter chips dapat dihapus satu per satu, state filter tetap berada di URL, dan `Reset` mengembalikan view tanpa menghilangkan project/run context.
- Findings memiliki `Start guided finding review`. Reviewer novice diarahkan pada pertanyaan “What might happen?”, evidence yang tersedia, dan pemeriksaan berikutnya. `Belum tahu`/missing evidence menyimpan status review sebagai `Needs Info`; status tersebut tidak mengubah scenario menjadi confirmed vulnerability atau final risk.
- Model memiliki `Start guided boundary review` dengan pertanyaan berbasis perbedaan akses/ownership, source/destination zone, identity, privilege, dan data exposure. Pilihan `Yes, access differs`, `No, same rule`, dan `Belum tahu` memakai boundary canonical yang sama dengan queue/diagram; `Belum tahu` mempertahankan status unresolved.
- Evidence menjadi queue-first pada mobile. Intake artifact dan ingestion coverage tetap ada sebagai disclosure sekunder, sehingga unread/deferred locator tidak hilang tetapi tidak menghalangi review item. Inspector sekarang menyediakan owner, state, next action, notes, dan source locator/evidence reference; backend menerima `evidence_refs` serta `follow_up_date` yang tervalidasi.
- Onboarding project menyediakan dua jalur: `Start from a document` atau `Fill a short summary`. Jalur dokumen tidak memaksa actor/description teknis sebelum artifact dibaca; description fallback diberi label document-driven. Draft scalar disimpan di `sessionStorage`, field invalid diberi `aria-invalid`/summary error, dan error create tidak menghilangkan input.
- Findings, Action Plan, dan Evidence membedakan error request dari empty state. Error menampilkan alasan, `Retry load`, dan link aman kembali ke Analysis; tidak merender “zero findings” yang menyesatkan ketika report belum dapat diambil.
- Mobile first viewport dipadatkan: secondary topbar actions disembunyikan ketika action yang sama tersedia di queue/summary, advanced details tidak mengambil ruang ketika tertutup, dan first review row diposisikan agar dapat ditemukan tanpa scroll panjang. Desktop tetap mempertahankan seluruh advanced controls.

Artefak implementasi utama: `frontend/findings.html`, `frontend/js/findings.js`, `frontend/action-plan.html`, `frontend/js/action-plan.js`, `frontend/evidence.html`, `frontend/js/evidence.js`, `frontend/project-new.html`, `frontend/js/project.js`, `frontend/js/analysis.js`, `frontend/css/pages.css`, `backend/routers/analysis.py`, `tools/u7_package_f_gate.js`, dan script `u7:package-f` di `package.json`.

Command validasi:

```bash
npm run u7:package-f -- --output /tmp/5stones-u7-package-f.json --screenshot-dir /tmp/5stones-u7-package-f-screens
```

Hasil Playwright Chromium 2026-09-24 terhadap **Hacktiv8 Commerce**: **7/7 checks pass**, 0 browser error, 0 horizontal overflow pada tiga workspace mobile, dan semua first review row berada ≤420 px (Findings 411 px, Action Plan 415 px, Evidence 398 px). Check yang lulus mencakup:

| Journey | Bukti |
|---|---|
| Findings quick view | URL `fst` terbentuk; advanced filters collapsed; inspect/close tidak kehilangan list position |
| Guided finding | Pertanyaan plain-language, evidence choice, dan deferred path tersedia |
| Action Plan | Quick view `Needs decision` membentuk URL `aexec`; queue compact dan actionable |
| Evidence | `Needs attention` membentuk URL `est`; inspector menyediakan source locator |
| Guided boundary | Tiga pilihan akses/ownership termasuk `Belum tahu` terhubung ke canonical boundary |
| Document-first onboarding | Name-only dapat lanjut; description/actors teknis tidak dipaksa; guidance terlihat |
| Recovery | Load failure membedakan error, menyediakan Retry, dan safe return ke Analysis |

Status requirement setelah Paket F:

| Requirement | Status | Bukti / gap tersisa |
|---|---|---|
| R08 progressive filter/list | **REOPENED oleh §22** | Fondasi quick preset/URL/chips ada, tetapi mobile field 83–92px, duplicate disclosure, native multi-select, dan nested scroll harus diremediasi pada H4; saved views tetap U8 setelah H6 |
| R09 novice guided review | **Implemented + Chromium pass** | Boundary/finding guided path, plain-language choices, dan explicit unknown pass; studi novice manusia masih pending |
| R10 error/loading/recovery | **Implemented + Chromium pass pada covered surfaces** | Retry + safe destination + draft recovery pass; slow API/partial/stale production-load testing tetap follow-up |
| R11 evidence/source-to-question | **Implemented + Chromium pass** | Queue-first, source locator, unread/deferred disclosure, owner/state/next action pass; upload/revision coverage end-to-end dan screen reader masih pending |
| R12 onboarding | **Implemented + Chromium pass** | Document-first/manual-first, draft, validation summary pass; human comprehension, real artifact ingestion, dan multi-tab conflict masih pending |
| U3/U4/U5 guided work | **Implemented + Paket G automated gate pass** | Core journey, keyboard-only, exact trace, dan matrix 768/1280/1440 pass; expert ≤60 detik manusia dan screen-reader review tetap pending |

Paket F selesai pada level implementasi dan automated Chromium journey, tetapi tidak menutup U7 release gate. Validasi manusia tetap wajib untuk memastikan “Belum tahu”, deferred, source evidence, dan next action dipahami novice tanpa bantuan fasilitator.

### 19.2.7 Implementasi Paket G — status dan bukti release gate

Paket G melakukan revalidasi lintas flow, bukan hanya smoke test per halaman. Gate menjalankan aplikasi dengan backend fixture lokal, membuka route melalui Chromium, dan memeriksa state UI yang diperlukan untuk journey berikut:

- **Full surface matrix:** `analysis`, `model`, `findings`, `action-plan`, `evidence`, dan `report` pada 390/768/1280/1440 px. Semua 24 kombinasi memiliki `h1`, body, action yang berlabel, tanpa horizontal overflow, page error, atau failed API request.
- **DFD workspace:** canvas terlihat pada first viewport desktop dan memenuhi ≥55% intersection tinggi viewport; tombol Fit memeriksa geometry node setelah layout; accessible outline menyediakan node/flow; boundary review dan guided `Belum tahu` tetap tersedia.
- **Workspace keyboard contract:** Findings, Action Plan, dan Evidence mendukung `/` ke search, ArrowDown ke row, Enter membuka inspector modal mobile, Escape menutup dan mengembalikan focus ke row semula.
- **Progressive/recovery flow:** zero-match state memberi penjelasan, advanced filter hanya muncul on demand, Evidence context/intake/coverage memakai disclosure, report appendix collapsed, dan document-first onboarding dapat maju tanpa input teknis yang belum tersedia.
- **Traceability:** fixture synthetic menguji exact ID `DFD flow → finding → control → executable test` dengan URL selection canonical. Link tidak dicocokkan berdasarkan posisi row atau label yang mirip.

Artefak gate:

```bash
npm run u7:package-g -- --output /tmp/5stones-u7-package-g.json --screenshot-dir /tmp/5stones-u7-package-g-screens
npm run u7:baseline -- --output /tmp/5stones-u7-package-g-axe.json
npm run u7:package-c -- --output /tmp/5stones-u7-package-c-after-g.json
```

Hasil 2026-09-24: Paket G **9/9 checks pass**, matrix **24/24**, 0 browser/page/API error, dan 12 screenshot; axe **24/24 pass**, 0 violation, 0 serious/critical; Paket C **6/6 journey pass**. Satu mismatch ditemukan saat gate: threshold top canvas awal terlalu ketat dibanding acceptance U2; gate diperbaiki agar memvalidasi intersection ≥55% dan top orientation yang realistis. Mismatch kedua adalah selector test yang mengasumsikan colon tidak di-encode; validasi diubah untuk membaca `URLSearchParams.selected` canonical.

Status historis Paket G: **automated release evidence tersedia**. Deep visual audit lanjutan pada 2026-09-24 membuka kembali G3 karena mobile overlay, nested scrolling, tiny text, dan shell inconsistency tidak tertangkap assertion awal. U7 belum berstatus `Accepted`; jangan memakai hasil synthetic trace sebagai bukti usability participant atau menganggap axe 0 violation sebagai bukti information architecture sudah mudah digunakan.

### 19.3 Template tiket dan area kode

Setiap ticket implementasi harus menyebut: **ID finding → user problem → state/breakpoint → perubahan → acceptance → fixture → bukti**. Contoh:

> UX-R03 / tombol Update context kosong pada 390 px. Goal: reviewer mengenali dan membuka context dari header. Ubah styling action mobile secara eksplisit, tambahkan fallback label/icon berukuran sentuh. Test: lihat label, buka dialog dengan keyboard, Escape kembali ke action, ulang pada 320/390/768/1440. Done bila tidak ada action aktif kosong dan input dialog dapat diakses; sertakan screenshot before/after.

| Concern | Area implementasi yang kemungkinan disentuh |
|---|---|
| Shell/focus/label | `frontend/js/sidebar.js`, HTML page, `style.css`, `components.css` |
| Model/canvas/trace | `frontend/model.html`, `frontend/js/analysis.js`, `pages.css` |
| List/filter/inspector | `findings.html`, `action-plan.html`, `evidence.html` dan JS masing-masing |
| URL/return context | `frontend/js/ui-state.js`, sync-route helper per workspace |
| Report/revision/readability | `report.html`, `report.js`, `pages.css`; kontrak report/export bila perlu |
| Guided onboarding/context | `project-new.html`, `project.js`, evidence context dialog |
| Validation | Harness U7, fixture sintetis yang dilacak git, dependency/version runner |

Setiap PR menyentuh satu kontrak perilaku yang jelas dan menjalankan smoke lintas-workspace yang memakai komponen tersebut. Branch alignment yang sudah ada menjadi dasar kerja; strategi commit/branch per paket harus menjaga perubahan sebelumnya dapat ditelusuri. Tidak perlu mengubah engine threat modeling demi layout.

## 20. Protokol validasi dan acceptance terukur

### 20.1 Fixture standar

- Project sintetis dengan ≥2 flow yang berbeda, boundary candidate + confirmed, grounded finding dan deferred finding dari kedua framework.
- Control assigned, control unassigned, test executable dan test blocked. Definisikan expected linkage per ID, bukan posisi array atau label.
- ≥25 findings agar deep link melewati page size 20; satu source dengan section unread/deferred; satu gap tanpa owner.
- Varian run partial/preserved/stale dan report draft/signed/superseded dari snapshot sintetis. Hasil sign-off harus mengikuti gate, bukan flag UI hard-coded.
- Varian corpus besar ≥200 findings/100 controls/200 tests untuk U8. Tidak mencampur hasil performance varian ini dengan usability fixture standar.

### 20.2 Automated dan manual accessibility

1. Jalankan axe pada halaman utama dan state interaktif: filter open, inspector finding/control/test/evidence, context dialog, sidebar mobile, guided decision, report search/appendix/revision.
2. Gate: **0 critical/serious yang belum diremediasi**. Temuan moderate/minor mendapat owner dan disposition; `incomplete` wajib review manual. Jangan menafsirkan nol critical/serious sebagai seluruh WCAG otomatis terpenuhi.
3. Keyboard-only: mulai dari address/page entry; gunakan Tab/Shift+Tab/Arrow/Enter/Space/Escape. Assertion membandingkan actual focused element, visibility dan focus return; tidak mengarahkan fokus ke target secara programatik untuk melewati langkah sulit.
4. Screen reader manual minimal satu kombinasi OS/browser/reader yang dicatat, misalnya VoiceOver + Safari atau NVDA + Firefox; uji labels, list/detail, status perubahan, dialog dan outline DFD.
5. Uji 200% text resize, 400% zoom/reflow, reduced motion, dan target sentuh. Pisahkan aturan WCAG dari target produk yang lebih ketat.

### 20.3 Playwright visual dan relasi

| Test | Setup/action | Assertion wajib |
|---|---|---|
| A11Y-01 | Analysis artifact intake | Select punya nama programatik, input error terhubung |
| MOB-01 | Enam page pada 390/320 | Setiap action aktif terlihat, bernama, dapat dipilih |
| FOCUS-01 | Evidence mobile row → detail → Escape | Fokus masuk panel lalu kembali; tidak tertutup sheet |
| FOCUS-02 | Findings/Action inspector + sidebar open/close | Tidak ada background focus pada modal; desktop tetap nonmodal |
| DFD-01 | Model initial 1440×900 | Canvas unobscured intersection ≥495 px; bukan sekadar CSS min-height |
| DFD-02 | Mobile, Fit, select, fullscreen, resize | Selection terlihat, outline memilih objek sama, boundary tidak hilang |
| TRACE-01 | Flow A → Finding B → Control C → Test D | Semua ID dan relasi cocok fixture; tidak berpindah ke row pertama |
| TRACE-02 | Controls-only filter → linked test | Detail test benar terbuka, return ke filter/scroll sebelumnya |
| REPORT-01 | Initial mobile report | Height summary ≤3 viewport, appendix belum full rendered |
| REPORT-02 | Scroll dan section deep link | Header/search/TOC tidak overlap; focused item terlihat |
| REPORT-03 | Finding ke-25 melalui permalink | Section/page benar terbuka; stable selection |
| REV-01 | Signed snapshot kemudian latest draft | Snapshot yang dibaca konsisten; link latest eksplisit |
| STATE-01 | Slow API, error, partial, retry | Project id tetap ada, previous results diberi label, action recovery jelas |

Visual matrix: 390, 768, 1280, 1440 px; tambahan 390×844 dan layar pendek untuk mobile. Tetapkan fonts, viewport, reduced motion, data fixture, readiness wait, dan waktu screenshot. Compare screenshot dengan baseline yang direview; bila data berubah, perbarui baseline beserta alasan. Capture initial viewport **dan selected/error/overlay state**.

### 20.4 Studi novice

**Peserta minimum:** satu orang yang belum terbiasa dengan STRIDE/LINDDUN/DFD; untuk iterasi formatif target lima novice. Tidak boleh menyebut bot sebagai peserta.

**Instruksi netral:** “Anda menerima rancangan fitur checkout. Tentukan bagian alur yang perlu dikonfirmasi, periksa satu skenario masalah, dan catat informasi yang masih perlu diminta. Jelaskan apakah hasil sudah cukup untuk persetujuan.” Jangan menyebut tombol atau istilah yang harus diklik.

**Tugas:**

1. Dalam ≤10 detik setelah layar siap, sebutkan status dan tindakan berikutnya dengan kata sendiri.
2. Ikuti boundary review; baca sumber, pilih keputusan sesuai fixture, termasuk `Belum tahu` ketika bukti tidak cukup.
3. Buka finding terkait; jelaskan potensi dampak dan perbedaan evidence/deferred versus kerentanan terverifikasi.
4. Tautkan kebutuhan informasi atau defer dengan owner/next action; kembali ke Overview dan jelaskan perubahan.

**Catatan:** waktu per tugas, keberhasilan keputusan, salah klik/backtrack, bantuan fasilitator, istilah yang tidak dipahami, dan penilaian mudah/sulit 1–7. Jangan merekam isi dokumen sensitif; gunakan fixture.

**Acceptance minimum:** boundary/finding selesai tanpa bantuan terminologi, keputusan benar terhadap fixture, tidak menyimpulkan deferred sebagai aman atau verified. Bila peserta perlu bantuan untuk menyelesaikan langkah wajib, tandai gagal/assisted dan revisi desain. Satu peserta hanya bukti minimum, bukan jaminan seluruh populasi.

### 20.5 Studi expert

**Peserta minimum:** satu praktisi yang terbiasa dengan review arsitektur/security; target lima expert pada iterasi berikutnya.

**Instruksi:** “Mulai dari flow checkout yang ditentukan. Temukan finding terkait, control yang menanganinya, dan skenario test yang memverifikasi control tersebut. Jelaskan expected result serta evidence yang harus dikumpulkan.”

**Timer:** mulai saat workspace siap dan task diberikan, berhenti ketika test **yang benar** terbuka dan peserta dapat menunjuk expected result/evidence. Catat network wait terpisah tetapi laporkan wall-clock pengguna juga; jangan mengurangi waktu mencari atau membaca agar lolos batas.

**Acceptance minimum:** ≤60 detik, seluruh ID sesuai fixture, tanpa global re-search dan tanpa bantuan. Tambahkan kasus test blocked: peserta mengerti alasan blocked dan next action. Test executable terbuka bukan berarti test security telah dijalankan atau lulus.

### 20.6 Decision record dan penutupan gate

| Gate | Evidence | Kondisi pass | Status saat audit |
|---|---|---|---|
| G1 Automated a11y | Axe JSON per state/breakpoint | 0 unresolved critical/serious | **Pass automated: 24/24, 0 violation; screen reader pending** |
| G2 Focus/keyboard | Step log + focus/occlusion assertions + manual review | Semua tugas inti keyboard-only | **Pass automated: Paket C 6/6 + Paket G workspace journey; manual SR pending** |
| G3 Visual/responsive | Approved screenshot diff + geometry | Tidak ada blank actions/overlap; canvas/report target terpenuhi | **REOPENED: Model mobile rail menutupi canvas ±118.297 px²; open-filter dan nested-scroll state belum tercakup gate lama** |
| G4 Trace identity | Expected ID mapping + actual navigation | Flow/finding/control/test sama tanpa fallback | **Pass synthetic exact-ID: Paket G** |
| G5 Novice usability | Participant task sheet | Keputusan benar, tanpa bantuan terminologi | **Belum diuji manusia** |
| G6 Expert usability | Participant task sheet + elapsed | Correct trace ≤60 detik | **Belum diuji manusia** |
| G7 Revision/report | Snapshot fixture + UI/export assertion | Revision konsisten dan read-only | **Automated report/appendix/onboarding pass; sign/superseded approval review pending** |

Status U7 boleh ditutup setelah gate relevan lulus, dan Product/UX + QA mencatat reviewer, tanggal, fixture/revision, browser, hasil, serta gap yang masih diterima. Accessibility engine severity adalah klasifikasi temuan tool, berbeda dari prioritas backlog P0/P1.

## 21. Definition of ready, done, dan langkah berikutnya

**Ready untuk implementasi:** ticket mengacu ID UX-R, state dan persona jelas, wireframe terkait dipilih, kontrak data/route dipahami, serta acceptance dapat dijalankan. Pilihan warna final atau detail spacing boleh diputuskan selama implementasi berdasarkan target contrast/area kerja.

**Done per ticket:** kode selesai, lintas-workspace smoke yang relevan pass, tidak mengubah canonical semantics secara tidak sengaja, screenshot/trace/a11y evidence tersedia, dan status pada tabel §19 diperbarui. Jika hanya implementasi selesai tetapi studi manusia belum ada, status harus `Implemented; validation pending`.

**Done revamp:** pengguna memahami status dan batas hasil, dapat mengikuti flow/finding/control/test yang sama, menyelesaikan evidence/review, dan membaca report revision yang benar dengan keyboard maupun mobile. Tidak ada critical/serious a11y temuan terbuka pada cakupan gate, dan novice/expert task memiliki evidence manusia.

Langkah eksekusi pada paragraf ini digantikan oleh baseline §22. Urutan terbaru adalah **H0 contract freeze → H1 shared shell/lifecycle → H2 Model mobile recovery → H3 readability → H4 filters/lists → H5 page simplification → H6 release revalidation**. Screen reader dan studi manusia dilakukan pada H6 setelah P0 visual/layout selesai agar hasilnya tidak menguji desain yang sudah diketahui bermasalah.

## 22. Deep visual re-audit dan consistency remediation plan — 2026-09-24

Bagian ini adalah baseline terbaru dan mengoreksi asumsi bahwa Paket G otomatis sudah cukup untuk menutup visual/responsive gate. Jika terdapat konflik dengan status sebelumnya, gunakan §22 sebagai acuan eksekusi berikutnya.

### 22.1 Kesimpulan eksekutif

**Aplikasi belum layak dinyatakan selesai dari sisi UI/UX.** Core function dan data loading bekerja: enam workspace dapat dibuka, seluruh request API audit mendapat `200`, tidak ada console warning/error, URL state tersedia, exact-ID trace dapat dijalankan, dan axe initial-state tidak menemukan violation. Namun kemudahan penggunaan belum konsisten karena information architecture, responsive overlay, ukuran teks, filter, dan content density masih membebani pengguna.

Audit dilakukan dengan Playwright Chromium pada project **Hacktiv8 Commerce** (`9b3aeb5d-1e7b-4f62-809c-0f74b33a1510`) dengan viewport 1440×900 dan 390×844. State yang diperiksa: initial workspace, sidebar, advanced filter tertutup/terbuka, Model boundary rail, nested list scrolling, Report first viewport, heading/navigation contract, console, dan request API. Data aplikasi disalin ke temporary directory; audit tidak mengubah canonical project/report.

Yang sudah baik dan harus dipertahankan:

- Tidak ada horizontal page overflow pada enam halaman yang diuji.
- Findings, Action Plan, dan Evidence sudah memakai pola list-detail yang serupa serta URL state.
- Primary object trace DFD → finding → control → test tersedia.
- Error request dibedakan dari empty result dan hasil deferred tidak dipresentasikan sebagai “no risk”.
- Report appendix collapsed dan initial document height sudah jauh lebih terkendali daripada baseline lama.
- Keyboard focus lifecycle pada inspector inti sudah mempunyai fondasi yang benar.

Masalah utama bukan lagi “fitur tidak ada”, tetapi terlalu banyak surface dan pola yang saling bersaing. Untuk novice, status dan langkah berikutnya tenggelam dalam warning, context, card, dan navigation yang berulang. Untuk expert, density tinggi, nested scroll, small text, dan perubahan posisi control memperlambat scanning.

### 22.2 Bukti terukur dari Chromium

| Area | Bukti aktual | Dampak |
|---|---|---|
| Sidebar | `analysis.html` dan `report.html` memiliki Dashboard, New Project, Current Project, Settings. `model.html` tidak memiliki New Project/Settings. Findings/Action Plan/Evidence memiliki New Project tetapi tidak Settings. Label akhir berubah antara `Report` dan `Report & sign-off`. | Pengguna tidak bisa membangun mental model lokasi menu yang stabil. |
| Lifecycle navigation | Pada Analysis desktop workflow bar berada sekitar y=844; pada mobile baru mulai sekitar y=1.210. Halaman lain tidak memiliki workflow bar yang sama. | Tahap aktif dan next stage tidak terlihat saat pertama masuk; navigation terasa seperti footer dan menduplikasi sidebar. |
| Model mobile | Canvas mulai sekitar y=498; Boundary Review sticky rail mulai sekitar y=515 dan menutup canvas sekitar **118.297 px²**. | Pengguna tidak dapat melihat model yang sedang direview; visual utama dan inspector saling berebut area. |
| Nested scrolling | Mobile list viewport hanya ±354px, sedangkan konten Findings/Action/Evidence masing-masing sekitar 3.815/5.466/6.644px. | Scroll terasa terjebak; pengguna sulit mengetahui apakah harus scroll list atau page dan kehilangan posisi. |
| Advanced filter | Mobile field hanya sekitar 83–92px. Native multi-select menampilkan value terpotong; desktop menampilkan `More filters` sekaligus summary `Advanced filters`, sehingga ada dua disclosure untuk panel yang sama. | Filter sulit dipahami, terutama bagi touch user dan pengguna yang tidak familiar dengan multi-select browser. |
| Readability | Di first viewport, proporsi leaf text di bawah 12px: Analysis 69–78%, Model 90–92%, Findings 88–93%, Action Plan 82–90%, Evidence 81–88%, Report 55–79%. | Axe dapat hijau tetapi content tetap melelahkan dibaca; metadata penting tidak cukup menonjol. |
| Action size | Model mobile mempunyai 23 dari 24 action terlihat dengan salah satu dimensi di bawah target produk 40px; banyak toolbar action tingginya 30–36px. | Touch accuracy rendah dan command terasa padat. |
| Analysis mobile | Warning panjang memenuhi sekitar 194px sebelum overview; overview tingginya ±843px; workflow baru tampil setelahnya. | Status, top action, dan lifecycle tidak dapat dipahami dalam satu viewport. |
| Report mobile | Topbar ±165px + command bar ±121px + TOC ±59px; report hero baru mulai sekitar y=421. | Hampir setengah viewport habis untuk chrome sebelum isi laporan. |
| Heading contract | Analysis memakai nama project sebagai `h1`; Model/Findings/Action/Evidence memakai nama workspace; Report memakai judul report. | Page identity dan hierarchy berbeda untuk screen reader maupun visual scanning. |

Catatan: angka ini adalah hasil fixture audit dan bukan performance benchmark seluruh dataset. Angka tersebut cukup untuk membuktikan adanya masalah layout nyata pada state yang diuji.

### 22.3 Finding terbaru dan target outcome

| ID | Prioritas | Finding | Root cause | Outcome yang wajib dicapai |
|---|---|---|---|---|
| UX-C01 | P0 | Sidebar/shell berbeda antar-HTML | Markup sidebar disalin manual di enam file | Satu canonical shell menghasilkan menu, icon, urutan, label, active state, dan breakpoint yang sama di seluruh halaman. |
| UX-C02 | P0 | Lifecycle menu hanya ada di bawah Analysis dan menduplikasi sidebar | Workflow dibuat sebagai komponen lokal Analysis, bukan project navigation global | Tahap aktif, progress, previous/next, dan sign-off tersedia konsisten dari semua project workspace tanpa scroll. |
| UX-C03 | P0 | Boundary Review mobile menutupi DFD | Inspector rail desktop diubah menjadi sticky bottom rail tanpa closed state yang aman | Canvas terlihat dan dapat dioperasikan sebelum sheet dibuka; sheet tidak menutupi selected element dan dapat ditutup dengan Escape/swipe/button. |
| UX-C04 | P0 | Teks terlalu kecil dan action terlalu padat | Banyak token `.54rem–.68rem`, toolbar 30–36px, metadata memakai density ekstrem | Body text nyaman dibaca, metadata minimum 12px, touch target produk minimum 40px, dan hierarchy tidak bergantung pada font sangat kecil. |
| UX-C05 | P1 | Seluruh halaman masih information-heavy | Summary, helper, counters, ID, description, queue, dan command ditampilkan bersamaan | First viewport menjawab “di mana saya, status apa, tindakan berikutnya apa” tanpa membaca detail teknis. |
| UX-C06 | P1 | Advanced filter tidak konsisten dan native multi-select sulit dipahami | Tiga implementasi mirip tetapi layout/pola disclosure tidak menjadi shared component | Satu Filter component: quick view, filter count, checkbox group, active chips, reset kontekstual, desktop popover/drawer, mobile full-width sheet. |
| UX-C07 | P1 | Nested scrolling pada list panjang | List diberi fixed/max height dan overflow sendiri di dalam page | Mobile memakai page scroll atau virtualized/load-more list; desktop boleh memakai pane scroll dengan posisi dan selection yang dipertahankan. |
| UX-C08 | P1 | Terminologi, CTA, dan bahasa berubah antarhalaman | Copy ditulis per-page (`Report`, `Report & sign-off`, `View Report`, `Open report`; English bercampur `Belum tahu`) | Canonical terminology dictionary dan satu bahasa UI per locale; project data boleh tetap dalam bahasa sumber. |
| UX-C09 | P1 | Cross-page journey bergantung sidebar dan tidak mempunyai continue flow | Topbar action berbeda arah; tidak ada shared “current stage / next stage” contract | Setelah menyelesaikan review, pengguna mendapat `Save & next`, `Next unresolved`, atau `Continue to <stage>` dengan return context yang deterministik. |
| UX-C10 | P2 | List besar merender banyak content dalam pane panjang | Belum ada pagination/virtualization konsisten di workspace operasional | Corpus besar tetap responsif tanpa mengorbankan URL selection, keyboard navigation, dan scroll restoration. |

### 22.4 Target information architecture

Gunakan dua tingkat navigation dengan ownership yang jelas:

1. **Global shell/sidebar**: Dashboard, Projects/New Project, Settings. Tidak memuat urutan lifecycle project.
2. **Project workflow navigation**: Overview → Model → Findings → Action plan → Evidence → Report. Komponen ini muncul tepat di bawah topbar pada seluruh project workspace.
3. **Page-local navigation**: hanya subview yang relevan, misalnya Context/System/Feature pada Model atau Controls/Tests pada Action Plan.

Jangan menampilkan lifecycle yang sama sekaligus di sidebar dan footer Analysis. Satu komponen shared harus menjadi source of truth untuk label, count, readiness, href, active state, dan responsive behavior.

Desktop target:

```text
┌ Global sidebar ────┬ Project / page title ───────────── Primary action ┐
│ Dashboard          ├ Overview › Model › Findings › Actions › Evidence › Report
│ Projects           ├───────────────────────────────────────────────────┤
│ New project        │ Page status + one-line guidance                  │
│ Settings           │ Main task surface                 Inspector       │
└────────────────────┴───────────────────────────────────────────────────┘
```

Mobile target:

```text
┌ Menu  Project name                         Primary action ┐
├ Stage 2 of 6 · Model                  [Change stage ▾]    ┤
├ Page title + one-line state
├ Main task surface
└ [Previous]                         [Continue / Next action] ┘
```

Pada mobile, full six-step bar tidak dipaksa masuk satu baris. Tampilkan current stage, stage count, dan dropdown/bottom sheet untuk berpindah stage. Previous/Continue hanya muncul bila meaningful; jangan membuat CTA palsu jika tahap berikutnya blocked.

### 22.5 Shared shell dan navigation requirements

#### UX-C01 · Canonical shell

Action:

- Hapus enam copy sidebar yang berbeda dan buat satu canonical navigation config/component.
- Canonical label: `Overview`, `DFD model`, `Findings`, `Action plan`, `Evidence`, `Report & sign-off` untuk project workflow; `Dashboard`, `Projects`, `New project`, `Settings` untuk global shell.
- Gunakan icon, spacing, active indicator, footer/version, dan accessible name yang sama.
- Active route ditentukan dari route contract, bukan class hardcoded yang berbeda per HTML.
- Project/run/selection/filter state tetap dibawa oleh `UIState.route()`.
- Bila shared navigation dirender dengan JavaScript, sediakan fallback link atau server/build-time partial agar navigation tidak hilang ketika script gagal.

Goal:

- Pengguna dapat berpindah halaman tanpa mencari ulang lokasi menu.
- Signature urutan/label menu identik pada enam halaman dan seluruh breakpoint.
- Sidebar tidak lagi menjadi tempat campuran global navigation dan lifecycle progress.

Acceptance:

- Playwright membandingkan canonical nav signature pada enam route; hasil harus identik kecuali `aria-current`.
- Satu dan hanya satu item memiliki `aria-current="page"`.
- Tidak ada variasi `Report` versus `Report & sign-off`, atau Settings yang hilang pada halaman tertentu.
- Sidebar mobile closed diberi `inert`; open state focus trapped; Escape kembali ke trigger.

#### UX-C02 · Shared project workflow navigation

Action:

- Pindahkan lifecycle bar dari bagian bawah Analysis menjadi shared component setelah topbar.
- Tampilkan readiness/count singkat, bukan deskripsi panjang: contoh `Model · 2 pending`, `Findings · 30 review`.
- Gunakan link asli untuk navigation; button hanya untuk action lokal.
- Desktop dapat memakai six-step compact navigation; mobile memakai current-stage control dan stage picker.
- Simpan `run`, filter, selection, dan return route saat berpindah.
- Hilangkan legacy result tabs dari Overview bila seluruh result sudah mempunyai dedicated workspace; jangan mempertahankan dua UI untuk data yang sama.

Goal:

- User selalu tahu current stage dan dapat melanjutkan alur dari semua halaman.
- Analysis menjadi lifecycle overview, bukan hub yang juga menyimpan second copy seluruh result UI.

Acceptance:

- Current stage terlihat tanpa scroll pada 390/768/1280/1440.
- Pindah Overview → Model → Findings → Action Plan → Evidence → Report memerlukan maksimal satu activation per tahap.
- Browser Back mengembalikan selection/filter/scroll yang relevan.
- Tidak ada bottom lifecycle bar terpisah pada Analysis.

### 22.6 Page-specific simplification

#### Analysis / Overview

Keep:

- Run status dan actual phase progress.
- Satu readiness statement.
- Top next actions yang benar-benar dapat dijalankan.

Change:

- Ubah page identity menjadi `Analysis overview`; project name berada di breadcrumb/topbar, bukan menjadi `h1` halaman.
- Ringkas warning menjadi `1 phase warning · 11 sign-off blockers` dengan satu kalimat top issue dan `View details`.
- Tampilkan maksimal tiga next actions; sisanya melalui `View all actions` atau workspace tujuan.
- Gunakan maksimal tiga summary metric utama. Hindari empat metric jika seluruh risk belum scored; prioritaskan `Needs review`, `Evidence gaps`, dan `Sign-off state`.
- Project Context desktop menjadi compact summary satu baris/card; detail dan editing berada di Evidence/context dialog.
- Hapus workflow footer setelah shared project navigation tersedia.

Goal: dalam ≤10 detik, novice dapat menyebut status, alasan belum siap, dan satu tindakan berikutnya.

#### Model / DFD

Keep:

- Canvas, Context/System/Feature selector, Fit, Fullscreen, selected-element trace.

Change:

- Mobile: Boundary Review tertutup secara default. Tampilkan button `Review boundaries (2)`; buka sebagai modal bottom sheet hanya setelah aktivasi.
- Sheet memiliki close button, title, item count, focus trap, dan max-height; saat ditutup, canvas kembali 100% interactive.
- Saat sheet terbuka, selected node/flow tetap dapat terlihat melalui pan/fit atau sheet dapat diminimize.
- Pindahkan long readiness/helper copy ke compact status/disclosure. `New to threat modeling?` menjadi dismissible guidance.
- `More` hanya berisi advanced commands; export dikelompokkan dalam satu submenu.
- Naikkan ukuran level selector dan toolbar target; jangan memakai 30px action pada touch viewport.

Goal: canvas menjadi visual utama; boundary/evidence detail hadir on demand dan tidak pernah menutupi model tanpa aksi pengguna.

Acceptance:

- Initial 390×844: minimum 240px area canvas terlihat dan tidak tertutup rail/sheet.
- Initial 1440×900: canvas intersection ≥55% viewport dan node tidak overlap setelah Fit.
- Rect intersection canvas versus closed inspector = 0.
- Open sheet mempunyai satu modal focus scope; Escape/Close kembali ke trigger; selected element tetap ada.

#### Findings

Change:

- Row default hanya menampilkan framework/category, state, concise title, scenario/final risk, dan primary DFD status.
- Sembunyikan full UUID dan paragraph scenario dari list; tampilkan short display ID dan detail lengkap di inspector.
- Gunakan satu baris plain-language summary maksimal dua line pada mobile bila dibutuhkan.
- `Start guided finding review` menjadi primary CTA hanya bagi guided/novice mode; expert mode memakai search sebagai primary task.
- Detail inspector mengelompokkan: Scenario → Evidence → DFD interaction → Risk → Controls/tests → Decision.

Goal: expert dapat scan 10 rows tanpa membaca paragraph; novice tetap dapat memulai guided review tanpa memahami STRIDE/LINDDUN terlebih dahulu.

#### Action Plan

Change:

- Pertahankan queue summary tetapi hanya tampilkan kartu yang count-nya >0; `0` state digabung menjadi status line, bukan card besar.
- Pisahkan view `Controls` dan `Tests` secara jelas melalui quick view/tab; jangan memaksa keduanya dibaca dalam list campuran jika user memilih task spesifik.
- Row default: type, title, priority, status/executability, owner; finding/checklist detail di inspector.
- Setelah control dipilih, tampilkan direct ordered trace `Control → Threat → DFD → Tests`.

Goal: reviewer langsung melihat item yang membutuhkan applicability/owner/test decision, bukan seluruh metadata sekaligus.

#### Evidence

Change:

- First viewport hanya memuat readiness summary, search/quick view, dan unresolved queue.
- `Add evidence` dan `Source coverage` menjadi secondary action/disclosure; jangan mengambil dua full-width card sebelum list pada desktop.
- Dedupe `Question` dan `Next action`. Jika keduanya sama, tampilkan sekali sebagai `Question to answer`; next action hanya muncul bila benar-benar berbeda dan actionable.
- Row default: type, area/title, priority, owner/state, concise question. Linked object, source locator, notes, dan full next action di inspector.
- Context edit memakai satu canonical CTA; hilangkan duplikasi `Update context` versus `Edit project context` pada desktop.

Goal: pengguna melihat unresolved evidence pertama tanpa melewati intake/coverage detail, dan memahami siapa melakukan apa berikutnya.

#### Formal Report

Change:

- Mobile topbar hanya satu primary action; kelompokkan MD/CSV/JSON dalam `Export` menu. `Save draft`/`Sign report` mengikuti revision state dan tidak semuanya dipaksa satu baris.
- Ringkas command bar: search + summary count; TOC menjadi stage/section picker pada mobile.
- Bila `0 scored + N deferred`, ganti empat severity tile `—` dengan satu explicit disposition card: `No findings scored · N awaiting evidence/review`.
- Tampilkan maksimal tiga blocker pada overview dengan `View all N blockers`.
- Provenance six-card row dipadatkan menjadi disclosure/table; field tetap tersedia untuk audit/export.
- Full appendix tetap tersedia saat print/export, tetapi web initial view tetap bounded.

Goal: report reader memahami disposition, blocker, revision, dan approval state sebelum detail teknis, tanpa salah mengartikan `—` sebagai aman.

### 22.7 Unified filter and list-detail contract

Semua Findings, Action Plan, dan Evidence wajib memakai komponen dan urutan yang sama:

```text
[Search................................] [View ▾] [Filters 3] [Reset]
[Active chip] [Active chip]
```

Filter panel contract:

- Satu disclosure trigger saja: `Filters` + active count. Hilangkan summary kedua `Advanced filters` yang dapat diklik terpisah.
- Desktop: anchored popover/drawer dengan lebar 420–560px atau full toolbar expansion yang benar-benar 100% width.
- Mobile: full-width bottom sheet/dialog; bukan grid 83–92px di setengah toolbar.
- Multi-value memakai checkbox list/searchable combobox dengan explicit selected state, bukan native `<select multiple size="2/3">`.
- Urutan field stabil: Type/Framework → Risk/Priority → Status/State → Mapping/Executability → Owner → Sort.
- `Reset` hanya prominent bila ada filter aktif; active chips dapat dihapus satu per satu.
- Apply dapat live bila murah dan focus stabil; jika memakai sheet, sediakan `Show N results` serta `Clear all`.
- URL state, Back/Forward, row selection, dan scroll position harus tetap deterministik.

Acceptance:

- Pada 390px, panel minimal selebar viewport minus 32px; setiap field memakai full usable width dan tidak ada value terpotong.
- Hanya satu control mengubah open/closed state dan `aria-expanded` sinkron.
- Filter dapat digunakan keyboard-only dan touch-only tanpa modifier key.
- Zero matches menampilkan active filters, clear action, dan tidak dianggap sebagai zero canonical data.
- Findings/Action/Evidence memakai spacing, label, chip, focus, dan reset behavior yang sama.

List-detail contract:

- Desktop ≥1024: list + sticky nonmodal inspector; list boleh mempunyai own scroll jika keyboard/scroll restoration terjamin.
- Tablet/mobile: satu page scroll untuk queue; inspector menjadi modal sheet setelah row dipilih.
- Jangan memakai 354px nested list untuk ribuan pixel content pada mobile. Gunakan pagination/load more/virtualization dengan page scroll.
- Close inspector mengembalikan fokus dan visible list position ke row asal.
- Deep link membuka exact row walaupun berada di page berikutnya atau di luar filter; beri banner `Opened linked item outside current filters`.

### 22.8 Visual, typography, content, dan interaction tokens

Typography target produk:

- Default body: 14–16px, line-height 1.45–1.6.
- Metadata/caption: minimum 12px; hindari `.54rem–.62rem` untuk informasi yang perlu dibaca.
- Page title: satu `h1` yang menjelaskan workspace, bukan project name.
- Full UUID tidak tampil sebagai metadata utama; gunakan display ID dan copy action bila exact ID diperlukan.

Interaction target:

- Touch target produk minimum 40×40px; primary/critical mobile action target 44×44px.
- Icon-only action wajib mempunyai accessible name dan tooltip desktop, tetapi label visible dipakai untuk aksi utama.
- Satu primary CTA per first viewport. Secondary action dikelompokkan dalam `More`/`Export`/context menu.
- Sticky/fixed element tidak boleh menutup focused item, canvas, atau footer action.

Content style:

- Pilih satu bahasa UI per locale. Untuk UI English, ganti `Belum tahu` menjadi `Not sure — evidence missing`; bila UI Bahasa Indonesia akan didukung, terjemahkan seluruh shell dan action secara konsisten melalui dictionary.
- Gunakan kalimat singkat dan action-oriented. Hindari paragraph warning berisi banyak blocker yang dipisahkan titik tengah.
- Canonical nouns: `Overview`, `DFD model`, `Finding`, `Control`, `Verification test`, `Evidence gap`, `Report & sign-off`.
- Canonical verbs: `Open`, `Review`, `Resolve`, `Assign`, `Verify`, `Defer`, `Continue` sesuai konsekuensi. Jangan berganti antara `View/Open/Edit/Update` untuk action yang sama.

### 22.9 Paket implementasi terbaru

Paket H scale/polish **ditahan** sampai H0–H5 berikut selesai. Ini mencegah optimasi performa dilakukan di atas shell/layout yang masih akan berubah.

| Paket | Prioritas | Scope | Owner utama | Dependensi | Deliverable | Exit gate |
|---|---|---|---|---|---|---|
| H0 · Contract freeze | P0 | UX-C01/C02/C08 | Product + UX + FE lead | Tidak ada | Canonical IA, nav labels, page title, CTA dictionary, responsive workflow contract | Review Product/UX + route contract test tersedia |
| H1 · Shared shell & lifecycle | P0 | UX-C01/C02/C09 | Frontend + QA | H0 | Shared global sidebar, shared project workflow nav, consistent topbar, removal workflow footer/legacy duplicate navigation | Nav signature 6/6 route sama; current stage above fold seluruh breakpoint |
| H2 · Model mobile recovery | P0 | UX-C03/C04 | Frontend + UX + QA | H0; dapat paralel dengan H1 setelah contract stabil | Canvas-first mobile, closed boundary sheet, safe open/close/focus/selection, touch-size toolbar | 0 canvas-sheet overlap saat closed; ≥240px canvas terlihat mobile; keyboard/touch pass |
| H3 · Readability & density | P0 | UX-C04/C05 | Design/UX + Frontend | H0; token dipakai H1/H2 | Typography tokens, warning summary, one-primary-CTA rule, compact row/card hierarchy | Tidak ada essential text <12px; target size pass; first viewport task statement pass |
| H4 · Unified filters & lists | P1 | UX-C06/C07/C10 | Frontend + QA | H1 + H3 | Shared filter component, checkbox groups, active chips, mobile sheet, page-scroll list/pagination | 390px no clipping/nested-scroll trap; keyboard/touch/URL state pass |
| H5 · Page simplification | P1 | UX-C05/C08/C09 | Product/UX + Frontend | H1–H4 | Analysis/Findings/Actions/Evidence/Report content reduction dan canonical copy | Per-page acceptance §22.6 pass; one primary CTA; no duplicated action/copy |
| H6 · Release revalidation | P0 gate | Seluruh UX-C | QA + Accessibility + UX/Product | H1–H5 complete | Expanded Playwright matrix, axe, screen reader, novice/expert study | G1–G7 mempunyai evidence; tidak ada P0 open |

Urutan wajib: **H0 → H1 → H2 → H3 → H4 → H5 → H6**. H2 dan persiapan H3 boleh paralel setelah H0, tetapi H6 hanya dijalankan setelah seluruh implementation package selesai.

#### 22.9.1 Checklist eksekusi per paket

H0 · Contract freeze:

- [x] H0-A01 — Inventaris route, sidebar, workflow, breadcrumb, title, topbar, dan footer; fixture/test lulus pada 2026-09-24. Lihat §22.15.1.
- [x] H0-A02 — Setujui pemisahan Global shell versus Project workflow; contract dibekukan di `fixtures/h0_contract_freeze.json`.
- [x] H0-A03 — Tetapkan canonical route/label/icon/order dan dictionary noun/verb.
- [x] H0-A04 — Tetapkan satu `h1`, satu primary CTA, dan status placement untuk tiap route.
- [x] H0-A05 — Putuskan responsive pattern: desktop step navigation, mobile current-stage picker.
- [x] H0-A06 — Tambahkan contract fixture/test yang mendeteksi sidebar/workflow drift saat ini.
- [x] H0-A07 — Capture baseline Playwright initial + interactive states; simpan manifest redacted dan raw screenshot di `/tmp`.
- [x] H0-A08 — Jalankan contract gate baseline-drift detection; mode `--assert-target` disiapkan untuk setelah H1.

H1 · Shared shell & lifecycle:

- [ ] Buat satu source of truth untuk sidebar dan workflow navigation.
- [ ] Migrasikan enam project HTML ke shell yang sama.
- [ ] Pindahkan workflow dari bottom Analysis ke shared top project navigation.
- [ ] Hapus duplicate/legacy navigation dan result entry point yang tidak lagi digunakan.
- [ ] Pertahankan project/run/filter/selection pada semua href.
- [ ] Selaraskan heading, breadcrumb, active state, dan topbar action.
- [ ] Jalankan nav signature, Back/Forward, mobile drawer, dan keyboard regression.

H2 · Model mobile recovery:

- [ ] Default mobile rail menjadi closed; tambahkan trigger dengan pending count.
- [ ] Implement modal bottom sheet dengan close/focus trap/focus return.
- [ ] Pastikan canvas tetap terlihat, pan/zoom/Fit bekerja, dan selection preserved.
- [ ] Kelompokkan advanced/export command di `More`.
- [ ] Naikkan target toolbar/level selector sesuai token.
- [ ] Tambahkan geometry assertion sheet closed/open, fullscreen, resize, dan orientation change.

H3 · Readability & density:

- [ ] Inventaris seluruh `.54rem–.68rem` dan petakan ke semantic typography tokens.
- [ ] Terapkan minimum 12px untuk essential metadata dan 14–16px untuk body/task copy.
- [ ] Terapkan target action 40px/44px dan exception list yang disetujui.
- [ ] Ringkas warning, helper, counter, dan empty-state copy.
- [ ] Hilangkan full UUID dari default row; pertahankan di inspector/copy action.
- [ ] Jalankan 200% text resize, 400% reflow, short-height, dan reduced-motion check.

H4 · Unified filters & lists:

- [ ] Buat shared Filter component dan API state adapter untuk tiga workspace.
- [ ] Ganti native multi-select dengan checkbox/searchable selection.
- [ ] Implement desktop drawer/popover dan mobile full-width filter sheet.
- [ ] Satukan active chips, count, clear/reset, zero-result recovery, dan sort behavior.
- [ ] Hapus fixed-height nested mobile list; pilih page scroll + pagination/load more atau accessible virtualization.
- [ ] Pertahankan deep-link, exact selection, keyboard list navigation, URL, dan scroll restoration.

H5 · Page simplification:

- [ ] Analysis mengikuti hierarchy/status/next-action contract §22.6.
- [ ] Findings dan Action Plan memakai compact row serta ordered inspector grouping.
- [ ] Evidence mendahulukan unresolved queue dan dedupe Question/Next action.
- [ ] Report mengelompokkan export, mengganti empty severity tiles, dan collapse blocker/provenance.
- [ ] Hilangkan duplicate CTA (`Update/Edit context`, repeated report/model links) yang tidak memberi context tambahan.
- [ ] Jalankan content review novice/expert untuk istilah, bahasa, dan deferred-risk interpretation.

H6 · Release revalidation:

- [ ] Jalankan expanded Playwright state matrix §22.11 dan simpan JSON/screenshot diff.
- [ ] Jalankan axe pada initial + interactive state; review `incomplete` secara manual.
- [ ] Jalankan keyboard-only dan minimal satu screen-reader combination.
- [ ] Jalankan novice dan expert human journey §22.12.
- [ ] Catat residual issue, owner, accepted risk, fixture/revision, browser, tanggal, dan reviewer.
- [ ] Tutup U7 hanya setelah G1–G7 dan seluruh P0 memiliki bukti.

### 22.10 Area kode yang diperkirakan berubah

| Concern | Area utama |
|---|---|
| Shared shell/navigation | `frontend/js/sidebar.js`, `frontend/js/ui-state.js`, enam HTML workspace, shared CSS shell |
| Lifecycle/header contract | `analysis.html`, `model.html`, `findings.html`, `action-plan.html`, `evidence.html`, `report.html`, route sync helper |
| Model mobile sheet/canvas | `frontend/model.html`, `frontend/js/analysis.js`, `frontend/js/focus-manager.js`, `frontend/css/pages.css` |
| Unified filter | HTML/JS Findings, Action Plan, Evidence; shared filter helper/component; `pages.css` |
| Mobile list strategy | `findings.js`, `action-plan.js`, `evidence.js`, optional shared pagination/virtualization helper |
| Report simplification | `frontend/report.html`, `frontend/js/report.js`, `pages.css`; backend hanya bila summary contract belum cukup |
| Content dictionary | Shared labels/config, sidebar/workflow/topbar/page copy |
| Validation | `tools/u7_release_gate.js`, Paket C/G gate, gate baru H1–H6, fixture U7 |

Backend canonical threat/DFD/control/test semantics tidak boleh diubah hanya untuk menyelesaikan layout. UI projection boleh diringkas, tetapi exact IDs, deferred state, provenance, dan trace relation harus tetap tersedia di inspector/export.

### 22.11 Playwright regression matrix baru

Route: Analysis, Model, Findings, Action Plan, Evidence, Report.

Viewport minimum: 390×844, 768×900, 1280×900, 1440×900. Tambahkan 320px smoke untuk shell/filter dan layar pendek mobile untuk sheet.

State wajib per route:

| State | Assertion |
|---|---|
| Initial | Heading, current stage, one primary CTA, no horizontal overflow, no blank action |
| Sidebar closed/open | Canonical menu signature, focus trap/return, active route benar |
| Workflow navigation | Current stage visible; exact route/project/run preserved; Back restore |
| Warning/details | Collapsed initial; expand tanpa mendorong primary task keluar secara berlebihan |
| Filters closed/open/applied/zero | Satu disclosure, full-width mobile sheet, no clipped value, chip/reset/URL benar |
| List first/middle/deep-link | Tidak ada nested scroll trap mobile; exact row dan scroll restore |
| Inspector open/close | Desktop region versus mobile modal, no occlusion, focus return |
| Model canvas initial/Fit/sheet/fullscreen | Node non-overlap, canvas visible, closed sheet intersection 0, selection preserved |
| Report draft/signed/superseded | Action availability benar; summary bounded; deferred tidak terlihat sebagai zero risk |
| 200% text / reduced motion | Reflow tanpa clipping; navigation/action tetap usable |

Assertion tambahan yang harus dimasukkan ke gate:

- Canonical sidebar/workflow signature equality antarroute.
- `getBoundingClientRect()` intersection untuk canvas versus rail/sheet, focused item versus sticky/fixed layer.
- Essential text computed font size ≥12px; body/task copy mengikuti token baru.
- Product touch target ≥40px dengan exception yang terdokumentasi.
- Mobile operational list tidak memakai nested scroll fixed-height, kecuali komponen virtualized yang mempunyai explicit accessibility contract.
- First viewport visible-text budget dan action count dicatat sebagai regression metric, bukan hard-coded tanpa review.
- Screenshot comparison mencakup initial, filter open, inspector open, warning expanded, dan Model sheet open/closed; bukan initial page saja.

### 22.12 Human usability journeys setelah remediasi

Novice:

1. Buka Overview dan jelaskan status + next action dalam ≤10 detik.
2. Masuk Model melalui shared workflow, buka boundary queue, pilih `Not sure — evidence missing` tanpa bantuan istilah.
3. Lanjut ke finding terkait, jelaskan bahwa deferred bukan confirmed vulnerability.
4. Tambahkan/defer evidence owner dan next action, lalu kembali ke Overview.

Acceptance: tanpa bantuan navigasi/terminologi; tidak salah mengartikan `0 scored`; tidak kehilangan posisi setelah sheet/inspector ditutup.

Expert:

1. Dari DFD flow yang ditentukan, buka exact finding.
2. Buka control dan executable/blocked test yang benar.
3. Jelaskan expected result dan evidence yang harus dikumpulkan.

Acceptance: exact ID trace ≤60 detik, tanpa global re-search, tanpa fallback row pertama, dan filter/selection tetap terjaga.

Tambahkan satu task mobile untuk kedua persona: stage switching, filter, row selection, inspector close, dan return. Catat wall-clock, salah klik, backtrack, bantuan, istilah tidak dipahami, dan rating kemudahan 1–7.

### 22.13 Definition of done terbaru

Remediasi UI/UX dinyatakan selesai hanya jika:

- [ ] UX-C01–UX-C04 P0 selesai dan mempunyai visual/interaction evidence.
- [ ] Sidebar dan project workflow benar-benar shared, bukan enam copy yang kebetulan tampak serupa.
- [ ] Tidak ada canvas/inspector/sticky overlap pada seluruh state matrix.
- [ ] Essential text dan target action memenuhi token produk baru.
- [ ] Advanced filter dan list-detail contract sama pada tiga operational workspace.
- [ ] First viewport tiap halaman mempunyai satu page goal, satu status, dan satu primary next action.
- [ ] Deferred/scored/blocker state tetap akurat setelah content disederhanakan.
- [ ] Axe 0 critical/serious, keyboard-only pass, dan screen-reader manual review selesai.
- [ ] Novice dan expert human task memenuhi acceptance tanpa bantuan.
- [ ] Product/UX dan QA mencatat sign-off, tanggal, browser, fixture/revision, serta accepted residual risk.

Sampai seluruh checkbox tersebut terpenuhi, status aplikasi adalah **core workflow technically functional, UX remediation in progress**, bukan “UX complete”.

### 22.14 Success metrics dan project goal alignment

| Metric | Baseline terbaru | Target release |
|---|---:|---:|
| Canonical sidebar/menu variants | ≥3 variasi pada 6 route | 1 shared signature |
| Route dengan current lifecycle stage above fold | Analysis tidak above fold; 5 route tidak memiliki komponen | 6/6 route |
| Closed Model mobile overlay terhadap canvas | ±118.297 px² | 0 px² |
| Essential text di bawah 12px | Tinggi; total leaf text first viewport 55–93% tergantung route | 0 essential text; exception dekoratif terdokumentasi |
| Mobile operational workspace dengan fixed nested list scroll | 3/3 | 0/3, atau accessible virtualization yang disetujui |
| Mobile advanced-filter field width | ±83–92px | Full usable width; tidak clipping pada 320/390px |
| Primary CTA per first viewport | Beragam/duplikat | Tepat 1 per route/state |
| Novice status comprehension | Belum diuji | Status + next action dijelaskan ≤10 detik tanpa bantuan |
| Expert exact trace | Synthetic pass; manusia belum diuji | DFD → finding → control → test ≤60 detik tanpa fallback/search ulang |
| Automated accessibility | Axe initial 0 serious/critical | Tetap 0 pada initial + interactive states; incomplete direview |
| Console/API stability | 0 error pada audit | Tetap 0 untuk seluruh regression journey |

Alignment terhadap main product goal:

- **Threat modeling correctness** tetap dijaga melalui exact canonical DFD/finding/control/test IDs dan deferred-risk semantics.
- **Ease of use** dicapai melalui shared lifecycle, progressive disclosure, compact list, dan next-action continuity.
- **Auditability** tetap tersedia di inspector, source locator, revision metadata, dan export; detail tidak dihapus, hanya dipindahkan dari first viewport.
- **Novice support** memakai plain-language guided path dan explicit insufficient-evidence choice.
- **Expert efficiency** memakai direct trace, search/filter state, keyboard interaction, compact rows, dan deterministic return context.
- **Release confidence** berasal dari gabungan geometry/assertion, screenshot review, accessibility, dan human task—not dari satu jenis gate saja.

### 22.15 Milestone delivery plan dan executable action backlog

Bagian ini adalah sumber kerja utama untuk implementasi. Checklist pada §22.9.1 tetap menjadi ringkasan, sedangkan tabel berikut menjelaskan unit kerja yang harus dibuat, hasil yang diharapkan, dan cara membuktikan bahwa pekerjaan benar-benar selesai.

Aturan status:

- `TODO`: belum mulai.
- `IN PROGRESS`: sedang dikerjakan dan belum memenuhi seluruh acceptance.
- `BLOCKED`: mempunyai blocker yang tercatat beserta owner dan next action.
- `DONE`: implementasi, automated check, dan bukti visual/manual yang diwajibkan sudah tersedia.
- Action tidak boleh dipindahkan ke `DONE` hanya karena tampilan terlihat benar pada satu viewport.

#### Milestone UX-M0 — Contract dan baseline freeze

**Goal:** seluruh tim memakai satu definisi tentang navigasi, penamaan, hierarchy, state URL, breakpoint, dan success criteria sebelum markup/CSS diubah. Milestone ini mencegah enam halaman kembali berkembang dengan pola berbeda.

**Entry criteria:** audit §22.1–§22.3 tersedia dan route utama dapat dibuka menggunakan fixture yang sama.

| ID | Status | Action spesifik | Output yang harus tersedia | Validasi/acceptance |
|---|---|---|---|---|
| H0-A01 | **DONE — 2026-09-24** | Inventaris semua item sidebar, workflow navigation, breadcrumb, page title, topbar action, dan footer navigation pada enam route. Tandai duplicate, route-only, dan obsolete item. | Matriks `route × navigation item` di §22.15.1 dan fixture `fixtures/h0_a01_navigation_inventory.json`; test `tests/test_h0_a01_navigation_inventory.js`. | Test statis lulus; seluruh active navigation control pada baseline terklasifikasi. |
| H0-A02 | **DONE — 2026-09-24** | Bekukan IA: global shell hanya `Dashboard`, `Projects`, `New project`, `Settings`; project workflow berurutan `Overview`, `DFD model`, `Findings`, `Action plan`, `Evidence`, `Report & sign-off`. | `fixtures/h0_contract_freeze.json` bagian `global_shell` dan `project_workflow`. | Urutan, label, icon key, scope, route, dan aturan shared shell tervalidasi oleh H0 contract gate. Implementasi saat ini masih memiliki drift yang diserahkan ke H1. |
| H0-A03 | **DONE — 2026-09-24** | Tetapkan route contract untuk `project`, `run`, filter, selected object, return target, dan report revision. Definisikan parameter required, optional, dan invalid-state fallback. | `fixtures/h0_contract_freeze.json` bagian `url_state`; legacy hash mapping dan transition rules. | Required/optional key unik, enum phase/view lengkap, selected ID pattern, legacy mapping, preservation, dan invalid-state policy tervalidasi. |
| H0-A04 | **DONE — 2026-09-24** | Bekukan heading contract: breadcrumb/context, satu `h1`, status label, helper text, dan satu primary CTA untuk setiap route/state. | `fixtures/h0_contract_freeze.json` bagian `page_contracts`; static H0-A01 test mengunci satu `h1` per route. | Enam page goal, status, primary CTA, dan secondary action contract tersedia; baseline aktual yang belum canonical menjadi input H1. |
| H0-A05 | **DONE — 2026-09-24** | Buat canonical content dictionary untuk noun, verb, status, empty state, insufficient evidence, deferred risk, dan report lifecycle. | `fixtures/h0_contract_freeze.json` bagian `content_dictionary`. | Dictionary default `en-US`, state semantics, deferred/not-scored wording, dan verb consistency tervalidasi tanpa mixed copy pada canonical values. |
| H0-A06 | **DONE — 2026-09-24** | Tetapkan responsive contract untuk desktop sidebar, mobile drawer, workflow step navigation/current-stage picker, inspector, filter sheet, dan Model boundary sheet. | `fixtures/h0_contract_freeze.json` bagian `responsive_contract`; breakpoint/state matrix 320/390/768/1280/1440px. | Breakpoint, overlay focus/scroll behavior, no-overflow rule, canvas 55%, dan mobile sheet target tervalidasi sebagai target contract. |
| H0-A07 | **DONE — 2026-09-24** | Ambil baseline screenshot dan geometry/typography metrics untuk semua route dan state kritis sebelum implementasi. | `fixtures/h0_a07_baseline_manifest.json`; runner `tools/h0_a07_baseline.js`; raw JSON/screenshots di `/tmp/5stones-h0-a07-custom.mUeNoo/`. | Playwright Chromium: 24 initial route/viewport, 15 interactive state, 39 screenshot, 0 page error, 0 API failure, 0 blank action, 0 horizontal overflow. |
| H0-A08 | **DONE — 2026-09-24** | Tambahkan contract test yang mendeteksi variasi sidebar/workflow saat ini dan menyediakan mode target untuk H1. | `tools/h0_contract_freeze_gate.js`; baseline inventory fixture/test. | Default drift-detection pass mempertahankan NAV-C01–NAV-C06 sebagai historical baseline; `--assert-target` memverifikasi canonical static/runtime shell dan sekarang pass. |

#### 22.15.1 H0-A01 result — route × navigation inventory

Baseline ini dibaca langsung dari enam file route dan dikunci oleh fixture/test berikut:

- Fixture: `fixtures/h0_a01_navigation_inventory.json`.
- Contract test: `node tests/test_h0_a01_navigation_inventory.js`.
- Result: **PASS** pada 2026-09-24.
- Scope: static route markup. Dynamic href yang diisi oleh `UIState` tetap dicatat berdasarkan semantic target, bukan nilai `#` sebelum project ID tersedia.

Legend: `✓` hadir dan semantically shared; `△` hadir tetapi section/label/availability berbeda; `D` duplicate/contextual duplicate; `R` route-only; `—` tidak tersedia; `O` obsolete active control. `O` belum ditemukan pada baseline ini, tetapi kolom tersebut tetap wajib dipertahankan pada review berikutnya.

| Navigation item | `analysis.html` | `model.html` | `findings.html` | `action-plan.html` | `evidence.html` | `report.html` | Baseline classification |
|---|---:|---:|---:|---:|---:|---:|---|
| Dashboard | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Shared global; target `/index.html`. |
| New Project | ✓ | — | ✓ | ✓ | ✓ | ✓ | Shared global tetapi hilang pada Model. |
| Settings & BYOK | ✓ | — | — | — | — | ✓ | Shared global tetapi hanya tersedia pada Analysis/Report. |
| Analysis | ✓ current | △ Workspace | ✓ | ✓ | ✓ | △ Current Project | Shared workflow; section berbeda pada Model/Report. |
| DFD Model | △ `#` until bound | ✓ current | ✓ | ✓ | ✓ | △ `#` until bound | Shared workflow; route href dinamis. |
| Findings | ✓ | ✓ | ✓ current | ✓ | ✓ | ✓ | Shared workflow. |
| Action plan | ✓ | ✓ | ✓ | ✓ current | ✓ | ✓ | Shared workflow. |
| Evidence | ✓ | ✓ | ✓ | ✓ | ✓ current | ✓ | Shared workflow. |
| Report / Report & sign-off | △ `Report` | ✓ `Report & sign-off` | ✓ `Report & sign-off` | ✓ `Report & sign-off` | ✓ `Report & sign-off` | △ `Report` current | One semantic destination with inconsistent labels. |
| Context workflow step | R | — | — | — | — | — | Analysis-only workflow stage; no sidebar equivalent. |
| Model workflow step | D | — | — | — | — | — | Duplicate of DFD Model sidebar item. |
| Findings workflow step | D | — | — | — | — | — | Duplicate of Findings sidebar item. |
| Action plan workflow step | D | — | — | — | — | — | Duplicate of Action plan sidebar item. |
| Evidence workflow step | D | — | — | — | — | — | Duplicate of Evidence sidebar item. |
| Sign-off workflow step | D + label variant | — | — | — | — | — | Duplicate of Report destination; label differs from Report & sign-off. |
| Report section TOC | — | — | — | — | — | R | Report-local navigation: Overview, Trust boundaries, Threat scenarios, Controls, Tests, Evidence gaps, Assumptions. |

**Inventory counts:** Analysis `9`, Model `7`, Findings `8`, Action Plan `8`, Evidence `8`, Report `9` sidebar links. Project workflow steps are rendered only by Analysis (`6` steps). No route has a semantic breadcrumb. No route has footer navigation; `.sidebar-footer` is branding only. Evidence has a dialog `<footer>`, but it contains form actions and is not route navigation.

| Route | Back control | Page title pattern | Topbar action inventory | Classification |
|---|---|---|---|---|
| Analysis | `Back to dashboard` | Dynamic project name as topbar `h1` | `View Report`, `Run analysis` | View Report duplicates sidebar Report; Run analysis is route action. |
| Model | `Back to analysis` | Project name in topbar + `Data flow diagram` `h1` | `Open report` | Duplicate of sidebar Report. Model revision status is status text, not navigation. |
| Findings | `Back to analysis` | Project name in topbar + `Findings` `h1` | `Open DFD model` | Duplicate of sidebar DFD Model. |
| Action Plan | `Back to analysis` | Project name in topbar + `Action plan` `h1` | `Open findings` | Duplicate of sidebar Findings. |
| Evidence | `Back to analysis` | Project name in topbar + `Evidence` `h1` | `Update context` | Valid contextual action but duplicated by inline Update context action. |
| Report | `Back to analysis` | Report title in topbar + report `h1` | `Save draft`, `Sign report`, `MD`, `CSV`, `JSON` | Formal report actions; not navigation duplicates. |

**H0-A01 findings recorded:**

- `NAV-C01 · P0`: sidebar shell varies by route; global items and section placement are inconsistent.
- `NAV-C02 · P0`: lifecycle workflow exists only on Analysis; five workspace routes have no shared stage navigation.
- `NAV-C03 · P1`: Report, Report & sign-off, dan Sign-off refer to one destination with three labels.
- `NAV-C04 · P1`: four topbar links duplicate sidebar destinations (`View/Open report`, `Open DFD model`, `Open findings`).
- `NAV-C05 · P1`: no semantic breadcrumb exists; back links are route-specific topbar controls.
- `NAV-C06 · P2`: no footer navigation exists; branding footer is correctly classified as non-navigation.

**H0-A01 decision:** inventory is complete for the historical static route baseline and every active control is classified. The mismatch list remains preserved as audit history; canonical target markup/runtime is verified by the H1 target contract and must be treated as the current implementation source of truth.

#### 22.15.2 H0-A02–H0-A08 result — contract freeze evidence

Sisa action UX-M0 sudah dieksekusi dan dibekukan dalam `fixtures/h0_contract_freeze.json`. Fixture ini menjadi single source of truth sebelum H1 mengubah markup/CSS. Keputusan yang dikunci:

| Action | Keputusan yang dibekukan | Bukti eksekusi | Dampak implementasi berikutnya |
|---|---|---|---|
| H0-A02 · IA | Global shell mempunyai `Dashboard`, `Projects`, `New project`, `Settings`; project workflow mempunyai enam tahap `Overview → DFD model → Findings → Action plan → Evidence → Report & sign-off`. `Projects` untuk sementara dipetakan ke subview project list pada Dashboard. | `global_shell`, `project_workflow`, dan `navigation_rules` pada contract fixture; H0 gate memvalidasi key/label/route/icon/order unik. | H1 harus menghapus variasi sidebar, menambah `Projects` contract tanpa menggandakan menu project, dan menampilkan workflow di enam route. |
| H0-A03 · URL/state | `id` wajib pada project workspace. `run`, `phase`, `view`, `selected`, `revision`, query, sort, dan filter bersifat optional tetapi dipertahankan saat navigasi. Phase canonical menambahkan `overview`; selection wajib canonical ID; legacy hash dipetakan ke phase/view baru. | `url_state` pada contract fixture; validasi enum, pattern, legacy mapping, transition, preservation, dan invalid-state policy pada H0 gate. | H1/H1-A06 perlu menyelaraskan `UIState` dengan contract, termasuk `revision` dan `phase=overview`, tanpa mematahkan legacy hash. |
| H0-A04 · Page anatomy | Semua route mempunyai page goal, satu `h1`, status placement, satu primary CTA, dan secondary action yang dibatasi. Report mempunyai title `Report & sign-off` dan revision status. | `page_contracts` pada fixture; static route test mengunci tepat satu `h1` pada baseline. | H1/H3 wajib menempatkan current stage, goal, status, dan primary CTA dengan urutan yang konsisten. |
| H0-A05 · Content | Default locale `en-US`; noun, verb, deferred/not-scored/preserved/manual-decision/signed copy dikunci. `Deferred` bukan safe/no risk; tidak boleh ada campuran `Belum tahu` pada default UI. | `content_dictionary` pada fixture; H0 gate memvalidasi canonical keys, values, dan state semantics. | H1/H5 wajib memigrasikan label lama seperti `Report`, `Sign-off`, `View/Open`, dan mixed-language copy melalui dictionary. |
| H0-A06 · Responsive | `320/390` compact, `768` tablet, `1280/1440` desktop. Compact memakai drawer, filter sheet, bottom-sheet inspector, dan current-stage picker; desktop memakai persistent sidebar, inline workflow, dan inspector region. | `responsive_contract` pada fixture; seluruh lima test width tercakup. | H2/H4 wajib mengimplementasikan target sheet/overlay; geometry gate tidak boleh menganggap current Model rail sebagai final behavior. |
| H0-A07 · Baseline | Initial state diuji pada 6 route × 4 viewport; state sidebar/filter/inspector/warning/Model rail/context editor juga dicapture. Baseline redacted disimpan sebagai manifest, screenshot berisi UI tetap di `/tmp`. | `fixtures/h0_a07_baseline_manifest.json`; `tools/h0_a07_baseline.js`; 24 initial, 15 interactive, 39 screenshot, 0 page/API error. | H1–H6 memakai run ID/fixture/viewport yang sama saat membandingkan perubahan. Baseline bukan klaim UX lulus; ia adalah titik pembanding. |
| H0-A08 · Drift gate | Gate mode default mendeteksi drift yang diharapkan pada baseline; mode `--assert-target` akan gagal sampai canonical shell/workflow terimplementasi. | `node tools/h0_contract_freeze_gate.js` pass dengan NAV-C01–NAV-C06; `--assert-target` sengaja red sebelum H1. | CI/PR berikutnya menjalankan default untuk inventory dan `--assert-target` setelah H1 sebagai release contract. |

Perintah validasi yang sudah dijalankan:

```bash
node tests/test_h0_a01_navigation_inventory.js
node tools/h0_contract_freeze_gate.js
node tools/h0_a07_baseline.js --output <tmp>/h0-a07.json --screenshot-dir <tmp>/screens
```

Output gate H0-A08 historis mendeteksi enam expected drift: `NAV-C01` sampai `NAV-C06`. Setelah shared shell/workflow runtime diterapkan, target implementation diverifikasi melalui:

```bash
node tools/h0_contract_freeze_gate.js --assert-target
```

Gate sekarang pass (`canonical_ready=true`) setelah `tests/test_h1_shared_shell.js` dan runtime Chromium contract memverifikasi sidebar/workflow/label drift sudah ditutup. Historical inventory tetap dipertahankan sebagai baseline, sehingga H0 tidak mencampur “definition siap” dengan “UI sudah diimplementasikan”.

**H0-A02–H0-A08 decision:** contract dan baseline freeze selesai; tidak ada keputusan navigasi, URL state, page anatomy, terminology, breakpoint, atau success metric yang masih implicit. Implementation readiness sekarang **canonical pada runtime shell**; fallback markup tetap dipertahankan agar route tidak blank ketika JavaScript gagal.

**Exit criteria UX-M0:** H0-A01–H0-A08 `DONE`; tidak ada keputusan IA/terminologi/responsive yang masih implisit. Setelah milestone ini selesai, perubahan contract wajib melalui change record, bukan perubahan lokal pada satu HTML.

#### Milestone UX-M1 — Shared shell dan lifecycle navigation

**Goal:** pengguna selalu mengetahui sedang berada di project mana, tahap workflow mana, dan cara berpindah tahap tanpa mencari navigation control di area berbeda.

**Dependency:** UX-M0 selesai.

| ID | Status | Action spesifik | Area implementasi | Validasi/acceptance |
|---|---|---|---|---|
| H1-A01 | **DONE — runtime 2026-09-24** | Refactor sidebar menjadi satu renderer/source of truth; static markup tetap menjadi fallback ketika JavaScript gagal. | `frontend/js/sidebar.js`, shared shell CSS, enam HTML workspace. | Runtime DOM/menu signature sama pada 6/6 route; hanya active workflow stage yang berbeda. |
| H1-A02 | **DONE — 2026-09-24** | Implement shared project workflow navigation di bawah project header/topbar dan di atas page content. | `installProjectWorkflowNavigation()` + shared CSS. | Current stage terlihat pada 390, 768, 1280, dan 1440px; semua route memakai urutan yang sama. |
| H1-A03 | **DONE — 2026-09-24** | Buat mobile current-stage control yang membuka daftar enam tahap tanpa menambah horizontal overflow. | `#project-workflow-stage`, responsive shell CSS. | Native select dapat dioperasikan touch/keyboard; stage count dan current label tersedia. Screen-reader announcement final masih masuk H6-A04. |
| H1-A04 | **DONE — 2026-09-24** | Hapus workflow footer pada Analysis dan duplicate route entry point pada halaman lain. | Shared workflow runtime; legacy Analysis workflow dihapus dari markup, CSS, dan route logic. | Tidak ada lifecycle footer bersaing; global sidebar hanya Dashboard/New project/Settings. |
| H1-A05 | **PARTIAL — core 2026-09-24** | Standardisasi project identity, run state, page heading, breadcrumb/back label, dan topbar action. | Existing topbar contracts + workflow shell. | Project identity/state dan stage sudah konsisten; breadcrumb/back-label/topbar contextual action lintas route masih perlu normalisasi penuh. |
| H1-A06 | **DONE — 2026-09-24** | Hubungkan setiap link dengan shared UI state contract. | `uiuxplan.md`, `frontend/js/ui-state.js`, route builders, workflow click handler. | Workflow click/picker mempertahankan project ID; route scripts tetap mengisi run/filter/selection sesuai contract. |
| H1-A07 | **PENDING** | Tambahkan fallback yang jelas ketika project/run/revision invalid atau tidak tersedia. | Shared empty/error state. | Masih perlu satu invalid-route recovery contract lintas semua workspace. |
| H1-A08 | **PARTIAL — automated core 2026-09-24** | Jalankan regression sidebar, workflow, Back/Forward, refresh, deep link, mobile drawer, dan keyboard focus. | `tools/u6_release_signoff_gate.js`, U4/Package G regression. | Sidebar/workflow/mobile focus dan stateful Chromium journeys pass; Back/Forward/deep-link matrix formal perlu dipisahkan sebagai H1-specific gate. |
| H1-A09 | **DONE — 2026-09-24** | Normalisasi jarak antara shared workflow navigator dan content heading pada enam route; jadikan renderer workflow idempotent dengan load fallback; reset scroll pada bootstrap workspace agar first viewport tidak tertutup; hilangkan label panel Model yang tidak actionable. | `frontend/js/sidebar.js`, `frontend/js/analysis.js`, `frontend/css/style.css`, `frontend/css/pages.css`, `frontend/model.html`, `tools/u7_package_g_gate.js`. | Setiap route memiliki tepat satu navigator visible, aligned setelah topbar, dan satu active stage pada 390/768/1280/1440px; Model memakai spacing 18px desktop/12px mobile; label panel menjelaskan fungsi (`Review elements`, `Text alternative`). |

#### Implementasi terbaru UX-M1 — 2026-09-24

- `frontend/js/sidebar.js` sekarang menjadi canonical runtime renderer. Semua project route menampilkan global sidebar yang identik: `Dashboard`, `New project`, `Settings & BYOK`; lifecycle tidak lagi bercampur dengan global menu.
- Shared workflow navigator menampilkan `Overview → DFD model → Findings → Action plan → Evidence → Report & sign-off` di bawah topbar pada seluruh project route. Desktop memakai six-step links; mobile memakai `1 of 6 · Current stage` picker.
- Vertical rhythm shell dinormalkan: Findings, Action Plan, Evidence, Model, Analysis, dan Report memiliki separation yang konsisten dari topbar/workflow navigator. `installProjectWorkflowNavigation()` memiliki guard idempotensi dan load fallback sehingga route legacy tidak kehilangan navigator.
- Legacy `analysis-workflow` footer sudah dihapus dari markup, CSS, dan route logic; tidak ada lagi dua mental model navigation. Route IDs (`nav-analysis`, `nav-model`, dan seterusnya) dipertahankan pada shared navigator sehingga UIState/route scripts tetap kompatibel.
- H1 contract ditambahkan ke M6/Package G Chromium gate: signature sections/labels/order/icon, tepat satu navigator visible, satu active stage, desktop link navigation, mobile picker, focus lifecycle sidebar, dan project identity preservation.

**Exit criteria UX-M1:** satu shell digunakan secara nyata oleh semua route; pengguna dapat berpindah ke tahap sebelum/sesudahnya dari area yang konsisten; current project, run, dan stage dapat dijelaskan dalam ≤10 detik.

#### Milestone UX-M2 — DFD Model canvas-first recovery

**Goal:** DFD menjadi task utama, bukan tertutup queue/tooling; node, flow, boundary, evidence, dan linked finding dapat ditelusuri pada desktop maupun mobile tanpa overlap.

**Dependency:** UX-M0 selesai; integration akhir mengikuti shell UX-M1.

| ID | Status | Action spesifik | Area implementasi | Validasi/acceptance |
|---|---|---|---|---|
| H2-A01 | DONE — 2026-09-24 | Ubah mobile boundary review rail menjadi closed-by-default bottom sheet dengan pending-count trigger. | `model.html`, Model JS/CSS. | Closed sheet tidak beririsan dengan canvas; open state tidak kehilangan selection. |
| H2-A02 | DONE — 2026-09-24 | Implement dialog semantics, accessible name, Escape/close, focus trap, focus return, backdrop, dan body scroll lock. | Shared focus manager + Model sheet. | Keyboard-only dan screen-reader interaction pass. |
| H2-A03 | DONE — 2026-09-24 | Pastikan canvas memperoleh ≥55% tinggi viewport desktop dan area terlihat ≥240px mobile sebelum sheet dibuka. | Model layout CSS. | Geometry assertion pass pada seluruh breakpoint dan short-height viewport. |
| H2-A04 | DONE — 2026-09-24 | Perbaiki `Fit`: hitung boundary, label, node, dan edge extents; beri safe padding terhadap toolbar/inspector. | Diagram fit/layout logic. | Setelah Fit tidak ada node/label overlap yang membuat target tak terbaca; selected element tetap terlihat. |
| H2-A05 | DONE — 2026-09-24 | Pertahankan selected node/flow/boundary ketika resize, Fit, fullscreen, sheet open/close, dan navigation return. | Model state adapter. | Selection ID dan viewport focus preserved pada seluruh transition. |
| H2-A06 | DONE — 2026-09-24 | Kelompokkan export/layout/advanced commands di `More`; sisakan `Reflow layout` dan Review sebagai command utama dengan pan/zoom native canvas. | Model toolbar. | Toolbar tidak wrap/clip pada 320/390px dan semua target memenuhi token ukuran. |
| H2-A07 | DONE — 2026-09-24 | Hubungkan inspector dua arah: DFD element → evidence/finding dan finding/evidence → exact DFD element. | Route/deep-link handlers. | Tidak ada fallback ke node pertama; exact canonical ID selalu digunakan atau deferred state ditampilkan. |
| H2-A08 | DONE — 2026-09-24 | Tambahkan geometry, screenshot, keyboard, touch, and route-return tests untuk initial/Fit/sheet/fullscreen/selection. | `tools/u2_model_canvas_gate.js`, `tools/u7_package_g_gate.js`. | Intersection 0px² saat closed; no horizontal overflow; no console/API error. |
| H2-A09 | **DONE — 2026-09-24** | Pulihkan hierarchy canvas-first pada state nyata: hilangkan CTA/topbar duplicate, ringkas status, normalkan label level, tutup boundary rail pada initial desktop/mobile, dan kelompokkan command `More`. | `frontend/model.html`, `frontend/css/pages.css`, `frontend/js/analysis.js`. | First viewport memiliki satu primary review action; kanvas dimulai 302.97px pada mobile 390×844 dan 333.03px pada desktop 1440×900; rail hanya terbuka setelah Review/selection; selection, keyboard, Fit, dan deep-link tetap lulus. |
| H2-A10 | **DONE — 2026-09-24** | Tambahkan heading workspace yang konsisten, expose DFD detail levels dengan label teknis `L0/L1/L2`, dan satukan `Model inventory` serta `Accessible model outline` sebagai disclosure panel yang compact, keyboard-accessible, dan progressive. Badge aksi panel dipisahkan menjadi kolom kanan yang stabil agar tidak “mengambang” di tengah saat caret disclosure dirender. | `frontend/model.html`, `frontend/css/pages.css`, `frontend/js/analysis.js`, `tools/u2_model_canvas_gate.js`. | Pengguna awam melihat `Overview/Services/Feature flow`; pengguna teknis melihat `L0/L1/L2`; kedua panel memiliki header/subtitle/state/caret yang sama, badge state berada di kanan title tanpa overlap/centering yang membingungkan, tidak terbuka otomatis, dapat dibuka dengan keyboard, dan tidak menutupi kanvas. |
| H2-A11 | **DONE — 2026-09-24** | Hardening state Boundary review saat rail desktop terbuka: batasi tinggi rail terhadap viewport, tampilkan Boundary review sebagai section langsung tanpa collapse menu, pisahkan scroll boundary queue dari selection inspector, cegah isi card/flow/evidence meluber, dan letakkan CTA `Start guided boundary review` pada action row rata kanan. Pertahankan bottom sheet mobile tanpa mewarisi constraint desktop. | `frontend/model.html`, `frontend/css/pages.css`, `frontend/js/analysis.js`, `tools/u2_model_canvas_gate.js`. | Saat Review dibuka, header Boundary review, pending count, CTA, dan queue langsung usable; tombol `×` menjadi satu-satunya control untuk menghapus section; pada 1440×900 rail review selesai di dalam viewport; boundary queue dan selection inspector tidak overlap; CTA sejajar ke kanan; detail evidence/flow tetap dapat discroll tanpa horizontal overflow; mobile sheet, Escape, focus return, selection, Reflow, dan deep-link tetap lulus. |
| H2-A12 | **DONE — 2026-09-24** | Ganti aksi toolbar `Fit` menjadi `Reflow layout` sebagai aksi langsung di luar `More`; jadikan count pada Review sebagai toggle show/hide Boundary review; tambahkan tombol `×` langsung pada header Boundary review untuk menghapus section tanpa menutup selection inspector. | `frontend/model.html`, `frontend/js/analysis.js`, `frontend/css/pages.css`, `tools/u2_model_canvas_gate.js`. | Tidak ada `Fit` pada toolbar Model; `Reflow layout` hanya satu dan terlihat langsung; klik count dua kali mengubah Boundary review show → hide → show; tombol close menyembunyikan Boundary review; tidak ada collapse/caret tambahan; selected DFD element, mobile sheet, keyboard, dan exact trace tetap lulus. |

**Exit criteria UX-M2:** kanvas langsung terlihat dan usable; boundary queue tidak menutupi diagram; Fit deterministik; trace dua arah memakai canonical object ID.

**H2-A01–H2-A08 result — UX-M2 core recovery selesai (2026-09-24):**

- `frontend/model.html` sekarang memakai toolbar utama `Reflow layout` + `Review (N)`; fullscreen, export, import, undo/redo, unconnected-node, dan visual mode berada di `More`. Count Review dapat toggle show/hide Boundary review, sementara tombol `×` hanya menghapus section review tanpa menghilangkan selection inspector.
- Mobile boundary rail tertutup sejak initial render, dibuka sebagai dialog bottom sheet dengan accessible role/name, backdrop, focus trap melalui `UXFocus`, Escape/close focus-return, background inert, dan `model-sheet-scroll-lock`. `node-inspector` tetap menjadi selection detail tanpa membuat queue selalu mengambil ruang layout.
- Mobile chrome non-esensial diringkas agar canvas dimulai sekitar y=303px pada fixture 390×844. Sheet dibatasi `48vh`; seleksi node/flow dipindahkan ke safe area di atas sheet ketika inspector terbuka. Desktop canvas pada 1440×900 memiliki tinggi 680px dan top 333px setelah spacing shell dinormalkan, sehingga visible area tetap memenuhi kontrak ≥495px.
- `fitModelDiagram()` dan initial canonical render memakai overlap gap 40px serta padding 56px; selected node/flow/boundary dipulihkan dari URL/UI state dan viewport digeser ke safe area setelah Fit, resize, sheet open/close, dan fullscreen.
- Inspector DFD menampilkan link evidence yang membawa locator ke Evidence Workspace serta linked finding dengan `threat:<id>`. Findings mengembalikan pengguna ke `dfd-flow:<canonical-id>`; tidak ada fallback ke node pertama.
- Regression test permanen tersedia melalui `node tools/u2_model_canvas_gate.js`. Run Chromium terakhir: 5/5 checks, 2 screenshots, 0 error, 0 page error, 0 failed API request. Check tambahan mencakup heading workspace, label `L0/L1/L2`, dan keyboard disclosure untuk inventory/outline. Fixture yang dipakai adalah synthetic `checkout-traceability-standard`; screenshot disimpan di `/tmp/5stones-u2-model-l0l1l2-final/`.
- `node tools/u7_package_g_gate.js` juga lulus setelah update journey mobile: 24 route/viewport matrix, 9 checks, 0 error, 0 page error, dan 0 failed API request.

**Residual integration note:** core Model acceptance sudah tertutup pada shell saat ini. H1 shared-shell implementation tetap menjadi pekerjaan terpisah; saat UX-M1 selesai, jalankan ulang `tools/u2_model_canvas_gate.js` dan validasi ulang route links tanpa mengubah canonical selection contract.

#### Milestone UX-M3 — Readability dan hierarchy normalization

**Goal:** setiap first viewport menjawab tiga hal—`di mana saya`, `statusnya apa`, dan `apa tindakan berikutnya`—tanpa memaksa pengguna membaca blok teks panjang atau teks mikro.

**Dependency:** UX-M0; token diterapkan ke output UX-M1/UX-M2.

| ID | Status | Action spesifik | Output/area | Validasi/acceptance |
|---|---|---|---|---|
| H3-A01 | DONE — 2026-09-24 | Audit seluruh font-size, line-height, spacing, color, button height, icon-only action, dan sticky offset; exceptions ditutup dengan page-scoped overrides. | `frontend/css/style.css`, `frontend/css/components.css`, `frontend/css/pages.css`. | Tokenized controls, wrapping tablet report, clipped internal horizontal rails, dan exception styles tervalidasi. |
| H3-A02 | DONE — 2026-09-24 | Definisikan dan implement body 14–16px, essential metadata ≥12px, heading scale, line length, spacing, elevation, and focus tokens. | Shared CSS variables/utilities. | Body 16px; essential text gate ≥12px; 3px focus ring, reduced motion, forced-colors styles. |
| H3-A03 | DONE — 2026-09-24 | Naikkan interactive target ke ≥40px product minimum dan 44px untuk mobile primary controls. | Shared controls + page overrides. | Gate menolak target visible <40px; sidebar, Back, DFD controls/outline, filters, disclosure, report TOC, dan search diperbaiki. |
| H3-A04 | DONE — 2026-09-24 | Ringkas blocker/warning menjadi summary satu baris, severity/state, primary recovery action, dan expandable detail. | `report.html` blocker banner + shared alert styles. | Report menampilkan “Human review is required…” sebagai summary; rationale berada di `details`; next action tetap berada di readiness/orientation. |
| H3-A05 | DONE — 2026-09-24 | Hilangkan UUID, provenance panjang, helper repetitif, dan metadata sekunder dari default row/card; pindahkan ke inspector. | Findings/Actions/Evidence/Report projections + page CSS. | Finding/action/evidence IDs tidak dirender pada row default; detail dan provenance tetap tersedia pada inspector/report appendix. |
| H3-A06 | DONE — 2026-09-24 | Terapkan one-primary-CTA rule dan hierarchy primary/secondary/tertiary/destructive yang konsisten. | Six route first-view actions. | Analysis Run, Model Review, Findings guided review, Action Plan Review decisions, Evidence Update context, dan Report Sign report menjadi primary tunggal. |
| H3-A07 | DONE — 2026-09-24 | Uji text zoom 200%, browser zoom 400% equivalent narrow reflow, reduced motion, high contrast, dan short-height viewport. | `tools/u3_readability_gate.js` + Chromium. | 30 route×breakpoint checks, 200% text reflow, 1280×480 short-height, reduced-motion, forced-colors lulus tanpa overflow/clipping/lost action. Browser-level zoom equivalent menggunakan Chromium narrow/reflow coverage; actual browser chrome zoom tetap menjadi manual release check. |

**Exit criteria UX-M3:** essential text <12px = 0; touch target kritis memenuhi ukuran; page goal/status/next action dapat dipindai tanpa membaca detail sekunder.

**H3-A01–H3-A07 result — UX-M3 core selesai (2026-09-24):**

- Shared readability tokens sekarang memakai root 16px, body line-height 1.5, essential metadata/caption 12px minimum, content measure 70ch, control minimum 40px, mobile primary 44px, visible focus ring, reduced-motion override, dan forced-colors fallback. Body memakai horizontal clipping untuk mencegah scroll dua arah saat text zoom; internal rails/canvas tetap mengelola overflow lokalnya.
- Semua six first viewport memakai pola yang sama: page title/topbar sebagai lokasi, status live/status summary, dan next action. Findings, Action Plan, Evidence, dan Report memakai `ux-orientation-strip`; Analysis mempertahankan lifecycle overview/next-action queue; Model memakai readiness summary plus Fit/Review toolbar.
- Default list rows hanya memuat label keputusan, severity/state, DFD reference/deferred state, owner/executability, dan next action. UUID/provenance/helper panjang dipindahkan ke inspector, report formal metadata, source manifest, atau appendix.
- Blocker report dipadatkan menjadi summary + expandable rationale. Action Plan memiliki satu CTA `Review decisions`; Evidence mempertahankan satu CTA `Update context` pada desktop/mobile; DFD `Review` menjadi primary command sedangkan advanced commands tetap di `More`.
- Permanent gate tersedia melalui `npm run u3:readability` / `node tools/u3_readability_gate.js`. Fixture Chromium: `fixture-u7-checkout`. Hasil terakhir: **30 matrix checks, 5 additional checks, 0 errors, 0 page errors, 0 failed API requests**. Matrix mencakup 320, 390, 768, 1280, dan 1440px; checks tambahan mencakup 200% text zoom, short-height 1280×480, reduced motion, forced colors, 40px target, dan essential text ≥12px.
- Regression setelah tokenization: `node tools/u7_package_g_gate.js` **24 route/viewport checks + 9 journeys lulus**; `node tools/u2_model_canvas_gate.js` **4/4 checks lulus**. Tidak ada regresi pada DFD Fit/selection/sheet, keyboard list-detail, report appendix, atau exact DFD → finding → control → test trace.
- Residual manual check: browser chrome zoom 400% perlu dijalankan pada release candidate karena Chromium headless gate tidak mengendalikan menu zoom browser secara portable; narrow 320px + 200% text reflow sudah menjadi automated proxy dan tidak boleh menggantikan manual accessibility sign-off.

#### Milestone UX-M4 — Unified filter, operational list, dan inspector

**Goal:** Findings, Action Plan, dan Evidence mempunyai pola pencarian/penyaringan/list-detail yang sama, dapat dipelajari sekali, dan tetap efisien untuk expert.

**Dependency:** UX-M1 dan UX-M3 selesai.

| ID | Status | Action spesifik | Area implementasi | Validasi/acceptance |
|---|---|---|---|---|
| H4-A01 | DONE — 2026-09-24 | Definisikan shared filter schema: search, quick presets, advanced groups, sort, active count, chip serialization, reset, dan zero-results recovery. | `frontend/js/workspace-filters.js`, `frontend/js/ui-state.js`, tiga workspace. | Findings, Action Plan, dan Evidence memakai terminology, state lifecycle, count/chip, reset, dan recovery yang sama. |
| H4-A02 | DONE — 2026-09-24 | Ganti native multi-select dengan checkbox group/searchable selection yang mempunyai label, count, Select all/Clear, dan keyboard support. | Filter dialog pada tiga workspace. | Checkbox group terlabel, searchable, `Select all visible`, `Clear all`, live selection count, dan value tidak terpotong pada 390px. |
| H4-A03 | DONE — 2026-09-24 | Gunakan satu `Filters` trigger; hapus kombinasi `More filters` plus visible `Advanced filters`. | Filter toolbar. | Tiap workspace hanya memiliki satu trigger `Filters`; active count/chips tetap terlihat saat drawer tertutup. |
| H4-A04 | DONE — 2026-09-24 | Implement desktop anchored panel/drawer dan mobile full-width sheet menggunakan semantics/focus behavior yang sama. | Native `<dialog>` + shared controller. | Open/close/Escape/apply/cancel/focus return lulus pada Chromium tanpa overlay menghalangi control. |
| H4-A05 | DONE — 2026-09-24 | Hapus fixed-height nested mobile list. Gunakan document scroll + pagination/load-more, atau virtualization yang disetujui accessibility review. | Responsive list CSS pada tiga workspace. | 390/768px tidak memiliki nested-scroll trap; list memakai document flow dan inspector tetap memakai mobile sheet. |
| H4-A06 | DONE — 2026-09-24 | Standardisasi compact row anatomy: title, framework/type, state, risk/severity context, primary DFD ref/deferred reason, owner/status, dan selection affordance. | Findings/Actions/Evidence renderers. | Row default tetap scan-first; detail sekunder/provenance tidak memenuhi list dan canonical DFD/deferred state tetap visible. |
| H4-A07 | DONE — 2026-09-24 | Standardisasi inspector: summary → relation/trace → guidance/steps → evidence/provenance → actions. | Shared focus contract + tiga inspector. | Desktop region dan mobile modal mempertahankan urutan, heading, role, focus trap, dan focus return yang sama. |
| H4-A08 | DONE — 2026-09-24 | Implement URL serialization, deep link, Back/Forward, scroll restoration, exact selection, dan zero-result fallback tanpa memilih row pertama. | `ui-state.js` (`q`, `aq`, `eq`, filter params, `selected`) + workspace adapters. | Reload/deep-link dan Back/Forward mengembalikan filter/query; selection memakai canonical ID; zero result memberi recovery/reset yang eksplisit. |
| H4-A09 | DONE — 2026-09-24 | Uji keyboard list navigation, filter state, mobile sheet, inspector, pagination, large fixture, dan no-result state. | `tools/u4_unified_workspace_gate.js`, U7 Package G regression. | Chromium gate membuktikan seluruh tiga workspace pada 390/768/1280/1440px, filter lifecycle, keyboard inspector, deep-link, Back/Forward, dan no overflow. |

#### Implementasi dan bukti UX-M4 — 2026-09-24

- `workspace-filters.js` menjadi controller bersama untuk tiga halaman: native dialog desktop anchored, full-width bottom sheet mobile, searchable checkbox option, `Select all visible`, `Clear all`, selection status, Apply/Cancel, Escape, serta focus return ke trigger.
- `findings.js`, `action-plan.js`, dan `evidence.js` memakai adapter yang sama untuk membaca/menulis checkbox values, filter count/chips, reset, dan Apply. Query action kini mempunyai state URL sendiri (`aq`) sehingga tidak lagi tercampur dengan query Findings (`q`); Evidence tetap (`eq`).
- Filter Apply memakai history entry sehingga Back/Forward mengembalikan state sebelumnya. Deep-link tetap mereproduksi query/filter/selection tanpa memilih row pertama secara implisit. List mobile tidak lagi menjadi nested fixed-height scroll container.
- Gate permanen tersedia melalui `npm run u4:filters` / `node tools/u4_unified_workspace_gate.js`. Hasil final: **12 route×viewport checks, 18 workspace checks, 0 errors, 0 page errors, 0 failed API requests**.
- Regression final `node tools/u7_package_g_gate.js`: **24 route/viewport checks + 9 journey checks lulus**, termasuk DFD canvas/selection, keyboard inspector tiga workspace, report/onboarding, dan exact DFD → finding → control → test trace.

**Exit criteria UX-M4:** user yang memahami filter di satu workspace dapat memakai dua workspace lain tanpa mempelajari pola baru; mobile tidak memiliki clipped control atau nested scroll trap.

#### Milestone UX-M5 — Page-specific simplification dan journey continuity

**Goal:** setiap halaman hanya menampilkan informasi yang dibutuhkan untuk keputusan pada tahap tersebut; detail tetap tersedia melalui progressive disclosure dan hubungan antarobjek tetap utuh.

**Dependency:** UX-M1–UX-M4 selesai.

| ID | Status | Action spesifik | Goal halaman | Validasi/acceptance |
|---|---|---|---|---|
| H5-A01 | **DONE — 2026-09-24** | Analysis: tampilkan run status, current phase/progress, consolidated blocker, next-action queue, dan compact scored/deferred summary; jangan render full result list. | Overview dapat dipahami dalam ≤10 detik. | Tiga metric summary; max tiga next actions; intake/context progressive disclosure; phase/retry/preserved-result tetap tersedia. |
| H5-A02 | **DONE — core 2026-09-24** | Model: finalisasi canvas-first layout, compact queue trigger, concise inspector, and contextual trace actions. | User memvalidasi DFD sebelum menilai threat. | Canvas/Fit/mobile review contract tetap pass; Model menyediakan direct continuation ke Findings. |
| H5-A03 | **DONE — core 2026-09-24** | Findings: gabungkan STRIDE/LINDDUN dalam list, pisahkan scenario severity dari scored/deferred risk, dan wajibkan primary DFD interaction/deferred reason. | Triage threat grounded pada DFD. | Shared list/inspector contract dan exact DFD references tetap pass. |
| H5-A04 | **DONE — core 2026-09-24** | Action Plan: pisahkan Controls dan Verification Tests sebagai views; tampilkan unassigned applicability queue; collapse detail default. | Control → threat → DFD → test dapat diikuti tanpa search ulang. | Queue hanya menampilkan keputusan yang benar-benar terbuka; row tetap keyboard-accessible; detail tidak expanded massal. |
| H5-A05 | **DONE — 2026-09-24** | Evidence: prioritaskan unresolved queue; kelompokkan context/artifact/gap/assumption/coverage; dedupe `Question` dan `Next action`. | User mengetahui evidence apa yang kurang dan siapa yang harus bertindak. | Queue/filter berada sebelum intake/coverage; satu CTA context per breakpoint; unread/deferred source tetap dapat dibuka. |
| H5-A06 | **DONE — core 2026-09-24** | Report: pertahankan read-only; ringkas web view; kelompokkan export; tampilkan provenance/revision/approval; bedakan `0 scored + N deferred` dari no risk. | Report dapat direview tanpa mengubah canonical data. | Export menjadi progressive disclosure; sign-off tetap primary pada mobile; U6 revision/read-only contract tetap pass. |
| H5-A07 | **DONE — core 2026-09-24** | Standardisasi empty/loading/error/partial/retrying/preserved-result states pada enam route. | System status tidak ambigu. | Existing lifecycle/recovery state contract dipertahankan; M5 tidak mengubah semantic state menjadi zero/blank. |
| H5-A08 | **DONE — core 2026-09-24** | Tambahkan contextual `Continue`, `Back to …`, dan return-to-selection behavior sesuai lifecycle, bukan duplicate global navigation. | Journey terasa kontinu antarobject dan antarstage. | Model → Findings direct action ditambahkan; existing exact-ID DFD → finding → control → test trace tetap lulus. |
| H5-A09 | **DONE — core 2026-09-24** | Review copy pada surface yang disentuh M5; gunakan action-first wording, jelaskan secondary detail lewat disclosure, dan pertahankan canonical terminology. | UI mudah dipahami tanpa mengurangi precision. | M5 copy memakai label keputusan yang ringkas; detailed rationale tetap tersedia melalui inspector/details. Moderated persona study tetap menjadi UX-M6 evidence. |

#### Implementasi dan bukti UX-M5 — 2026-09-24

- **Analysis:** overview sekarang hanya menampilkan tiga metric keputusan (`Scored risk`, `Needs review`, `Evidence gaps`) dan maksimal tiga next action. Artifact intake menjadi `<details>` tertutup; project context tetap collapsed sehingga status/run phase dan tindakan berikutnya menjadi orientasi utama.
- **Model:** canvas-first dan boundary review contract dari UX-M2 dipertahankan. Topbar Model mendapat continuation langsung `Review findings` dengan project/run state yang sama sehingga reviewer tidak perlu kembali ke sidebar.
- **Action Plan:** queue card dengan count nol tidak dirender. Queue menjadi daftar keputusan yang benar-benar terbuka, sedangkan seluruh inventory tetap tersedia melalui Task view/list dan inspector.
- **Evidence:** review queue dan filter diposisikan sebelum intake/source coverage pada desktop maupun mobile. Context mempunyai satu CTA terlihat per breakpoint; intake dan coverage tetap dapat dibuka, tetapi tidak mengambil alih keputusan pertama.
- **Report:** MD/CSV/JSON dikelompokkan di menu Export. Pada mobile, `Sign report` tetap action utama dan `Save draft` disembunyikan dari first viewport; report tetap read-only dan appendix/provenance tersedia melalui disclosure.
- **Continuity:** `frontend/js/ui-state.js` tetap membawa project, run, phase, filter, dan selection. `btn-model-findings` melanjutkan route Model → Findings tanpa kehilangan project identity.
- **Validation gate:** `npm run u5:simplification` lulus **7/7 checks, 0 page errors, 0 failed API requests** pada Chromium (Analysis/Model/Action Plan/Evidence/Report, 390 dan 1280px). Regression `npm run u4:filters` lulus **12 matrix checks + 18 workspace checks**; `npm run u7:package-g` lulus **24 route×viewport checks + 9 journey checks**; `npm run u7:baseline` lulus **24 axe page checks, 0 serious/critical violations**.

**Exit criteria UX-M5:** **DONE — core 2026-09-24.** Page-specific acceptance §22.6 dan action table di atas sudah diterapkan pada six-route surface; first viewport tidak memuat full dataset; exact IDs, deferred semantics, dan provenance tetap dapat diakses. Moderated novice/expert usability study dan release sign-off formal tetap dikerjakan pada UX-M6.

#### Milestone UX-M6 — Accessibility, responsive, performance, dan release sign-off

**Goal:** membuktikan UX baru bekerja pada state nyata—bukan hanya initial screenshot—serta dapat digunakan dengan keyboard, assistive technology, mobile, dan data besar.

**Dependency:** UX-M1–UX-M5 selesai dan release candidate dibekukan.

| ID | Status | Action spesifik | Bukti wajib | Validasi/acceptance |
|---|---|---|---|---|
| H6-A01 | **DONE — automated 2026-09-24** | Jalankan Playwright Chromium matrix §22.11 untuk enam route × breakpoint × critical state. | `/tmp/5stones-uxm6-signoff-final.json`, optional screenshots/trace. | **24/24** route×viewport pass pada 390/768/1280/1440px; tidak ada P0 visual/interaction failure. |
| H6-A02 | **DONE — automated 2026-09-24** | Jalankan geometry assertions untuk overflow, sticky/fixed intersection, canvas/sheet, focused item, dan touch target. | Machine-readable matrix pada M6 gate. | Horizontal overflow **0**, fixed occluder **0**, undersized control **0** pada matrix yang diuji. |
| H6-A03 | **DONE — automated; manual follow-up 2026-09-24** | Jalankan axe pada inspector, filter, Model sheet, Evidence context dialog, dan Report Export state; normalisasi semantic role yang ditemukan. | Axe states pada JSON gate + incomplete disposition. | Actual serious/critical violation **0**. `incomplete` **36 target** dicatat sebagai `manual_review_required`; bukan dianggap pass tanpa review visual/manual. Minor inspector role finding diperbaiki dengan container semantics. |
| H6-A04 | **PARTIAL — automated keyboard 2026-09-24** | Jalankan keyboard-only journey dan validasi dialog, focus return, live status, accessible DFD outline, serta touch/mobile sheet. | 3 workspace keyboard trace + axe state report. | Search → filter → list → inspector → Escape lulus pada Findings/Action Plan/Evidence; Model sheet dan outline lulus. Screen-reader session manual masih diperlukan sebelum formal sign-off. |
| H6-A05 | **PARTIAL — automated novice proxy 2026-09-24** | Jalankan novice journey §22.12 pada guided boundary/finding review dengan plain-language decision. | Chromium journey trace + deferred-state assertion. | Guided review memakai `Belum tahu`, progress, dan explicit deferred state; studi dengan partisipan representatif belum dijalankan. |
| H6-A06 | **PARTIAL — automated expert proxy 2026-09-24** | Jalankan expert trace §22.12 menggunakan exact canonical IDs. | Exact object trace log. | DFD → finding → control → executable test lulus dalam sekitar **1,4 detik** pada fixture; moderated expert study masih diperlukan untuk bukti manusia. |
| H6-A07 | **DONE — automated 2026-09-24** | Uji large fixture dengan long labels dan banyak finding/control/test/evidence. | Performance section pada JSON gate. | 240 findings, 80 controls, 80 tests, 180 evidence items tetap searchable/selectable di mobile; search→selection sekitar **0,75 detik**, tanpa overflow. |
| H6-A08 | **DONE — automated 2026-09-24** | Verifikasi console/API stability, loading/retry/partial/preserved-result, deferred-only report, dan no stale selection. | Network/console logs + recovery journey. | **0** page errors, failed API requests, HTTP errors, dan console warning/error; retry affected phase mengirim action deterministik; previous results tetap terlihat; `0 scored + N deferred` memblokir sign-off. |
| H6-A09 | **PENDING — formal release 2026-09-24** | Buat residual-risk register dan lakukan Product/UX/QA sign-off. | Signed release record dengan fixture/revision/browser/date. | Automated candidate gate lulus; formal sign-off masih menunggu manual contrast review, screen-reader check, moderated novice/expert evidence, dan keputusan atas UX-M1 shared-shell residual. |

#### Implementasi dan bukti UX-M6 — 2026-09-24

- Ditambahkan gate permanen `npm run u6:signoff` (`tools/u6_release_signoff_gate.js`) yang meniru interaksi pengguna melalui Playwright **Chromium 1.57.0**, bukan hanya mengambil initial screenshot. Gate memakai fixture terisolasi, mock API yang sama untuk semua route, dan data tidak menulis ke dataset development. Filter workspace menunggu row hasil render sebelum keyboard assertion agar hasil gate deterministik pada response yang lambat.
- Skenario yang benar-benar dijalankan: matrix six-route × 390/768/1280/1440; keyboard search → filter → list → inspector → Escape pada tiga workspace; mobile Model review sheet; accessible DFD outline; exact DFD → finding → control → test; novice guided review; axe pada state terbuka; preserved-result + retry; large fixture; dan deferred-only report.
- Hasil final: **24/24 matrix**, **13/13 journey checks**, exact trace sekitar **1,4 detik**, large fixture selection sekitar **0,75 detik**, **0** page error, **0** failed request, **0** HTTP error, **0** console warning/error. Regression `npm run u7:baseline` lulus **24/24 axe page states** tanpa serious/critical violation; `npm run u7:package-g` lulus **24 route/viewport + 9 journeys**. Assertion overview terbaru memastikan tiga kartu summary tetap seimbang pada mobile dan desktop.
- Report fallback diperkeras agar `0 scored + N deferred` selalu menampilkan disposition `deferred` dan kalimat bahwa kondisi tersebut **bukan bukti tidak ada risiko**. Export/provenance/revision group diberi semantic role; inspector container tidak lagi memicu `aria-allowed-role` saat berubah menjadi dialog mobile.
- Accessibility result dibagi menjadi dua: `violations` aktual dan `incomplete_disposition`. Pada run ini violation serious/critical aktual adalah **0**; axe masih menandai **36 target contrast dinamis** sebagai `manual_review_required`. Target dan rationale tersimpan di JSON agar reviewer dapat memeriksa selector yang sama pada browser visual.

**Residual-risk register UX-M6:**

1. **P1 — Manual accessibility evidence:** jalankan VoiceOver/NVDA pada browser yang didukung untuk dialog, live region, canvas outline, and focus return; review 36 target axe `incomplete` secara visual.
2. **P1 — Human usability evidence:** moderated novice dan expert session belum dapat dibuktikan oleh automated Chromium. Catat task time, bantuan, backtrack, terminology issue, dan ease score.
3. **P1 — UX-M1 shared shell:** tracker masih menyatakan shared-shell integration sebagai follow-up; jangan menandai formal release sign-off sebelum navigation contract dan regression lintas enam route disetujui.
4. **P2 — Release artifact:** simpan JSON gate, screenshot 390/1440, browser/version, fixture revision, commit SHA, reviewer, dan tanggal pada CI/release record; file `/tmp` hanya bukti lokal sementara.

**Exit criteria UX-M6:** automated acceptance **terpenuhi untuk H6-A01, H6-A02, H6-A03, H6-A07, dan H6-A08**; H6-A04–H6-A06 memiliki automated proxy yang lulus tetapi belum menggantikan screen-reader/moderated study; H6-A09 masih pending. UX-M6 belum boleh disebut formal release sign-off sampai residual P1 di atas memiliki owner, bukti, dan keputusan rilis.

### 22.16 Delivery sequence, checkpoint, dan ownership

Urutan delivery yang direkomendasikan:

| Checkpoint | Milestone/action | Hasil demonstrasi | Keputusan gate |
|---|---|---|---|
| CP0 · Contract review | UX-M0 | Canonical IA, state, copy, responsive, dan baseline tests | Approve contract atau revisi sebelum coding shell. |
| CP1 · Shell demo | UX-M1 | Enam route memakai sidebar/workflow/header yang sama | Lanjut jika navigation/state/focus regression pass. |
| CP2 · Core Model demo | UX-M2 + token awal UX-M3 | Canvas mobile/desktop, Fit, sheet, selection, canonical trace | Lanjut jika tidak ada overlap dan exact trace pass. |
| CP3 · Shared operations demo | UX-M3 + UX-M4 | Typography, filters, lists, inspector pada tiga workspace | Lanjut jika responsive/keyboard/URL state pass. |
| CP4 · End-to-end content demo | UX-M5 | Overview → Model → Findings → Action → Evidence → Report | Lanjut jika state/semantics tetap benar dan page acceptance pass. |
| CP5 · Release candidate | UX-M6 | Automated + manual + human usability evidence | Sign-off hanya jika no open P0. |

Ownership minimum:

- **Product owner:** memutuskan IA, lifecycle, terminology, priority, and accepted residual risk.
- **UX/design:** page anatomy, progressive disclosure, content hierarchy, responsive state, usability script, dan visual acceptance.
- **Frontend:** shared shell/components, state preservation, responsive behavior, semantics, performance, dan test hooks.
- **Backend/domain owner:** menjaga canonical DFD/threat/control/test semantics, revision, and provenance contract; tidak mengubah semantics untuk memudahkan layout.
- **QA/accessibility:** contract/regression/axe/keyboard/screen-reader/geometry evidence dan defect triage.

Setiap pull request harus mencantumkan action ID, screenshot sebelum/sesudah untuk viewport terdampak, automated test yang ditambah/diubah, accessibility impact, dan confirmation bahwa canonical IDs/deferred semantics tidak berubah.

### 22.17 Milestone tracker

Gunakan tabel ini sebagai ringkasan status; detail tetap berada pada action ID di §22.15.

| Milestone | Status awal | Syarat mulai | Definition of Done | Progress |
|---|---|---|---|---:|
| UX-M0 · Contract/baseline | **DONE — 2026-09-24** | Audit selesai | H0-A01–H0-A08 DONE; contract fixture, baseline manifest, dan drift gate tersedia | **8/8** |
| UX-M1 · Shared shell/lifecycle | **PARTIAL — core 2026-09-24** | UX-M0 DONE | H1-A01/A02/A03/A04/A06 core done; H1-A05/A08 partial; H1-A07 pending | **5/8 core + 2 partial + 1 pending** |
| UX-M2 · DFD Model recovery | **DONE — core 2026-09-24** | UX-M0 DONE | H2-A01–H2-A08 DONE; H1 shared-shell integration remains a follow-up validation | **8/8** |
| UX-M3 · Readability/hierarchy | **DONE — 2026-09-24** | UX-M0 DONE | H3-A01–H3-A07 DONE; Chromium readability gate + U7/U2 regression lulus | **7/7** |
| UX-M4 · Filters/list/inspector | **DONE — core 2026-09-24** | UX-M1 + UX-M3 output digunakan; shared-shell integration UX-M1 tetap follow-up | H4-A01–H4-A09 DONE; UX-M4 Chromium gate + U7 regression lulus | **9/9** |
| UX-M5 · Page simplification | **DONE — core 2026-09-24** | UX-M1–UX-M4 DONE | H5-A01–H5-A09 DONE; M5 Chromium gate + U4/Package G/axe regression lulus | **9/9** |
| UX-M6 · Release sign-off | **PARTIAL — automated gate 2026-09-24** | UX-M1–UX-M5 output digunakan; formal dependency UX-M1 shared-shell masih residual | Automated H6-A01/A02/A03/A07/A08 pass; H6-A04/A05/A06 proxy pass; H6-A09 formal sign-off pending | **5/9 automated + 3 partial + 1 pending** |

Parallelization yang aman:

- Setelah UX-M0, UX-M1, UX-M2, dan token foundation UX-M3 dapat berjalan paralel selama memakai contract yang sama.
- UX-M4 menunggu shared shell dan typography/interaction tokens stabil.
- Content inventory UX-M5 sudah diterapkan setelah UX-M4; detail persona study dan release evidence tetap menjadi scope UX-M6.
- UX-M6 tidak boleh dimulai sebagai release sign-off sebelum UX-M1–UX-M5 selesai; smoke test tetap dijalankan pada setiap PR.

Perkiraan unit delivery adalah **satu action ID per PR kecil** atau beberapa action yang sangat terkait dalam satu PR. Jangan menggabungkan seluruh milestone ke satu perubahan besar karena akan menyulitkan review visual, regression isolation, dan rollback.
