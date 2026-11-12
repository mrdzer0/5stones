# Threat Modeling PRD Corpus

Corpus ini adalah kumpulan PRD sintetis untuk menguji apakah analisis threat modeling berbasis DFD dapat:

- mengekstrak aktor, proses, data store, external system, boundary, dan data flow;
- mempertahankan evidence locator dan source snippet dari dokumen;
- membedakan risiko yang grounded dari gap yang hanya perlu diklarifikasi;
- menghasilkan STRIDE, LINDDUN, control recommendation, dan test scenario yang relevan;
- tetap berguna ketika dokumen lengkap, setengah lengkap, simple, atau sengaja tidak lengkap.

Dokumen `tests/PRD - J1 Dukcapil FR Check.pdf` digunakan sebagai referensi struktur PRD feature perusahaan: objective, requirement, user story, acceptance criteria, threshold, response code, quota, monitoring, dan decision flow. Case Dukcapil di corpus ini ditulis ulang sebagai data sintetis dan tidak menyalin data produksi, nama orang, URL internal, atau identifier nyata.

## Isi corpus

| File | Kelengkapan | Domain | Fokus sampling |
| --- | --- | --- | --- |
| `01_complete_digital_banking.md` | Complete | Digital banking | Auth, payment, fraud decision, vendor KYC, PII |
| `02_complete_telemedicine.md` | Complete | Healthcare | PHI, consent, clinician access, video provider |
| `03_half_ecommerce_checkout.md` | Half | E-commerce | Checkout, payment, inventory, missing retention/auth detail |
| `04_half_saas_project_management.md` | Half | B2B SaaS | Multi-tenancy, sharing, webhooks, incomplete tenant controls |
| `05_simple_hr_leave.md` | Complete/simple | Internal HR | Small workflow, role access, approval, audit |
| `06_complete_public_service_document_verification.md` | Complete | Public service/fintech onboarding | Document verification, score thresholds, quota, response-code branching |
| `07_incomplete_digital_wallet.md` | Incomplete | Fintech wallet | Deliberately missing boundary, store, auth, retention, recovery details |
| `08_incomplete_ai_support_assistant.md` | Incomplete | AI support | Prompt injection, customer data, LLM provider, human handoff gaps |
| `09_half_partner_webhook_integration.md` | Half | API/platform integration | Signature verification, replay, retries, partner ownership gaps |

The machine-readable expectations are in [`manifest.json`](manifest.json). Each entry describes signals that should be present, topics that should be deferred when the PRD is insufficient, and negative assertions that prevent absence-of-evidence from being scored as a vulnerability.

The CR3 DFD contract is in [`dfd_quality_contract.json`](dfd_quality_contract.json). It separates required labels, optional/inferred candidates, forbidden hallucinations, and safe alias examples. Runtime DFD snapshots expose the same decision through `dfd-quality-v1` metrics, alias mappings, primary interactions, and deferred interaction records.

## CR0 metric contract and evaluation

The release metric contract is in [`metric_contract.json`](metric_contract.json). It requires explicit numerator/denominator counts for every quality metric and treats the existing 2026-09-24 `e2e_results.json` as a legacy v1 snapshot. Legacy percentage fields such as `overall_pct` and `coverage_pct` remain visible for context, but cannot pass a release gate without counts.

Run the fail-closed evaluator with:

```bash
python3 -m backend.services.prd_corpus_evaluator \
  --results tests/prd_corpus/e2e_results.json \
  --manifest tests/prd_corpus/manifest.json \
  --contract tests/prd_corpus/metric_contract.json \
  --output /tmp/prd-corpus-cr0.json \
  --markdown-output /tmp/prd-corpus-cr0.md
```

The baseline is expected to exit with code `1`: framework validation is `0/9` and the legacy result does not contain DFD precision, duplicate, topology, deferred, control mapping, or test executability counts. A future producer must emit `prd-corpus-e2e-v2` with run/provider/DFD/source provenance and explicit case-level metric counts before the result can be evaluated as a release candidate.

## Recommended test procedure

For each case:

1. Create a new project in the application.
2. Upload the corresponding Markdown file as `PRD`.
3. Wait for ingestion coverage to finish. Record `complete`, `partial`, or `deferred`, plus unread sections.
4. Run the analysis and record the active run, phase progress, retry state, and preserved results.
5. Review the DFD before reviewing findings. Check canonical nodes, trust boundaries, primary interactions, data labels, and evidence links.
6. Review STRIDE and LINDDUN findings. A finding should point to a canonical DFD interaction or be explicitly deferred.
7. Review controls and tests. Controls need an applicability decision when the PRD is silent; tests must be specific to the control/finding and not be copied verbatim to every row.
8. Compare the observed result with `manifest.json`. Save the run ID, artifact revision, DFD revision, and report revision for reproducibility.

## Expected behavior by completeness

### Complete

The system should produce a connected DFD with direct evidence for the primary user journeys. It may still identify security gaps, but those gaps should be phrased as review items or unassigned controls when the PRD does not state how a control is implemented. The result must not invent endpoints, vendors, data stores, or vulnerabilities.

### Half

The system should produce useful partial modeling and make omissions visible. Missing tenant isolation, retention, authentication, or operational ownership must become deferred questions, assumptions, or applicability decisions. They must not silently become confirmed vulnerabilities.

### Incomplete

The system should produce a limited candidate model and a clear readiness blocker. It is acceptable to have few or zero scored findings when the primary interaction cannot be grounded. The expected result is not “no risk”; it is “insufficient evidence to assess”, with next actions for the owner.

## Evaluation rubric

Use a 0-2 score for each dimension:

| Dimension | 0 | 1 | 2 |
| --- | --- | --- | --- |
| Ingestion coverage | Tail/sections silently lost | Partial with weak visibility | All sections accounted for with manifest |
| DFD grounding | Unknown or isolated nodes | Candidate model with deferred refs | Connected canonical model with evidence |
| STRIDE/LINDDUN grounding | Unsupported findings | Mixed grounded/deferred | Every scored finding has interaction/evidence |
| Control applicability | Generic or unassigned without queue | Queue exists but guidance weak | Decision, rationale, owner, and evidence are clear |
| Test executability | Repeated generic steps | Partially specific | Unique, actionable, observable, and linked |
| UX traceability | Cannot navigate across objects | Some links work | DFD -> finding -> control -> test -> evidence works |

Suggested release interpretation:

- `>= 10/12`: effective for this sample;
- `7-9/12`: usable but needs remediation for the failing dimensions;
- `<= 6/12`: not yet reliable for production threat modeling.

The rubric is a sampling aid, not a security certification. A release sign-off still requires review of the actual project context, evidence quality, and unresolved decisions.
