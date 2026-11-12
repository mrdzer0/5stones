# Product Requirements Document

> ID: PRD-IDV-006
> Completeness: Complete
> Product type: Identity and document verification feature in an underwriting workflow
> Owner: Onboarding and Risk Team
> Release: J1 synthetic sample
> Expected threat-model scope: Government identity check, face match, threshold configuration, quota alert, decision audit

## 1. Overview

The underwriting workflow checks an applicant's government identity data and then performs a face-recognition check before the applicant proceeds to the next credit decision step. The face check is triggered only after the government identity service passes. The feature must preserve the score category and threshold configuration used at the time of the decision so that later threshold changes do not rewrite historical decisions.

This PRD is based on the shape of the provided Dukcapil FR reference: a post-webservice verification step, score bands, response-code branches, configurable thresholds, quota monitoring, monitoring columns, and a decision flow. All values, providers, IDs, and examples below are synthetic.

## Actors and roles

- **Applicant**: submits identity and face data during onboarding.
- **Underwriting workflow**: orchestrates the identity checks and applies decision branches.
- **Document verification adapter**: calls the government identity service.
- **Face recognition adapter**: calls the face provider and normalizes score/response.
- **Risk operations analyst**: reviews exceptions and threshold decisions.
- **Product manager**: receives a low-quota alert and requests capacity replenishment.
- **Government identity service**: validates identity attributes.
- **Face recognition provider**: returns match score, response code, transaction reference, and remaining quota.
- **Alert channel**: receives operational quota alerts.

## User journeys

### UC-01 Applicant passes identity and face checks

Actor: Applicant

Trigger: Applicant reaches the J1 underwriting stage after submitting an application.

Preconditions: Applicant has provided a synthetic government identifier and face image; the J1 feature is active.

Steps:

1. Underwriting workflow sends identifier and required attributes to the Document verification adapter.
2. Document verification adapter calls the Government identity service.
3. Government identity service returns attribute match results; at least two of three configured attributes must match.
4. If the identity check passes, Underwriting workflow sends the face image and identifier reference to the Face recognition adapter.
5. Face recognition adapter calls the Face recognition provider.
6. The adapter validates the provider response and returns score, response code, verification result, transaction ID, and remaining quota.
7. Underwriting workflow reads the active J1 thresholds and maps the score to `very_high`, `high`, `low`, or `zero`.
8. Workflow writes the score category and threshold snapshot to the Decision store.
9. Workflow sends the applicant to the next stage or to a review/reapply branch according to the decision table.

Data: Government identifier reference, identity match result, face image, match score, response code, verification result, transaction ID, quota remaining, threshold snapshot, decision branch.

Decision rules:

- Score in `[9.5, 10.1)` maps to `very_high` and proceeds to the next stage.
- Score in `[5, 9.5)` maps to `high` and proceeds to the next stage.
- Score in `(0, 5)` maps to `low` and goes to review.
- Score `0` with response code `6020` goes to the next stage only after the configured exception policy; otherwise it goes to reapply after 14 days.
- A response code `6018` is a successful provider response; `6019` means the image does not match; `6020` means the identifier was not found.

Evidence locator: User journeys / UC-01 Applicant passes identity and face checks.

### UC-02 Risk operations reviews an exception

Actor: Risk operations analyst

Trigger: The workflow creates a low, zero, or provider-error review item.

Steps:

1. Analyst opens the exception record in the Operations console.
2. Console reads the masked applicant reference, score category, response code, threshold snapshot, and provider transaction reference.
3. Analyst records a review outcome and reason.
4. Decision store appends the outcome and analyst identity to the audit log.

Data: Masked applicant reference, score category, response code, threshold snapshot, provider transaction reference, review outcome, reason.

Evidence locator: User journeys / UC-02 Risk operations reviews an exception.

### UC-03 Product manager receives quota alert

Actor: Product manager

Trigger: Face recognition provider quota falls below the configured alert threshold.

Steps:

1. Face recognition adapter reads `quotaRemaining` from a valid provider response.
2. Quota monitor compares the value with the active threshold, for example 42,000 calls.
3. Quota monitor emits an alert event once per threshold crossing.
4. Alert channel delivers a message containing provider name, remaining quota, timestamp, and runbook link.

Data: Remaining quota, alert threshold, provider name, timestamp, alert state.

Evidence locator: User journeys / UC-03 Product manager receives quota alert.

## Components and trust boundaries

| Zone | Components | Trust boundary |
| --- | --- | --- |
| Applicant-controlled | Mobile/web onboarding client | Untrusted device and network |
| Public-facing | Onboarding API | Internet to organization boundary |
| Internal application | Underwriting workflow, adapters, Threshold configuration, Quota monitor | Organization application boundary |
| Restricted data | Decision store, Audit log, Evidence store | Identity, biometric, and decision boundary |
| Operations | Operations console, Alert channel | Privileged workforce/operations boundary |
| External systems | Government identity service, Face recognition provider | External provider boundary |

## Data flows

| Flow | Source -> destination | Protocol | Data | Evidence |
| --- | --- | --- | --- | --- |
| F-01 | Applicant -> Onboarding API | HTTPS | Identifier reference, face image | UC-01 |
| F-02 | Onboarding API -> Underwriting workflow | Internal mTLS | Application and stage context | UC-01 |
| F-03 | Underwriting workflow -> Document verification adapter | Internal mTLS | Identity attributes | UC-01 |
| F-04 | Document verification adapter -> Government identity service | Provider HTTPS | Identifier and matching attributes | UC-01 |
| F-05 | Underwriting workflow -> Face recognition adapter | Internal mTLS | Face image and identity reference | UC-01 |
| F-06 | Face recognition adapter -> Face recognition provider | Provider HTTPS | Face image, identifier, transaction source | UC-01 |
| F-07 | Face recognition adapter -> Underwriting workflow | Internal mTLS | Score, response code, result, transaction ID, quota | UC-01 |
| F-08 | Underwriting workflow -> Threshold configuration | Private API | Active J1 thresholds | UC-01 |
| F-09 | Underwriting workflow -> Decision store | Private database | Category, threshold snapshot, branch | UC-01 |
| F-10 | Decision store -> Operations console | Private HTTPS | Masked exception context | UC-02 |
| F-11 | Decision store -> Audit log | Append-only API | Analyst outcome and reason | UC-02 |
| F-12 | Face recognition adapter -> Quota monitor -> Alert channel | Internal event / HTTPS | Quota and threshold crossing | UC-03 |

## Data inventory

| Data | Classification | Store or transit | Protection expectation |
| --- | --- | --- | --- |
| Government identifier reference | Restricted personal data | Provider transit and Evidence store | Masked in operations views; retention TBD |
| Face image and match result | Restricted biometric data | Provider transit and controlled evidence store | Explicit purpose, encryption, deletion policy |
| Score and response code | Sensitive decision data | Decision store | Preserve threshold snapshot and audit changes |
| Provider transaction ID and log ID | Operational trace data | Decision store and audit log | No secret material; access restricted |
| Remaining quota | Operational data | Adapter and quota monitor | Alert only; no applicant data in alerts |

## External systems

- Government identity service: validates identity attributes and may return match responses.
- Face recognition provider: returns a score and response code. The adapter must validate response structure and provider identity.
- Alert channel: receives operational quota messages and must not receive identity or biometric data.

## Functional requirements

1. The face check runs after a successful government identity check and is not repeated after a later unrelated validation unless policy allows it.
2. Thresholds are configurable per product stage and are captured in each decision record.
3. Provider response codes and score values are normalized before branch evaluation.
4. Historical score categories do not change when thresholds are updated.
5. Low quota alerts use a configurable threshold and de-duplicate repeated alerts.
6. Operations views mask identifiers and face data.

## Security and privacy requirements

- Authenticate and authorize provider calls; validate TLS identity and response schema.
- Do not put biometric images or identifiers in logs, alerts, or change reasons.
- Enforce least privilege for threshold changes and require an approval/audit trail.
- Make decision evaluation deterministic and record the exact threshold version.
- Detect replay or duplicate provider transaction references.
- Apply data minimization and deletion rules to biometric evidence.

## Open questions and assumptions

- The exact biometric deletion schedule and lawful basis must be confirmed by privacy/legal owners.
- Certificate rotation and provider outage ownership must be assigned.
- Assumption: the provider's remaining quota is authoritative for alerting but not for underwriting decisions.

## Acceptance criteria

1. A failed government identity check does not invoke the face provider.
2. A provider score maps to exactly one category using the threshold version active at decision time.
3. A zero score and response code are evaluated together, not independently.
4. A duplicate provider response cannot create duplicate underwriting outcomes.
5. Historical decisions preserve score category and threshold snapshot after a configuration change.
6. Quota alerts contain no applicant or biometric data.
