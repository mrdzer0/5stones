# Product Requirements Document

> ID: PRD-WH-009
> Completeness: Half
> Product type: Partner webhook ingestion API
> Owner: Platform Integrations Team
> Release: Partner beta synthetic sample
> Expected threat-model scope: Webhook receive, authenticate, queue, process, retry, audit

## 1. Overview

The platform receives order-status events from partner systems. A partner sends an HTTP request to the Webhook gateway. The gateway validates the payload, places an event on a queue, and the Order service updates an order. A delivery log helps operators investigate failures.

The PRD names a signature header but does not specify the algorithm, key rotation, timestamp tolerance, replay window, or partner offboarding process. It also does not define whether the event processor is exactly-once or how a duplicate event is made harmless.

## Actors and roles

- **Partner system**: sends order events.
- **Integration operator**: reviews delivery failures and disables an integration.
- **Internal event processor**: consumes events and updates order state.
- **Order service**: authoritative owner of order status.
- **Partner platform**: customer-controlled external system.

## User journeys

### UC-01 Partner sends an order status event

Actor: Partner system

Steps:

1. Partner creates an event containing partner ID, event ID, order reference, status, and event timestamp.
2. Partner sends the event and a signature header to the Webhook gateway.
3. Webhook gateway validates the partner identity and signature.
4. Gateway places the event on the Event queue and returns an acknowledgement.
5. Internal event processor consumes the event.
6. Order service checks the event ID and updates order status.
7. Delivery log records receipt, processing result, and correlation ID.

Data: Partner ID, event ID, order reference, status, timestamp, signature, correlation ID.

Evidence locator: User journeys / UC-01 Partner sends an order status event.

### UC-02 Integration operator reviews a failed delivery

Actor: Integration operator

Steps:

1. Operator opens the delivery log.
2. Operator searches by partner ID or correlation ID.
3. Operator views a redacted payload summary and failure reason.
4. Operator may disable the integration.

Data: Partner ID, correlation ID, status, failure reason, redacted payload summary, operator decision.

Evidence locator: User journeys / UC-02 Integration operator reviews a failed delivery.

## Components and trust boundaries

| Zone | Components | Trust boundary |
| --- | --- | --- |
| External | Partner system | Customer-controlled boundary |
| Public-facing | Webhook gateway, rate limiter | Internet boundary |
| Internal application | Event queue, Event processor, Order service | Organization boundary |
| Data stores | Delivery log, Order database | Operational and business data boundary |
| Operations | Integration operator console | Privileged workforce boundary |

## Data flows

| Flow | Source -> destination | Protocol | Data | Evidence |
| --- | --- | --- | --- | --- |
| F-01 | Partner system -> Webhook gateway | HTTPS | Event payload, signature header | UC-01 |
| F-02 | Webhook gateway -> Event queue | Internal API | Validated event | UC-01 |
| F-03 | Event queue -> Event processor | Queue protocol | Event and metadata | UC-01 |
| F-04 | Event processor -> Order service -> Order database | Internal API / SQL | Order reference and status | UC-01 |
| F-05 | Gateway/processor -> Delivery log | Append-only API | Receipt, result, correlation ID | UC-01, UC-02 |
| F-06 | Operator console -> Delivery log | HTTPS | Search and redacted result | UC-02 |

## Data inventory

| Data | Classification | Store or transit | Known requirement |
| --- | --- | --- | --- |
| Event payload | Partner business data | Gateway, queue, processor | Schema validation and minimization |
| Signature header | Security-sensitive data | Gateway transit | Do not persist raw secret material |
| Order reference and status | Confidential business data | Order database and logs | Authorization and integrity |
| Delivery log | Operational data | Delivery log | Redaction and operator access |

## External systems

- Partner platform: sends events and owns signing credentials. Offboarding and ownership contacts are not specified.

## Functional requirements

1. A valid event is acknowledged and queued.
2. An invalid event is rejected and does not reach the Order service.
3. A valid event updates the relevant order.
4. Operators can inspect delivery status and disable a partner integration.
5. The event processor can retry failures.

## Security and privacy requirements

- Validate partner signature before enqueueing.
- Apply rate limits and payload size limits at the gateway.
- Make event processing idempotent using the partner event ID.
- Redact sensitive payload fields from operator views and logs.

The signing algorithm, key rotation, timestamp validation, replay window, dead-letter access, schema versioning, and partner offboarding controls are not specified.

## Open questions and assumptions

- **TBD**: Which signature algorithm and canonicalization rules are used?
- **TBD**: How are partner secrets rotated and revoked?
- **TBD**: What timestamp tolerance and replay window apply?
- **TBD**: Which service owns the dead-letter queue and replay approval?
- **TBD**: Is a status transition monotonic, and how are out-of-order events handled?
- **TBD**: What payload fields may be stored in the Delivery log?
- **TBD**: How is a partner disabled and removed from the trust list?
- Assumption: event ID is intended to be unique per partner but this is not yet enforced.

## Acceptance criteria

1. Invalid or replayed events are rejected or safely ignored according to a documented policy.
2. A duplicate event cannot produce a duplicate business side effect.
3. Operator views show enough context to triage without exposing unnecessary payload data.
4. The analysis reports signature, replay, retry, ordering, and offboarding details as deferred until specified.
