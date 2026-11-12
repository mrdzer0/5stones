# Product Requirements Document

> ID: PRD-DB-001
> Completeness: Complete
> Product type: Consumer web and mobile banking
> Owner: Digital Banking Product Team
> Release: Q4 synthetic sample
> Expected threat-model scope: Customer authentication, account view, internal transfer, bill payment, fraud review

## 1. Overview

The banking application lets a customer view accounts, add a trusted beneficiary, transfer money between accounts, and pay a bill. The mobile and web clients use the same API gateway. The ledger is authoritative for balances and transaction status. A fraud decision service evaluates a device signal, beneficiary history, amount, and velocity before a transfer is released.

The product must never expose a full payment instrument number to the application database. The payment network receives a tokenized instruction from the payment orchestration service. A customer can cancel a scheduled payment before the cut-off time, but cannot change a settled transaction.

## Actors and roles

- **Customer**: views balances, manages beneficiaries, submits transfers, and receives one-time codes.
- **Operations analyst**: reviews fraud alerts and can place a transfer on hold; cannot edit ledger entries.
- **Fraud decision service**: evaluates risk signals and returns allow, challenge, or hold.
- **Identity provider**: authenticates a customer with password plus one-time code and returns an identity assertion.
- **Payment network**: external recipient for tokenized bill payment instructions.
- **SMS provider**: delivers one-time codes and security notifications.

## User journeys

### UC-01 Customer signs in

Actor: Customer

Trigger: Customer opens the mobile app or web client.

Preconditions: The customer has an active account and the identity provider is available.

Steps:

1. Customer submits email and password to the banking client.
2. Banking client sends the credentials over HTTPS to the API gateway.
3. API gateway delegates authentication to the Identity provider.
4. Identity provider sends a one-time code through the SMS provider.
5. Customer submits the code; the identity provider returns an identity assertion.
6. API gateway creates a short-lived session and sends a session token to the client.

Data: Email, password credential, one-time code, identity assertion, session token.

Expected outcome: The customer can view only accounts associated with the authenticated identity.

Evidence locator: User journeys / UC-01 Customer signs in.

### UC-02 Customer submits an internal transfer

Actor: Customer

Trigger: Customer selects a beneficiary and confirms an amount.

Preconditions: Customer is authenticated; beneficiary is active; source account has sufficient available balance.

Steps:

1. Customer enters beneficiary, amount, reference, and confirmation code in the banking client.
2. Client sends a transfer request with the session token to the API gateway.
3. API gateway passes the normalized request to the Payment orchestration service.
4. Payment orchestration reads the customer profile, beneficiary, and recent transaction history from the Account database.
5. Payment orchestration sends device signal, amount, beneficiary age, and velocity to the Fraud decision service.
6. Fraud decision service returns allow, challenge, or hold with a reason code.
7. If allowed, Payment orchestration requests a debit and credit from the Ledger service.
8. Ledger service writes an immutable transaction record to the Ledger database.
9. Payment orchestration sends a confirmation event to the Notification service, which uses the SMS provider for a security notification.

Data: Beneficiary, transfer amount, reference, device signal, velocity, risk decision, ledger entry, notification content.

Decision rules: A hold is visible to Operations analysts. A denied request does not create a settled ledger entry. A request with the same idempotency key must not create a second debit.

Evidence locator: User journeys / UC-02 Customer submits an internal transfer.

### UC-03 Customer pays a bill

Actor: Customer

Trigger: Customer confirms a biller and amount.

Steps:

1. Customer selects biller and enters the bill reference in the banking client.
2. Payment orchestration validates the bill reference and obtains a payment token from the Token vault.
3. Payment orchestration sends a tokenized payment instruction over mutually authenticated HTTPS to the Payment network.
4. Payment network returns an authorization result and network reference.
5. Ledger service records the payment status and reference.
6. Notification service sends a receipt without including the full payment instrument number.

Data: Biller reference, payment token, amount, authorization result, network reference, receipt.

Evidence locator: User journeys / UC-03 Customer pays a bill.

### UC-04 Operations analyst reviews a fraud hold

Actor: Operations analyst

Trigger: A transfer receives a hold decision.

Steps:

1. Fraud decision service publishes a hold event to the Operations queue.
2. Operations analyst opens the hold record in the Operations console.
3. Operations console reads the masked customer and transaction context from the Fraud case store.
4. Analyst either releases the transfer or rejects it with a reason.
5. The decision is appended to the audit log; the analyst cannot directly edit ledger entries.

Data: Masked customer reference, risk signals, transfer summary, analyst decision, reason, audit event.

Evidence locator: User journeys / UC-04 Operations analyst reviews a fraud hold.

## Components and trust boundaries

| Zone | Components | Trust boundary |
| --- | --- | --- |
| Customer-controlled | Mobile client, web browser | Untrusted client device and network |
| Public-facing | API gateway, rate limiter | Internet to organization boundary |
| Internal application | Account service, Payment orchestration, Ledger service, Notification service | Organization application boundary |
| Restricted data | Account database, Ledger database, Token vault, Fraud case store, Audit log | Restricted financial and identity data |
| Operations | Operations console, Operations queue | Privileged workforce boundary |
| External systems | Identity provider, SMS provider, Fraud decision service, Payment network | Third-party control boundary |

## Data flows

| Flow | Source -> destination | Protocol | Data | Evidence |
| --- | --- | --- | --- | --- |
| F-01 | Customer -> Mobile/web client | HTTPS | Credentials, transfer form | UC-01, UC-02 |
| F-02 | Mobile/web client -> API gateway | HTTPS | Session token, normalized request | UC-01, UC-02 |
| F-03 | API gateway -> Identity provider | OIDC over HTTPS | Login request, identity assertion | UC-01 |
| F-04 | Identity provider -> SMS provider | HTTPS | One-time code delivery request | UC-01 |
| F-05 | API gateway -> Payment orchestration | Internal mTLS | Transfer request | UC-02 |
| F-06 | Payment orchestration -> Account database | Internal SQL | Profile, beneficiary, transaction history | UC-02 |
| F-07 | Payment orchestration -> Fraud decision service | mTLS | Device signal, amount, velocity | UC-02 |
| F-08 | Payment orchestration -> Ledger service | Internal mTLS | Debit/credit instruction | UC-02 |
| F-09 | Ledger service -> Ledger database | Private SQL | Immutable transaction record | UC-02, UC-03 |
| F-10 | Payment orchestration -> Payment network | mTLS | Tokenized payment instruction | UC-03 |
| F-11 | Ledger service -> Notification service -> SMS provider | Internal mTLS / HTTPS | Masked receipt and alert | UC-02, UC-03 |
| F-12 | Fraud decision service -> Operations queue -> Operations console | Private queue / HTTPS | Hold case and risk reason | UC-04 |
| F-13 | Operations console -> Audit log | Append-only API | Analyst decision and reason | UC-04 |

## Data inventory

| Data | Classification | Store or transit | Retention requirement |
| --- | --- | --- | --- |
| Customer profile and account number | Confidential PII | Account database | Retain for account lifecycle plus regulatory period; exact period TBD |
| Password and one-time code | Secret | Identity provider only, short-lived transit | Never persist in application database |
| Device signal and fraud score | Sensitive security data | Fraud service and Fraud case store | Restricted access; exact retention TBD |
| Payment token | Secret/payment data | Token vault and Payment network transit | Token vault policy applies |
| Ledger transaction | Financial record | Ledger database and audit log | Immutable; regulatory retention |
| Receipt and notification | Confidential | Notification service and SMS provider | Do not include full instrument number |

## External systems

- Identity provider: OIDC authentication, identity assertion, one-time-code challenge.
- SMS provider: outbound one-time codes and security notifications. The provider must not receive password or full account history.
- Fraud decision service: returns a decision and reason code; it does not write the ledger.
- Payment network: accepts tokenized payment instructions and returns authorization reference.

## Functional requirements

1. All client requests must use HTTPS and a short-lived session token.
2. Transfer requests must carry an idempotency key and be normalized server-side.
3. A customer may access only their own accounts and beneficiaries.
4. A fraud `hold` must be visible to Operations analysts without granting ledger-write access.
5. Settled ledger entries are immutable; cancellation is represented as a compensating transaction.
6. The application database must never store a full payment instrument number.
7. Every privileged review decision must produce an audit event containing actor, timestamp, target, outcome, and reason.

## Security and privacy requirements

- Enforce server-side authorization at account, beneficiary, and transaction scope.
- Verify the identity provider assertion issuer, audience, nonce, and expiry.
- Rate-limit login, one-time-code verification, beneficiary changes, and transfer submission.
- Protect service-to-service calls with mTLS and audience-scoped credentials.
- Use idempotency and replay detection for transfer and payment requests.
- Mask account and payment data in logs, support views, notifications, and fraud cases.
- Separate Operations roles for review, release, and policy administration.
- Alert on anomalous transfer velocity and repeated failed challenges.

## Open questions and assumptions

- The exact regulatory retention period for account and ledger data is not specified.
- The owner and rotation interval for mTLS certificates must be confirmed.
- The incident response owner for a Payment network outage must be assigned.
- Assumption: the Fraud decision service is a third-party system and may return an unavailable state.

## Acceptance criteria

1. A customer can authenticate and access only their own account context.
2. A duplicate transfer request with the same idempotency key creates one ledger effect.
3. A held transfer cannot settle until an authorized Operations analyst makes a decision.
4. A payment receipt contains a tokenized or masked reference, never the full payment instrument number.
5. A privileged review can be traced from the hold case to an immutable audit event.
6. The DFD review can locate every primary flow in UC-01 through UC-04 and the relevant trust boundary.
