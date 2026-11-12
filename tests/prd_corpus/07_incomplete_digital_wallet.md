# Product Requirements Document

> ID: PRD-WALLET-007
> Completeness: Incomplete
> Product type: Digital wallet top-up and transfer
> Owner: Payments Team
> Release: Discovery draft synthetic sample
> Expected threat-model scope: Wallet balance, top-up, peer transfer

## 1. Overview

Users should be able to add money to a wallet and send money to another user. The first draft is intentionally incomplete. It is useful for testing whether the application can recognize when a document is too sparse for a reliable DFD and can guide the owner toward the missing information.

The draft says that a user enters an amount, the wallet balance changes, and the recipient sees the transfer. It does not define the authentication method, source of funds, ledger, payment provider, fraud review, or recovery behavior.

## Actors and roles

- **User**: starts a top-up or transfer.
- **Recipient**: receives a transfer notification or updated balance.
- **Other actors**: unknown. It is not defined whether support, finance, or an automated fraud service can review or reverse a transfer.

## User journeys

### UC-01 User transfers money

Actor: User

Steps:

1. User enters recipient and transfer amount in the Wallet application.
2. Wallet application sends the transfer request.
3. Wallet balance decreases and the recipient balance increases.

Data: User ID, recipient ID, transfer amount, wallet balance.

Evidence locator: User journeys / UC-01 User transfers money.

The draft does not define how the user is authenticated, which service authorizes the transfer, which data store is authoritative, how a duplicate request is handled, or how the recipient is notified.

### UC-02 User adds money

Actor: User

Steps:

1. User selects an amount in the Wallet application.
2. The wallet is topped up.

Data: User ID, top-up amount.

Evidence locator: User journeys / UC-02 User adds money.

The funding source, external payment system, confirmation callback, and failed top-up behavior are not defined.

## Components and trust boundaries

Only one component is named:

- **Wallet application**: user interface and unspecified backend behavior.

The draft does not define whether there is an API gateway, ledger service, wallet database, payment gateway, notification system, fraud service, or administrative console. Trust boundaries are **not defined**.

## Data flows

| Flow | Source -> destination | Protocol | Data | Evidence |
| --- | --- | --- | --- | --- |
| F-01 | User -> Wallet application | Not defined | Recipient and amount | UC-01 |
| F-02 | Wallet application -> unknown wallet processing | Not defined | Transfer request | UC-01 |
| F-03 | Unknown wallet processing -> Recipient | Not defined | Updated balance or notification | UC-01 |
| F-04 | User -> Wallet application | Not defined | Top-up amount | UC-02 |

These are candidate interactions only. The draft is not sufficient to confirm the processing service or data stores.

## Data inventory

| Data | Classification | Store or transit | Known requirement |
| --- | --- | --- | --- |
| User ID | Personal data | Unknown | Access and source are not defined |
| Recipient ID | Personal data | Unknown | Enumeration and authorization are not defined |
| Transfer amount | Financial data | Unknown | Integrity and currency are not defined |
| Wallet balance | Financial data | Unknown | Ledger authority and immutability are not defined |

## External systems

No external system is named. A payment provider may be required for top-up, but that is an open question and must not be invented by the analysis.

## Functional requirements

1. A user can start a top-up.
2. A user can transfer money to a recipient.
3. The recipient eventually sees the transfer.

## Security and privacy requirements

No security control is specified beyond the expectation that the feature should be safe. Authentication, authorization, transaction integrity, idempotency, fraud controls, rate limits, ledger design, audit, encryption, retention, and support reversal are all **not defined**.

## Open questions and assumptions

- **TBD**: What authenticates the user and what step-up control protects a transfer?
- **TBD**: What service and database own the wallet ledger?
- **TBD**: Is top-up performed through a card, bank transfer, or another provider?
- **TBD**: How are duplicate requests and provider callbacks handled?
- **TBD**: Can transfers be reversed, and who is authorized to reverse them?
- **TBD**: What data is retained and how is a user deletion request handled?
- **TBD**: What monitoring detects unusual transfer velocity or account takeover?
- Assumption: none of the omitted controls should be treated as implemented or as a confirmed vulnerability.

## Acceptance criteria

1. Product owner supplies an authenticated end-to-end transfer flow before release planning.
2. Product owner identifies the authoritative ledger and external funding systems.
3. Product owner defines authorization, idempotency, reversal, audit, retention, and recovery requirements.
4. Threat modeling marks the primary interaction as deferred until those facts are provided.
