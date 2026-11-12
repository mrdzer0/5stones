# Product Requirements Document

> ID: PRD-AI-008
> Completeness: Incomplete
> Product type: LLM-assisted customer support console
> Owner: Support Experience Team
> Release: Exploration draft synthetic sample
> Expected threat-model scope: Conversation summarization, suggested reply, agent handoff

## 1. Overview

Support agents should be able to open a customer conversation, ask an AI assistant for a summary, and receive a suggested reply. The assistant may use conversation text and a customer profile. The draft does not define whether the assistant can call tools or change customer data.

The purpose of this case is to test prompt-injection, sensitive-data handling, model-provider boundary, and human-approval questions without allowing the analyzer to claim that an exploit is confirmed merely because controls are not documented.

## Actors and roles

- **Support agent**: reads a conversation and requests a summary or suggested reply.
- **Customer**: writes messages that may be included in the conversation.
- **AI assistant**: generates text based on context.
- **LLM provider**: external service that may process prompts and responses.
- **Other actors and administrators**: not defined.

## User journeys

### UC-01 Agent requests an AI summary

Actor: Support agent

Steps:

1. Agent opens a customer conversation in the Support console.
2. Console sends the conversation to the Conversation service.
3. Conversation service sends a prompt to the AI assistant.
4. AI assistant returns a summary to the Console.

Data: Customer message, conversation transcript, customer profile, prompt, summary.

Evidence locator: User journeys / UC-01 Agent requests an AI summary.

The draft does not define whether the full profile is sent to the LLM provider, how system instructions are separated from customer text, or how output is reviewed.

### UC-02 Agent uses a suggested reply

Actor: Support agent

Steps:

1. Agent asks the AI assistant for a reply draft.
2. AI assistant returns suggested text.
3. Agent may edit and send the reply.

Data: Customer message, suggested reply, agent edit, outbound message.

Evidence locator: User journeys / UC-02 Agent uses a suggested reply.

It is unknown whether the AI assistant can send the reply directly or invoke an account tool.

## Components and trust boundaries

| Zone | Components | Trust boundary |
| --- | --- | --- |
| Workforce | Support console | Privileged agent boundary |
| Internal application | Conversation service, AI assistant | Organization boundary; prompt handling not defined |
| Data stores | Conversation store, Customer profile store | Customer data boundary; exact stores are inferred as candidates |
| External system | LLM provider | Third-party model/data-processing boundary |

No tool executor, outbound message service, policy gateway, or redaction service is defined.

## Data flows

| Flow | Source -> destination | Protocol | Data | Evidence |
| --- | --- | --- | --- | --- |
| F-01 | Customer -> Conversation service | Not defined | Customer message | UC-01, UC-02 |
| F-02 | Support agent -> Support console | HTTPS assumed, not specified | Summary or reply request | UC-01, UC-02 |
| F-03 | Support console -> Conversation service | Not defined | Conversation reference | UC-01 |
| F-04 | Conversation service -> AI assistant -> LLM provider | Not defined | Prompt and conversation context | UC-01, UC-02 |
| F-05 | AI assistant -> Support console | Not defined | Summary or suggested reply | UC-01, UC-02 |

These flows do not prove that the LLM provider receives all profile fields or that the assistant can take an autonomous action.

## Data inventory

| Data | Classification | Store or transit | Known requirement |
| --- | --- | --- | --- |
| Customer message and transcript | Confidential customer data | Conversation store and AI prompt candidate | Scope and retention TBD |
| Customer profile | Personal data | Profile store and possible prompt context | Field minimization TBD |
| Suggested reply | Support business data | Console and conversation system | Human review boundary TBD |
| System prompt and policy | Security-sensitive configuration | AI assistant | Separation and versioning TBD |

## External systems

- LLM provider: external service that may process prompts and generated output. Data processing region, retention, training use, and contractual controls are not specified.

## Functional requirements

1. An agent can request a summary of a conversation.
2. An agent can request a suggested reply.
3. An agent can edit a suggested reply before sending.

## Security and privacy requirements

No concrete controls are specified for prompt injection, sensitive-field redaction, model output validation, tool authorization, provider retention, or audit. Those gaps must be represented as deferred decisions and not as implemented controls or confirmed vulnerabilities.

## Open questions and assumptions

- **TBD**: Can customer messages contain instructions that change assistant behavior?
- **TBD**: Which fields are allowed in a prompt sent to the LLM provider?
- **TBD**: Is the provider allowed to retain prompts or use them for training?
- **TBD**: Can the assistant call tools, send a reply, refund an order, or change an account?
- **TBD**: Is human approval mandatory before any outbound action?
- **TBD**: How are model output, prompt version, agent decision, and provider request audited?
- **TBD**: How are tenant and customer conversations isolated for an enterprise support deployment?
- Assumption: the assistant is advisory-only until product owners explicitly define an approved action boundary.

## Acceptance criteria

1. Product owner documents the prompt data allowlist and provider retention policy.
2. Product owner explicitly states whether tools or autonomous actions are available.
3. Product owner defines the human approval and output validation workflow.
4. Threat modeling shows prompt-injection and data-disclosure topics as deferred review items until those facts are grounded.
