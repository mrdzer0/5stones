# Product Requirements Document

> ID: PRD-SAAS-004
> Completeness: Half
> Product type: Multi-tenant B2B project management platform
> Owner: Collaboration Product Team
> Release: Beta synthetic sample
> Expected threat-model scope: Workspace membership, tasks, comments, attachments, sharing, webhooks

## 1. Overview

The platform allows organizations to create workspaces, invite members, manage projects, add tasks and comments, upload attachments, and publish selected tasks through a shared link. Enterprise customers may use their own identity provider. The platform also sends webhook events to customer systems when a task changes.

The product team has not finalized tenant-key enforcement, search authorization, attachment scanning, deletion propagation, webhook signing, or support access. The platform must treat those as decisions to resolve before general availability.

## Actors and roles

- **Workspace member**: reads and edits tasks in workspaces where they are a member.
- **Workspace admin**: manages membership, sharing settings, and integrations for one workspace.
- **Platform operator**: handles availability and support; tenant access is not yet fully specified.
- **Enterprise identity provider**: authenticates enterprise users.
- **Webhook consumer**: customer-controlled endpoint receiving task events.

## User journeys

### UC-01 Member edits a task

Actor: Workspace member

Steps:

1. Member signs in through the Web client.
2. Web client requests the workspace and project list from the Workspace API.
3. Member changes task title, status, comment, or due date.
4. Workspace API verifies membership and writes the task to the Task database.
5. Workspace API updates the Search index.
6. Workspace API publishes a task-updated event to the Event queue.

Data: Identity assertion, workspace ID, project ID, task, comment, due date, event.

Evidence locator: User journeys / UC-01 Member edits a task.

### UC-02 Admin invites a member

Actor: Workspace admin

Steps:

1. Admin enters an email address and role in the Web client.
2. Workspace API checks that the admin belongs to the workspace.
3. Workspace API writes a pending membership and sends an invitation through the Notification provider.
4. Invitee accepts the invitation and becomes a member.

Data: Workspace ID, email, role, invitation token, membership state.

Evidence locator: User journeys / UC-02 Admin invites a member.

### UC-03 Member uploads an attachment

Actor: Workspace member

Steps:

1. Member chooses a file for a task.
2. Web client requests an upload URL from the Workspace API.
3. Object storage receives the file.
4. Workspace API links the object key to the task and emits an attachment-created event.

Data: File name, content, object key, task ID, uploader identity.

Evidence locator: User journeys / UC-03 Member uploads an attachment.

### UC-04 Admin creates a webhook integration

Actor: Workspace admin

Steps:

1. Admin enters a customer endpoint URL in the Integration settings.
2. Workspace API stores the integration and enables task events.
3. Event delivery service sends task events to the endpoint.

Data: Endpoint URL, workspace ID, event type, task metadata.

Evidence locator: User journeys / UC-04 Admin creates a webhook integration.

## Components and trust boundaries

| Zone | Components | Trust boundary |
| --- | --- | --- |
| User device | Web client | Untrusted endpoint |
| Public-facing | API gateway, Workspace API | Internet boundary |
| Internal application | Membership service, Task service, Search service, Event delivery service | Organization boundary |
| Tenant data | Task database, Search index, Object storage | Tenant isolation boundary; enforcement TBD |
| External systems | Enterprise identity provider, Notification provider, Webhook consumer | Third-party/customer boundary |
| Operations | Support console | Privileged boundary; support scope TBD |

## Data flows

| Flow | Source -> destination | Protocol | Data | Evidence |
| --- | --- | --- | --- | --- |
| F-01 | Member -> Web client -> Workspace API | HTTPS | Session, workspace request, task change | UC-01 |
| F-02 | Workspace API -> Membership service | Internal API | User and workspace membership | UC-01, UC-02 |
| F-03 | Workspace API -> Task database | Private database | Task, comment, status | UC-01 |
| F-04 | Task service -> Search index | Internal API | Searchable task fields | UC-01 |
| F-05 | Workspace API -> Object storage | Signed upload URL, details TBD | Attachment content and metadata | UC-03 |
| F-06 | Workspace API -> Notification provider | HTTPS | Invitation and safe workspace details | UC-02 |
| F-07 | Event queue -> Webhook consumer | HTTPS | Task event payload | UC-01, UC-04 |
| F-08 | Enterprise identity provider -> Workspace API | OIDC, details TBD | Identity assertion | UC-01 |

## Data inventory

| Data | Classification | Store or transit | Known requirement |
| --- | --- | --- | --- |
| Workspace membership | Confidential authorization data | Task database | Must be scoped to workspace; tenant key strategy TBD |
| Task and comment | Customer business data | Task database and Search index | Search deletion and authorization TBD |
| Attachment | Customer content | Object storage | Malware scanning and download authorization TBD |
| Invitation token | Secret | Notification provider and database | Expiration and one-time use TBD |
| Webhook endpoint and event payload | Confidential integration data | Integration store and outbound delivery | Signing, minimization, and rotation TBD |

## External systems

- Enterprise identity provider: authenticates users; group-to-workspace mapping is not defined.
- Notification provider: sends invitations and service messages.
- Webhook consumer: customer-owned endpoint. The platform must not assume it is trusted merely because an admin entered the URL.

## Functional requirements

1. A member can edit only tasks in workspaces where membership is active.
2. An admin can invite members and configure integrations for their workspace.
3. Attachments are linked to a task and downloadable by authorized workspace members.
4. Task changes may produce webhook events.
5. Shared links can expose only explicitly selected task content.

## Security and privacy requirements

- Workspace membership must be checked server-side on every object read and write.
- Shared links must use a separate capability and must not expose the workspace admin API.
- Webhook delivery should authenticate the sender and prevent replay.
- Attachment downloads should be authorized and content should be scanned before availability.
- Search results must enforce the same tenant and object authorization as the primary database.

## Open questions and assumptions

- **TBD**: Is tenant ID part of every database and Search index key?
- **TBD**: Does Search service re-check authorization or receive only authorized documents?
- **TBD**: Are attachments scanned synchronously or asynchronously before download?
- **TBD**: How are webhook secrets rotated and what is the replay window?
- **TBD**: Can Platform operators impersonate a member, and what approval and audit trail apply?
- **TBD**: What happens to objects in Search and Object storage after workspace deletion?
- Assumption: the Web client is not trusted to enforce tenant isolation.

## Acceptance criteria

1. A member cannot read or update a task from another workspace by changing an ID.
2. A shared link exposes only the selected task and does not grant workspace navigation.
3. A webhook event can be authenticated and a duplicate event is safely ignored.
4. An attachment is unavailable to unauthorized users and follows the declared scan decision.
5. The analysis clearly defers tenant isolation, deletion propagation, support access, and webhook ownership decisions.
