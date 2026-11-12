# Product Requirements Document

> ID: PRD-HR-005
> Completeness: Complete
> Product type: Simple internal employee leave workflow
> Owner: People Operations
> Release: Internal pilot synthetic sample
> Expected threat-model scope: Leave request, manager approval, HR reporting, audit

## 1. Overview

The internal HR application lets employees request leave, managers approve or reject requests for their direct reports, and HR administrators view reports. The application uses the corporate identity provider. Leave reasons may contain personal or health-related information and should be visible only to people who need them.

This is a deliberately small, well-defined PRD. It tests whether the analysis can avoid producing a large amount of generic output when the DFD and workflow are simple.

## Actors and roles

- **Employee**: creates and views their own leave requests.
- **Manager**: approves or rejects requests for direct reports.
- **HR administrator**: corrects records and produces reports; access is audited.
- **Corporate identity provider**: authenticates employees and returns department/manager claims.

## User journeys

### UC-01 Employee submits leave request

Actor: Employee

Steps:

1. Employee signs in through the corporate identity provider.
2. Employee enters start date, end date, leave type, and optional reason.
3. HR web app sends the request to Leave API.
4. Leave API checks dates and employee entitlement from the HR database.
5. Leave API stores the request with `pending` status.
6. Notification service sends the manager a link to review.

Data: Employee ID, leave dates, leave type, reason, entitlement, manager ID.

Evidence locator: User journeys / UC-01 Employee submits leave request.

### UC-02 Manager approves a request

Actor: Manager

Steps:

1. Manager opens the request link.
2. Leave API verifies that the manager is the requester's current manager.
3. Manager approves or rejects the request with an optional comment.
4. Leave API changes status and writes an audit event.
5. Notification service informs the employee.

Data: Request ID, manager ID, decision, comment, timestamp, audit event.

Evidence locator: User journeys / UC-02 Manager approves a request.

### UC-03 HR administrator corrects a request

Actor: HR administrator

Steps:

1. HR administrator searches by employee and request ID.
2. Leave API verifies the HR administrator role.
3. Administrator changes the date or leave type and provides a reason.
4. Leave API stores the previous value, new value, actor, and reason in the audit log.

Data: Employee ID, request ID, old value, new value, reason, actor, timestamp.

Evidence locator: User journeys / UC-03 HR administrator corrects a request.

## Components and trust boundaries

| Zone | Components | Trust boundary |
| --- | --- | --- |
| Employee device | Browser | Untrusted endpoint |
| Internal application | HR web app, Leave API, Notification service | Corporate application boundary |
| Restricted data | HR database, Audit log | Employee personal data boundary |
| Workforce | Manager view, HR admin view | Role boundary |
| External system | Corporate identity provider | Corporate identity boundary |

## Data flows

| Flow | Source -> destination | Protocol | Data | Evidence |
| --- | --- | --- | --- | --- |
| F-01 | Employee/manager/admin -> HR web app | HTTPS | Forms and review actions | UC-01, UC-02, UC-03 |
| F-02 | HR web app -> Corporate identity provider | OIDC | Login and identity claims | UC-01 |
| F-03 | HR web app -> Leave API | HTTPS | Request and decision | UC-01, UC-02 |
| F-04 | Leave API -> HR database | Private SQL | Leave request and entitlement | UC-01, UC-02 |
| F-05 | Leave API -> Audit log | Append-only API | Change history | UC-02, UC-03 |
| F-06 | Leave API -> Notification service | Internal API | Safe notification content | UC-01, UC-02 |

## Data inventory

| Data | Classification | Store or transit | Protection expectation |
| --- | --- | --- | --- |
| Employee identity and manager relation | Personal/authorization data | HR database | Server-side role checks |
| Leave dates and leave type | Personal HR data | HR database | Employee and authorized manager access |
| Leave reason | Potentially sensitive personal data | HR database | Need-to-know display and redaction in reports |
| Approval and correction audit | HR compliance data | Audit log | Append-only and HR-admin restricted |

## External systems

- Corporate identity provider: authenticates staff and supplies employee and manager claims.

## Functional requirements

1. Employees can read their own requests.
2. Managers can act only on requests for direct reports.
3. HR administrators can correct a request only with a reason.
4. Every approval, rejection, and correction is auditable.
5. Notifications do not include the leave reason.

## Security and privacy requirements

- Enforce employee, manager, and HR administrator authorization at the API.
- Do not trust a manager ID supplied by the browser; resolve it from the identity provider or HR database.
- Mask or omit leave reasons from notifications and aggregate reports.
- Retain audit events even when a leave request is corrected.

## Open questions and assumptions

- Exact retention period for leave reasons and audit events must be confirmed by HR compliance.
- Assumption: the corporate identity provider is the source of truth for employee status.

## Acceptance criteria

1. An employee cannot read another employee's leave request by changing the request ID.
2. A manager cannot approve a request for a non-direct report.
3. An HR correction shows old value, new value, reason, actor, and timestamp.
4. Notifications do not contain the optional leave reason.
