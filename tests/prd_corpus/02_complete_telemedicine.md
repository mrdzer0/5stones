# Product Requirements Document

> ID: PRD-TM-002
> Completeness: Complete
> Product type: Telemedicine web and mobile application
> Owner: Care Experience Team
> Release: Q1 synthetic sample
> Expected threat-model scope: Appointment booking, video consultation, clinical record, prescription, payment

## 1. Overview

The telemedicine product lets patients book a consultation, upload a short symptom description, join a video appointment, and receive a prescription. Clinicians can view the minimum patient context needed for a scheduled consultation. Care coordinators manage appointment exceptions but cannot read full clinical notes unless assigned to the case.

Health information is treated as restricted. The application uses a separate clinical record store and a short-lived video session token. A video provider receives only the room token and media streams required for the appointment. Payment is handled by a hosted payment page so the product does not store card numbers.

## Actors and roles

- **Patient**: books appointments, gives consent, joins a consultation, and views their own records.
- **Clinician**: reads assigned patient context, writes consultation notes, and issues a prescription.
- **Care coordinator**: schedules appointments and contacts patients; cannot edit clinical notes.
- **Clinical administrator**: manages clinician assignment and access reviews.
- **Video provider**: hosts the encrypted media session using a short-lived room token.
- **Payment provider**: hosts checkout and returns a payment confirmation.
- **Notification provider**: sends appointment reminders without including clinical content.

## User journeys

### UC-01 Patient books a consultation

Actor: Patient

Trigger: Patient selects a specialty and time slot.

Steps:

1. Patient submits specialty, preferred time, symptom summary, and consent choice in the patient app.
2. Scheduling service checks slot availability and creates a provisional appointment.
3. Payment service redirects the patient to the hosted Payment provider.
4. Payment provider returns a payment confirmation reference.
5. Scheduling service commits the appointment and stores the consent record.
6. Notification service sends a reminder containing time, clinician display name, and a link without clinical details.

Data: Symptom summary, consent choice, appointment, payment reference, clinician display name.

Evidence locator: User journeys / UC-01 Patient books a consultation.

### UC-02 Patient joins a video consultation

Actor: Patient

Trigger: Patient selects `Join consultation` during the appointment window.

Preconditions: Appointment is paid, patient consent is present, and the clinician is assigned.

Steps:

1. Patient app requests a join token from Consultation service.
2. Consultation service checks appointment ownership and time window.
3. Consultation service issues a short-lived room token scoped to one appointment.
4. Patient app and clinician console use the token to join the Video provider room.
5. Consultation service records join and leave events without recording raw video.

Data: Appointment ID, patient identity, clinician identity, room token, join events.

Evidence locator: User journeys / UC-02 Patient joins a video consultation.

### UC-03 Clinician reviews and updates clinical record

Actor: Clinician

Trigger: Clinician opens an assigned consultation.

Steps:

1. Clinician console requests assigned patient context from Clinical record service.
2. Clinical record service checks clinician assignment and purpose of use.
3. Clinician reads allergies, relevant history, and current symptom summary.
4. Clinician writes consultation notes and, if needed, a prescription.
5. Clinical record service stores a versioned record and an access audit event.
6. Notification service tells the patient that a new record is available without including its content.

Data: Allergies, medical history, symptom summary, consultation notes, prescription, audit event.

Evidence locator: User journeys / UC-03 Clinician reviews and updates clinical record.

### UC-04 Care coordinator reschedules an appointment

Actor: Care coordinator

Trigger: Patient requests a schedule change.

Steps:

1. Coordinator searches by appointment reference, not free-text clinical detail.
2. Scheduling service verifies coordinator role and returns minimum scheduling context.
3. Coordinator selects a new slot.
4. Scheduling service records the change and writes the old and new times to the audit log.
5. Notification service sends the new appointment time to the patient.

Data: Appointment reference, patient contact channel, old slot, new slot, actor, timestamp.

Evidence locator: User journeys / UC-04 Care coordinator reschedules an appointment.

## Components and trust boundaries

| Zone | Components | Trust boundary |
| --- | --- | --- |
| Patient device | Patient mobile/web app | Untrusted endpoint |
| Public-facing | API gateway, WAF, rate limiter | Internet boundary |
| Internal application | Scheduling service, Consultation service, Clinical record service, Notification service | Organization application boundary |
| Restricted data | Clinical record store, Consent store, Audit store | PHI and compliance boundary |
| Workforce | Clinician console, Coordinator console, Admin console | Privileged workforce boundary |
| External systems | Video provider, Payment provider, Notification provider | Third-party boundary |

## Data flows

| Flow | Source -> destination | Protocol | Data | Evidence |
| --- | --- | --- | --- | --- |
| F-01 | Patient -> Patient app | HTTPS | Booking and symptom form | UC-01 |
| F-02 | Patient app -> API gateway -> Scheduling service | HTTPS / mTLS | Appointment request | UC-01 |
| F-03 | Scheduling service -> Payment provider | Hosted redirect / HTTPS | Payment session | UC-01 |
| F-04 | Payment provider -> Scheduling service | HTTPS webhook | Payment confirmation reference | UC-01 |
| F-05 | Patient app -> Consultation service | HTTPS | Appointment ID and identity | UC-02 |
| F-06 | Consultation service -> Video provider | HTTPS | Room token, appointment scope | UC-02 |
| F-07 | Clinician console -> Clinical record service | HTTPS | Assigned patient context | UC-03 |
| F-08 | Clinical record service -> Clinical record store | Private database | Notes, prescriptions, history | UC-03 |
| F-09 | Scheduling service -> Notification provider | HTTPS | Time and safe reminder content | UC-01, UC-04 |
| F-10 | Clinical record service -> Audit store | Append-only API | Access and change events | UC-03 |

## Data inventory

| Data | Classification | Store or transit | Protection expectation |
| --- | --- | --- | --- |
| Symptom summary and medical history | Restricted PHI | Clinical record store | Purpose-limited access and encryption |
| Consultation notes and prescription | Restricted PHI | Clinical record store | Versioned, audited, clinician-only write |
| Consent record | Restricted compliance data | Consent store | Immutable history and patient visibility |
| Video room token | Secret | Short-lived transit | Appointment-scoped and expiring |
| Payment reference | Confidential | Scheduling service | No card number in product systems |
| Reminder message | Limited personal data | Notification provider | No diagnosis or clinical content |

## External systems

- Video provider: receives a short-lived room token and media session traffic; does not receive the full clinical record.
- Payment provider: hosts payment collection and returns a reference; card data remains with the provider.
- Notification provider: receives appointment timing and a safe message template.

## Functional requirements

1. A clinician may read or write records only for assigned appointments or an explicitly delegated case.
2. A coordinator can reschedule but cannot read clinical notes or prescriptions.
3. Video tokens expire after the appointment window and cannot join another appointment.
4. Patient consent and withdrawal are versioned and linked to the appointment.
5. A clinical record update creates a new version and an audit event.
6. Reminder messages must not disclose diagnosis, symptom, prescription, or clinical note content.

## Security and privacy requirements

- Enforce purpose-based access for clinical record reads.
- Require step-up authentication for clinician and administrator actions.
- Log every clinical record access with actor, patient, appointment, purpose, and outcome.
- Encrypt PHI at rest and in transit; keys are managed outside application data stores.
- Prevent patient identifiers from appearing in video room names or URLs.
- Verify payment and appointment webhooks with an authenticated channel and replay protection.
- Provide patient access and correction workflow without exposing another person's record.

## Open questions and assumptions

- The exact jurisdictional retention period for clinical notes and audit records must be confirmed.
- The Video provider's media retention and support-access policy must be reviewed.
- Break-glass access for emergencies needs a named approver and post-event review.
- Assumption: raw video is not recorded by the product.

## Acceptance criteria

1. A patient cannot join another patient's consultation by changing an appointment ID.
2. A clinician cannot open an unassigned clinical record through the console or API.
3. A coordinator can reschedule an appointment without seeing clinical notes.
4. A video room token expires and is unusable outside its appointment scope.
5. Clinical record reads and updates are traceable to an actor and purpose.
6. Notifications and payment callbacks contain no unneeded health or card data.
