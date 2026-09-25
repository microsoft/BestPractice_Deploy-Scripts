---
title: Defender evidence and reports
parent: Microsoft Defender
nav_order: 3
---

# Evidence and reports

Each run writes a redacted JSON sidecar and HTML report under
`Products\Defender\Reports\`. Entries include module, action, status,
disposition, best-practice key, HTTP status when available, retry metadata,
and readback status.

Retry entries include the HTTP status when available and identify when a
message-only cmdlet signature classified an EXO, IPPS, or SPO failure as
transient. The bounded retry decision is recorded before the next attempt;
deterministic authorization, validation, duplicate, and semantic failures are
not retried.

Reports also include a module summary with one verdict per module: `OK`,
`FAILED`, `SKIPPED`, or `BLOCKED`. The JSON sidecar and HTML report use the
same verdict calculation, with failures taking precedence over blocked,
skipped, or successful entries. `GuidedOnly` entries are reported as
`SKIPPED`; an explicit blocked disposition is reported as `BLOCKED`.

The human-readable report uses the configured friendly recommendation name,
not the internal best-practice key. Internal keys may remain in the JSON
sidecar for machine correlation, but are not presented as operator-facing
labels. Each configured-item summary correlates that key with the terminal
module outcome so compliant, blocked, guided-only, and skipped results are not
replaced by an unattributed fallback.

The report is an operational record, not proof that a tenant policy was
changed. A `GuidedOnly` or `Skipped` disposition must be followed using the
continuation command recorded in the detail field.

Quarantine policy evidence records collection discovery and exact-name
selection, the planned or applied disposition, collision or refusal result, and post-create comparison of
the selected permission and notification fields. It also states that no
protection-policy assignments were changed. Adoption and updates of existing
quarantine policies are refused, so evidence for those cases records a blocked
disposition with the reason. Evidence cannot show whether a quarantine policy
has been assigned to a protection policy because the module does not read
assignments. The create-only boundary prevents that missing information from
reaching an update. Evidence also records whether the selected permission plan
authorized the apply operation. When the quarantine slice fails, the
Safe Attachments and outbound auto-forwarding entries are still recorded before
the run reports the quarantine failure.

Do not commit reports, tenant identifiers, access tokens, customer data, or
pilot evidence. Store pilot evidence in the approved private validation
location.

## Reviewer access to validation evidence

Each pilot or retrospective validation record must have a stable evidence ID.
Add the ID, date, scope, classification, and sanitized disposition to the
Defender validation register and reference the protected evidence location from
the pull request or release-readiness record. Reviewers who need to inspect the
record must be granted access to that protected location through the approved
sharing process; do not attach the record to GitHub or copy it into a
non-public repository directory. The PR or release record is the discoverability
index, while the protected location is the evidence source of truth.

For a retrospective record, label it `Retrospective / contributor-reported` and
state whether the underlying command output or notes are retained. A
repository-level summary is not a substitute for reviewer access to the
evidence source.
