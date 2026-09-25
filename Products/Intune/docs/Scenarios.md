---
title: Intune scenarios and capabilities
layout: default
parent: Intune
---

# Intune scenarios and capabilities

This page explains what the Intune toolkit can establish today, what still
requires an administrator in a portal, and what is deliberately blocked. It is
for deployment teams, security reviewers, support teams, and customer IT
owners. No PowerShell knowledge is required.

The current `0.3.0` release is **write-capable and pilot-first**. It always
assesses the supported tenant state, can apply six approved baseline tasks, and
records each planned or completed action in local reports. Guided and blocked
tasks remain explicit.

For commands and prerequisites, use the [operator guide](Operator-Guide.md).
For portal procedures, use the
[device enrollment deployment guide](Device-Enrollment-Deployment-Guide.md).

## At a glance

| Guide task | Current capability | What the script establishes | Operator action |
| --- | --- | --- | --- |
| 1. Windows automatic MDM enrollment | Guided only | Records why no approved GA write and readback path is used. | Verify the MDM user scope in the Intune admin center. |
| 2. Apple MDM push certificate | Automated read-only assessment | Reads certificate health and warns within the configured renewal window. | Verify, create, or renew the certificate through Intune and Apple when guided. |
| 3. Managed Google Play connection | Guided only | Records the interactive ownership and verification requirements. | Complete customer-owned Google consent and verify the required managed apps. |
| 4. Default compliance setting | Assessment plus gated write | Reads effective `secureByDefault`; with the high-risk category gate, sets it to true and verifies readback. | Apply only after pilot compliance policies and access impact are understood. |
| 5. Enrollment restrictions | Inventory plus gated write | Reads current restrictions; with the high-risk category gate, creates and assigns the configured Android and iOS/iPadOS restrictions. | Confirm supported platforms, ownership policy, and pilot scope. |
| 6. App protection policies | Assessment plus standard write | Reads Android and iOS/iPadOS policies, then creates the Level 1 baseline, targets core apps, and assigns the selected scope. | Review each platform and validate app behavior with pilot users. |
| 7. Device compliance policies | Inventory plus high-risk write | Reads supported policy types; with `-IncludeHighRisk`, creates the approved per-platform payloads and assigns the selected scope. | Confirm device receipt and expected noncompliance before access enforcement. |
| 8. Microsoft 365 Apps | Standard write | Creates the configured Microsoft 365 Apps deployment and assigns the selected scope through the validated beta resource. | Confirm installation status, architecture, channel, and licensing. |
| 9. Windows Backup for Organizations | Guided only | Records that the former Enterprise State Roaming workflow moved to current Windows backup policy management. | Follow current Microsoft administration guidance for the Windows estate. |
| 10. Conditional Access for enrollment | Gated report-only write | Ensures the enrollment service principal exists and creates the policy report-only after every high-risk gate and at least one emergency-access exclusion ID are supplied. | Verify exclusions, sign-in results, device compliance, and rollback before promotion. |

## What a successful run means

A successful preview means the toolkit connected to the expected tenant,
completed the supported reads, recorded planned writes and guided boundaries,
and produced its reports without changing tenant state. A successful apply
also means each selected write completed and its readback matched. Neither
result is a compliance certification. App-protection targeting and assignment
require portal verification because that module records the write operations
but does not emit a complete post-write readback projection.

The HTML report is the operator summary. The JSON sidecar is the structured
evidence record. Review every module outcome:

| Outcome | Meaning |
| --- | --- |
| `AlreadyCompliant` | The narrow implemented check proved the reported state. |
| `GuidedOnly` | A portal step, external identity, unsupported API, incomplete comparison, or unapproved write remains. |
| `Skipped` | The item was not applicable or an explicit run choice omitted it. |
| `Blocked` | A safety prerequisite refused the operation. Do not bypass it. |
| `Failed` | The toolkit could not establish trustworthy state. Correct the failure before relying on the report. |

A `-WhatIf` run must not contain a tenant action with status `Created`,
`Updated`, or `Adopted`. An apply run can contain those statuses only for the
approved task and assignment scope.

## Priority 1: establish enrollment prerequisites

### Windows automatic enrollment

The toolkit records this as guided because the current product has no approved
GA write and readback operation. The administrator verifies the MDM user scope
under **Devices > Device onboarding > Enrollment > Windows > Automatic
Enrollment**.

Use an approved pilot user group before broader enrollment. Keep the deprecated
Windows Information Protection user scope set to `None`.

### Apple MDM push certificate

The toolkit reads the certificate singleton and reports validity and renewal
timing without retaining the Apple ID or certificate material. A `404` response
is not treated as proof that no certificate exists because Microsoft does not
document that meaning. The operator must verify the Apple MDM Push Certificate
page when the result is guided.

Apple sign-in, certificate creation, upload, and annual ownership remain human
steps. Use a customer-owned Apple ID and record a renewal owner.

### Managed Google Play

Connecting Managed Google Play binds a customer-controlled Google account to
the tenant through an interactive browser flow. The toolkit does not automate
that flow or the destructive disconnect action.

After connection, verify Microsoft Intune, Microsoft Authenticator, Intune
Company Portal, and Managed Home Screen in managed Google Play. Record at least
two appropriate Google enterprise owners for continuity.

### Default compliance setting

The toolkit reads whether devices without an assigned compliance policy are
treated as noncompliant. A nullable or missing Graph projection is reported as
unknown and guided, not normalized to false or guessed from the documented
service default. The toolkit does not write when the current state is unknown.

This setting becomes access-impacting when Conditional Access requires a
compliant device. The toolkit changes it only with
`-IncludeHighRisk -EnableComplianceEnforcement` and a customer approval ID.
Do not select that path until enrolled devices receive the intended platform
policies and the deployment team has approved the impact.

## Priority 2: establish platform policy

### Enrollment restrictions

The toolkit inventories existing platform restrictions, assignments, and
selected normalized block signals. It does not decide which platforms the
customer supports and does not compare an approved desired policy.

The deployment team must decide whether personally owned enrollment is
allowed, which operating-system versions are supported, and whether
manufacturer restrictions are appropriate. With the documented high-risk
gates, the toolkit creates the configured personal-enrollment restrictions and
assigns them to the selected scope.

### App protection policies

Android and iOS/iPadOS are assessed separately. The toolkit reports normalized
policy and assignment counts plus target-app readback availability. It excludes
policy names, IDs, group IDs, settings, and raw responses from evidence.

The module creates the configured Android and iOS/iPadOS Level 1 policies,
targets the core Microsoft apps, and assigns the selected scope. Modern Windows
MAM remains outside the supported path. The imported policy catalog is
candidate input only, and `-EnablePolicyCatalogWrite` refuses the run.

### Device compliance policies

The toolkit inventories supported policy types and assignments. If the
documented `scheduledActionsForRule` relationship returns the known fixed-route
`400`, it records the action count as unavailable and continues the remaining
inventory. Unknown is never reported as zero.

With `-IncludeHighRisk`, the toolkit creates and assigns the approved
per-platform payloads. A broad compliance policy can affect access immediately
when a customer already enforces device compliance through Conditional Access,
so pilot scope is required by default.

### Microsoft 365 Apps

The toolkit creates the configured `officeSuiteApp`, assigns the selected
scope, and reads back its display name and update channel through the validated
beta path. Review installation status in Intune and on pilot devices.

### Windows Backup for Organizations

The source guide's Enterprise State Roaming task moved to Windows Backup for
Organizations policy management. The toolkit records the transition and keeps
the task guided while policy payload, assignment, readback, migration, and
recovery behavior remain unverified.

## Priority 3: protect enrollment access

Conditional Access is the highest-risk task. It can deny enrollment and lock
administrators out when it is enabled before devices enroll and become
compliant. The current module runs only after every documented gate is
supplied and creates the policy report-only by default.

The policy targets Microsoft Intune Enrollment and requires MFA plus a
compliant device. The module writes the supplied `-BreakGlassUserIds` and
`-BreakGlassGroupIds` values into the policy exclusions. Before promotion,
verify those exclusions in the portal, review report-only sign-in evidence,
confirm device compliance, allow for propagation, and retain the tested
disable or exclusion recovery.

## Deliberate differences from the source guide

The source guide often assigns settings to all users. This toolkit uses a
pilot-first contract because enrollment restrictions, compliance, and
Conditional Access can deny access. Tenant-wide assignment is never the safe
default.

The toolkit also refuses beta-only or ambiguous automation, does not infer
supportability from a successful mock, and does not adopt an unmanaged object
because its display name happens to match.

## Finish a tenant assessment

1. Run the toolkit with `-WhatIf` and the intended assignment and gate
   parameters.
2. Review the HTML and JSON reports in the approved private evidence location.
3. Resolve failed reads or blocked gates before applying.
4. Apply the standard or approved high-risk pilot scope.
5. Verify `Created` or `Updated` entries, supported readback, portal or device
   receipt, and idempotent rerun.
6. Complete guided portal checks under customer change control.
7. Retain before and after evidence outside the repository.
6. Rerun the assessment and compare the new report.
7. Record unresolved guided or blocked items with an owner and review date.

See [evidence and troubleshooting](Evidence-Troubleshooting.md) for recovery
and [future write capabilities](Future-Write-Capabilities.md) for the evidence
required before any tenant-changing operation can be implemented.