---
title: Intune change-management playbook
layout: default
parent: Intune
---

# Intune change-management playbook

This playbook is for the deployment lead responsible for an Intune onboarding
or baseline review. It covers the customer conversation, assessment, guided
portal work, enrollment pilot, support handoff, and closure record.

The current script is write-capable. A `-WhatIf` run changes nothing, while an
apply run can create applications, policies, assignments, and a report-only
Conditional Access policy. Neither mode replaces customer approval or proves
every guide task is complete.

## Phase 0: scope the deployment

Complete this before authenticating to the tenant.

| Action | Owner | Required output |
| --- | --- | --- |
| Confirm tenant and licensing. | Deployment lead | Expected tenant, Business Premium or Intune Plan 1 scope, and Entra licensing for later Conditional Access. |
| Select supported platforms and ownership models. | Customer IT owner | Company-owned, personal, or mixed decision for Windows, Android, Apple, and macOS. |
| Decide MDM, MAM, or both for personal devices. | Security and privacy owners | Data-protection and enrollment approach for each platform. |
| Select pilot users and representative devices. | Customer IT owner | Pilot group, device matrix, exclusions, and success measures. |
| Name external identity owners. | Customer IT owner | Apple certificate owner and at least two appropriate Google enterprise owners. |
| Identify emergency-access accounts. | Identity owner | Tested accounts excluded from any later Conditional Access policy. |
| Select evidence and support locations. | Deployment lead | Private report location, change record, support queue, and escalation contacts. |
| Agree rollback and stop conditions. | Change approver | Recovery owner and criteria that stop expansion. |

Do not put tenant IDs, UPNs, group IDs, Apple IDs, screenshots, or approval
records in the repository.

Use [pilot group setup](Operator-Guide.md#prepare-a-pilot-group) to create the
assigned security group and locate its object ID. Follow the
[object-specific recovery checklist](Evidence-Troubleshooting.md#recover-a-partial-pilot-deployment)
when recording before-state and stop conditions.

## Phase 1: prepare the workstation

1. Use PowerShell 7 in a normal interactive desktop session.
2. Install the documented Microsoft Graph modules for the current user, or plan
   to pass `-AutoInstallModules` so the toolkit installs a missing module
   without a prompt.
3. Close unrelated PowerShell sessions that may hold a stale Graph context.
4. Confirm the intended administrator account and expected tenant.
5. Create the private evidence location before the run.
6. Review the eleven configured delegated scopes (six read, five write) in the
   [configuration reference](Configuration-Reference.md). The orchestrator
   requests all eleven at connect time for every run; the five write scopes are
   consented ahead of their write paths, which remain gated separately.
7. For a GDAP-delegated administration of a separate customer tenant, plan to
   pass `-DelegatedOrganization` with the customer's verified domain.

The deployment team enters credentials only in the Microsoft sign-in
experience. Do not capture a password in a script, transcript, issue, or chat.

## Phase 2: preview the intended deployment

```powershell
cd Products/Intune
./Deploy-IntuneBestPractice.ps1 `
  -TenantAdminUpn admin@contoso.onmicrosoft.com `
  -PilotGroupId '<entra-group-object-id>' `
  -WhatIf
```

After sign-in:

1. Confirm the displayed tenant before continuing.
2. Allow the supported assessments and write previews to finish.
3. Open `Reports/intune-run-report.html` locally.
4. Confirm no outcome is `Created`, `Updated`, or `Adopted`.
5. Treat every `Failed` module as unresolved.
6. Confirm every `WillChange` target, assignment, and safety gate matches the
   approved pilot.
7. Record each guided task with an owner and target date.
8. Move reports to the approved private location.

The generated reports are tenant evidence. Do not commit them.

## Phase 3: apply the supported pilot baseline

The standard apply creates Microsoft 365 Apps and the Android/iOS app
protection policies. High-risk changes require the category switches and
customer approval in the operator guide's
[separate stage commands](Operator-Guide.md#add-high-risk-changes-one-at-a-time).
Default compliance changes the entire tenant, regardless of the pilot group;
it requires its own tenant-wide impact review.

After the run:

1. Review every `Created`, `Updated`, and assignment entry.
2. Confirm supported readback is `Verified`; verify app-protection targeting
   and assignment in the portal.
3. Confirm the pilot group, not a wider audience, received the assignment.
4. Stop if a partial failure created an object without its intended assignment.
5. Rerun with the same parameters and confirm the result is idempotent.
6. Move the apply and rerun reports to the approved private location.

Do not combine the first high-risk apply with Conditional Access promotion.

## Phase 4: verify portal and device state

Portal navigation can change. Use the linked Microsoft Learn page when a label
has moved.

| Assessment | Portal verification | Result to compare |
| --- | --- | --- |
| Apple certificate | **Devices > Device onboarding > Enrollment > Apple > Apple MDM Push Certificate** | Active state and renewal date. |
| Default compliance | **Devices > Manage devices > Compliance > Compliance settings** or **Endpoint security > Device compliance > Compliance policy settings** | Treatment of devices without an assigned compliance policy. |
| Enrollment restrictions | **Devices > Device onboarding > Enrollment > Enrollment options > Device platform restriction** | Supported platforms, personal-device rules, priority, and assignments. |
| App protection | **Apps > Manage apps > Protection** | Android and iOS/iPadOS policy presence and assignment scope. |
| Device compliance | **Devices > Manage devices > Compliance > Policies** or **Endpoint security > Device compliance > Policies** | Platform policy presence, assignments, and actions for noncompliance. |

If the report and portal do not agree, retain sanitized diagnostics, stop the
rollout, and investigate before changing the tenant again.

## Phase 5: complete one guided change at a time

Use this cycle for a separately approved portal action:

1. Identify the exact guide task and Microsoft Learn procedure.
2. Record current state without exporting unnecessary customer data.
3. Confirm approval, pilot scope, owner, maintenance window, and recovery.
4. Apply only the approved change in the portal.
5. Verify portal readback and, where relevant, device receipt.
6. Stop if the result differs from the approved intent.
7. Rerun the toolkit when it has a supported read for that task.
8. Record the outcome and remaining exceptions in the customer change record.

Do not batch enrollment restrictions, compliance policy, and Conditional
Access into one change. Separate changes make impact and recovery observable.

## Phase 6: enroll and observe a pilot

| Check | Evidence |
| --- | --- |
| User can start and finish enrollment. | Enrollment timestamp and supported device method. |
| Device appears in the expected tenant and ownership class. | Portal readback retained privately. |
| Required applications arrive. | Device-side confirmation. |
| Platform policy arrives. | Intune device status and device-side result. |
| Expected compliance issues are understandable and remediable. | Support case or pilot feedback record. |
| Emergency-access accounts remain usable. | Identity-owner confirmation before any access enforcement. |
| Support team can route failures. | Named queue, owner, and escalation path. |

Use representative devices. One successful Windows enrollment does not prove
Android, Apple, or macOS readiness.

## Phase 7: make the access decision separately

Conditional Access is not a day-zero enrollment setting. The toolkit can
create the enrollment policy report-only after every high-risk gate is
supplied. Run that path only after the selected platform policies reach pilot
devices and compliance results are stable.

Before enforcement, require:

- approved pilot users and explicit exclusions;
- verified emergency-access accounts whose object IDs were supplied through
  `-BreakGlassUserIds` or `-BreakGlassGroupIds`;
- the correct Microsoft Intune Enrollment target resource;
- MFA and compliant-device grant controls reviewed together;
- report-only sign-in evidence;
- propagation time and helpdesk readiness;
- a tested disable or exclusion recovery path; and
- a named human approval record.

The toolkit does not promote the policy to enforcement by default.

## Closure checklist

- [ ] Every supported platform has an owner and current disposition.
- [ ] Every failed assessment is resolved or explicitly blocks closure.
- [ ] Every selected write has supported readback or documented portal/device
      verification, plus an idempotent rerun.
- [ ] Guided tasks have portal evidence, an owner, and a review date.
- [ ] Pilot enrollment and device-side policy receipt are recorded.
- [ ] Support ownership and user communications are active.
- [ ] Reports are stored privately and absent from source control.
- [ ] Remaining risks and deferred platforms have named owners.
- [ ] Any later enforcement decision is recorded separately.

For user communications, use the
[end-user adoption guide](End-User-Adoption-Guide.md). For technical failures,
use [evidence and troubleshooting](Evidence-Troubleshooting.md).