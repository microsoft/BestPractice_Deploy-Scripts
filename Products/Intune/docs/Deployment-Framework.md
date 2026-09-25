---
title: Intune deployment framework
layout: default
parent: Intune
---

# Intune deployment framework

The Intune baseline is a sequence, not a collection of independent settings.
Enrollment prerequisites must exist before devices enroll. Platform policies
must reach pilot devices before compliance is used for access. Conditional
Access belongs at the end, after enrollment and compliance are proven.

The current toolkit automates assessment plus six supported write paths. Guided
portal changes, device enrollment, Conditional Access promotion, and broader
assignment remain separate customer-approved work.

## The safe sequence

| Stage | Purpose | Current toolkit role | Exit evidence |
| --- | --- | --- | --- |
| 0. Decide | Select supported platforms, ownership model, pilot users, support owner, and evidence location. | Documents scope and validates local configuration. | Approved scope and named owners. |
| 1. Preview | Establish tenant identity, licensing, five assessments, six planned writes, and remaining guided boundaries. | Runs assessments under `-WhatIf`, records `WillChange`, and writes HTML and JSON reports. | No failed reads, no blocked prerequisite, and no applied tenant write. |
| 2. Prepare enrollment | Complete Windows, Apple, and Android prerequisites under change control. | Reads Apple certificate health; guides other work. | Portal evidence for each supported platform. |
| 3. Apply pilot policy | Configure Microsoft 365 Apps, app protection, default compliance, enrollment restrictions, and per-platform compliance for the approved pilot. | Applies the supported standard and high-risk paths; Windows backup remains guided. | Supported readback, portal or device verification, assignment proof, idempotent rerun, and recovery owner. |
| 4. Enroll a pilot | Enroll representative devices and confirm applications, policy check-in, and support readiness. | Does not enroll devices. | Successful enrollment and device-side validation. |
| 5. Observe compliance | Confirm devices receive policy and resolve expected noncompliance before access enforcement. | Reruns assessment and verifies the applied objects. | Stable compliant-device population and exception list. |
| 6. Protect access | Create the enrollment Conditional Access policy report-only, then make a separate enforcement decision. | Creates and reads back the policy only after every high-risk gate and at least one emergency-access exclusion ID are supplied. | Report-only review, exclusion proof, approval, and tested rollback. |

Do not skip from Stage 1 to Stage 6. Requiring a compliant device before a
pilot device can enroll, receive policy, and become compliant can deny access
and block the enrollment process the baseline is meant to protect.

## Decision flow for each guide task

1. **Can the current script assess or apply the task?** Review the task
   disposition in
   [scenarios and capabilities](Scenarios.md).
2. **Did the assessment succeed?** Resolve `Failed` outcomes before relying on
   the report.
3. **Is the task guided or blocked?** Follow the official source and the
   [device enrollment deployment guide](Device-Enrollment-Deployment-Guide.md).
4. **Would the action change tenant or device behavior?** Require customer
   approval, a pilot group, before-state evidence, and a recovery plan.
5. **Can the result be verified?** Capture portal and device-side readback.
6. **Did the result match intent?** Rerun the toolkit where it has a supported
   read, record guided closure elsewhere, and retain evidence privately.

## Safety gates

| Gate | Protects against | Required decision |
| --- | --- | --- |
| Expected tenant identity | Cross-tenant work | Confirm tenant before any assessment or portal action. |
| Least-privilege delegated scopes | Excess consent | Use only the eleven scopes documented in the configuration reference; write scopes are used only after applicability, `ShouldProcess`, assignment, and high-risk gates. |
| Pilot group | Tenant-wide user or device impact | Use representative users and devices before broader assignment. |
| Customer approval | Unowned risk | Record who approved the change and its scope. |
| Emergency-access exclusions | Administrator lockout | Test excluded accounts before Conditional Access enforcement. |
| Readback | False success | Verify portal state and device receipt after a change. |
| Recovery plan | Extended outage | Define how to remove assignment, restore state, or stop rollout. |

`-WhatIf` previews the active write paths without changing the tenant. It does
not convert `-EnablePolicyCatalogWrite` into an approved capability; that
reserved switch continues to refuse the run.

## Evidence flow

The toolkit creates three local artifacts under `Products/Intune/Reports/`:

- `intune-run-report.html`, the operator summary.
- `intune-run-log.json`, the structured action record.
- `intune-applicability.json`, the task applicability record.

Move tenant reports to the approved private customer location. Do not commit
them, attach them to a public issue, or paste raw contents into an AI prompt.
The repository may contain only sanitized validation conclusions.

## First-party references

- [Device management and application management in Microsoft 365 Business Premium](https://learn.microsoft.com/microsoft-365/admin/security-and-compliance/m365bp-devices-enrollment)
- [Microsoft Intune enrollment guide](https://learn.microsoft.com/intune/device-enrollment/guide)
- [Microsoft Intune planning guide](https://learn.microsoft.com/intune/fundamentals/planning-guide)
- [Microsoft Intune setup deployment guide](https://learn.microsoft.com/intune/fundamentals/setup-migration)

These pages remain the product authority. The toolkit narrows their rollout to
a pilot-first sequence and blocks automation where supportability or recovery
is not established.