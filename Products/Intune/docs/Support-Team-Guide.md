---
title: Intune support-team guide
layout: default
parent: Intune
---

# Intune support-team guide

This guide is for service desk, endpoint operations, and identity support teams
who receive questions during an Intune onboarding. It explains what the current
toolkit does, what a later approved rollout can change for users, and how to
route common failures.

## What changes when the current script runs

A `-WhatIf` run connects to Microsoft Graph, reads selected tenant settings,
previews the supported writes, and writes local reports. It changes no tenant
state.

An approved apply can:

- create and assign Microsoft 365 Apps;
- create, target, and assign Android and iOS/iPadOS app protection;
- set the default compliance behavior;
- create and assign enrollment restrictions;
- create and assign the approved device compliance policies; and
- create the enrollment Conditional Access policy report-only.

The toolkit does **not**:

- enroll or retire a device;
- remove an application;
- promote Conditional Access to enforcement by default;
- upload or renew an Apple certificate; or
- connect or disconnect Managed Google Play.

Users should see no device or sign-in change because a preview ran. After an
apply, compare the symptom with the selected modules, pilot scope, and change
record before attributing it to the toolkit.

## What the deployment team receives

| Artifact | Purpose | Handling |
| --- | --- | --- |
| `intune-run-report.html` | Human-readable task and module summary. | Store in the approved private customer location. |
| `intune-run-log.json` | Structured action and disposition evidence. | Restrict to the deployment and review teams. |
| `intune-applicability.json` | License and task applicability record. | Keep with the run evidence. |

These files are tenant evidence. Do not attach raw reports to a public ticket
or paste them into chat. Use sanitized fields when escalating.

## What users can experience after later approved changes

| Change | Typical user experience | Support readiness |
| --- | --- | --- |
| Automatic enrollment scope | Windows may prompt or enroll when the user adds a work account or joins the organization. | Confirm supported enrollment method and ownership. |
| Apple certificate setup or renewal | Apple devices can enroll and continue receiving management commands. | Track annual renewal ownership and the Apple account used. |
| Managed Google Play connection | Android Enterprise enrollment and managed Android applications become available. | Confirm Google enterprise ownership and required managed applications. |
| Enrollment restrictions | A device can be refused because of platform, OS version, manufacturer, ownership, or device limit. | Know the assigned restriction, its priority, and approved exceptions. |
| App protection policy | A managed app can require a PIN or restrict organization-data movement and saving. | Confirm the user's platform, app, account, and policy assignment. |
| Device compliance policy | Company Portal can report settings the user must remediate. | Provide approved remediation steps and allow for device check-in. |
| Microsoft 365 Apps deployment | Applications install after assignment and device synchronization. | Confirm assignment, licensing, architecture, and installation status. |
| Windows backup policy | Supported Windows settings and backup behavior can change. | Route to the Windows platform owner. |
| Conditional Access | Sign-in or enrollment can require MFA and a compliant device. | Confirm report-only review, the written emergency-access exclusions, and ownership before enforcement. |

## Triage by symptom

### A device cannot begin enrollment

Check, in order:

1. The user has the expected Intune license.
2. Intune is the tenant's MDM authority.
3. The device platform and operating-system version are supported.
4. The user is in the intended automatic-enrollment or pilot scope.
5. Enrollment restrictions allow the platform and ownership type.
6. The user has not reached the device enrollment limit.
7. Platform prerequisites are complete: Apple certificate, Managed Google Play,
   or the selected Windows enrollment method.

Do not broaden a restriction or assign all users as a troubleshooting shortcut.

### Apple enrollment fails

Check the Apple MDM push certificate under **Devices > Device onboarding >
Enrollment > Apple > Apple MDM Push Certificate**. Confirm it is active and
that renewal used the same Apple account and certificate identity.

An assessment `404` is not proof that no certificate exists. Verify the portal
before starting certificate setup or renewal.

### Android Enterprise enrollment fails

Confirm the Managed Google Play connection is healthy and customer-owned, the
required managed applications are present, and the selected Android Enterprise
enrollment method matches the device ownership model.

Do not disconnect Managed Google Play for troubleshooting. Microsoft documents
disconnect as destructive to Android Enterprise management.

### Company Portal reports no compliance policy

Confirm whether the user and device should receive a platform compliance
policy. Review assignment, exclusions, filters, device ownership, and last
check-in. The tenant-wide setting for devices without a policy can report the
device as compliant or noncompliant, but it does not substitute for assigning
the intended platform policy.

### A device is noncompliant

Identify the exact failed setting and policy. Confirm the device checked in
after the latest change and that the user has an approved remediation path.
Do not tell the user to remove management, factory reset, or bypass security
controls unless the platform owner approved that recovery.

### A managed application is missing

Confirm the application assignment, user or device target, licensing,
architecture, platform, network access, and device synchronization. An app
protection policy protects organization data inside an application; it does
not install that application.

### A user is blocked during sign-in or enrollment

Capture the sign-in timestamp and correlation details through the approved
support process. Check Conditional Access results, target resource, user and
group scope, exclusions, authentication requirement, device registration, and
current compliance state.

Treat administrator lockout or an unavailable emergency-access account as an
incident. Use the named identity escalation owner and approved policy disable
or exclusion procedure.

## Safe escalation record

Include:

- UTC timestamp and support case number;
- product version and module or guide task;
- device platform, operating-system version, and ownership class;
- enrollment method or affected managed application;
- sanitized error code, correlation ID, and policy category;
- last successful device check-in when relevant;
- whether the impact affects one user, a pilot group, or a wider scope;
- expected result and last approved change; and
- current recovery owner.

Do not include credentials, tokens, certificate material, raw tenant exports,
full report files, device serial numbers, personal data, or unnecessary user
identifiers.

## Ownership map

| Issue | First owner | Escalate to |
| --- | --- | --- |
| Script, report, or deterministic assessment failure | Deployment team | Toolkit maintainer with sanitized evidence. |
| License, Intune RBAC, Entra role, or GDAP boundary | Tenant access owner | Security and permissions reviewer. |
| Apple certificate or Apple enrollment | Apple platform owner | Customer Apple identity owner. |
| Android Enterprise or Managed Google Play | Android platform owner | Customer Google enterprise owner. |
| Windows enrollment, Microsoft 365 Apps, or Windows backup | Windows platform owner | Endpoint engineering. |
| Compliance policy or enrollment restriction | Endpoint security owner | Change approver and security reviewer. |
| Conditional Access or sign-in block | Identity owner | Security incident and emergency-access owner. |

For the deployment sequence, use the
[change-management playbook](Change-Management-Playbook.md). For detailed
assessment errors, use
[evidence and troubleshooting](Evidence-Troubleshooting.md).

## Microsoft references

- [Microsoft Intune enrollment guide](https://learn.microsoft.com/intune/device-enrollment/guide)
- [Troubleshoot device enrollment in Intune](https://learn.microsoft.com/troubleshoot/mem/intune/troubleshoot-device-enrollment-in-intune)
- [Device compliance overview](https://learn.microsoft.com/intune/device-security/compliance/overview)
- [Monitor app information and assignments](https://learn.microsoft.com/intune/app-management/monitor-assignments)
- [Conditional Access insights and reporting](https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-insights-reporting)