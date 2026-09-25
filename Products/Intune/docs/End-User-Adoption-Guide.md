---
title: Intune end-user adoption guide
layout: default
parent: Intune
---

# Intune end-user adoption guide

This guide is for employees whose organization is preparing a Microsoft Intune
device or application-management rollout. It explains what enrollment can look
like, what information to have ready, and where to get help.

## Important: a preview does not change your device

When IT runs the toolkit with `-WhatIf`, it does not enroll your device,
install an app, change compliance, or block a sign-in. An approved apply can
assign applications and policies to a pilot group. You need to act only when
your organization sends a pilot or enrollment notice with a date and support
contact.

The communication templates later in this guide are for that separately
approved rollout. Deployment teams must edit the bracketed fields and remove
sections that do not apply.

## MDM and MAM in plain language

Your organization can protect work in two common ways:

- **Mobile device management (MDM)** enrolls the device in Intune. The
  organization can apply device settings, require security controls, install
  approved applications, and remove organization data according to its policy.
- **Mobile application management (MAM)** protects organization data inside
  supported applications. A personal device does not have to be fully enrolled
  for MAM to apply.

Your invitation should say which approach applies. Ask the support team before
enrolling when the invitation and your device ownership do not match.

## What to prepare for a pilot

- Use a supported device and operating-system version.
- Install available operating-system updates.
- Know whether the device is company-owned or personal.
- Use the organization account named in the invitation.
- Have your MFA method available.
- Back up personal data according to your normal process.
- Use a reliable internet connection and allow time for applications and
  policies to synchronize.
- Keep the support contact and pilot reference from the invitation.

Do not remove another organization's management profile or reset a device
unless the support team has approved the migration plan.

## What you might see

### During enrollment

You may be asked to sign in, complete MFA, install Company Portal, accept an
organization management profile, or wait while required applications and
policies arrive. The exact steps depend on platform, device ownership, and
enrollment method.

### After enrollment

Company Portal can show whether the device meets organization requirements. A
compliance issue might ask you to enable encryption, use a passcode, update the
operating system, or correct another security setting selected by your
organization.

### Inside managed applications

An app protection policy can require an application PIN and can limit copying,
saving, or opening organization data in personal applications. It protects
work data; it does not install the managed application by itself.

### At sign-in

A later Conditional Access rollout can require MFA and a compliant device.
Your organization should announce enforcement only after the enrollment pilot,
device-policy delivery, support process, and emergency-access testing are
complete.

## Before contacting support

Record:

- the date and time of the problem;
- device platform and operating-system version;
- whether the device is company-owned or personal;
- the step you were completing;
- the application or portal that showed the message;
- the exact error code or correlation ID, if shown; and
- a screenshot only when your organization permits it and it contains no
  password, token, QR code, or sensitive personal information.

Do not send your password, MFA code, recovery key, certificate, or access token
to support.

## Frequently asked questions

**Does the toolkit enroll my device?**

No. The toolkit can assign applications and policies, but enrollment remains a
separate user or provisioning process. A `-WhatIf` preview changes nothing.

**Can IT see all personal content on my device?**

Visibility and controls depend on platform, ownership, and enrollment method.
Review your organization's privacy notice and the information shown during
enrollment. Ask the support team when the notice is unclear.

**Why does Company Portal say my device is noncompliant?**

Open the device status and review the setting that needs attention. Policy
delivery and evaluation can take time after enrollment or a change. Follow only
the remediation approved by your organization.

**Why can I not copy work data into a personal app?**

An app protection policy can keep organization data inside approved managed
applications. Use the approved application or contact support for the business
workflow.

**Should I factory reset or remove management to fix enrollment?**

Not unless the support team instructs you through an approved recovery plan.
Those actions can remove data or make the problem harder to diagnose.

## Communication templates

### Template A: pilot invitation

> **Subject:** Invitation to the [ORGANIZATION] Intune device pilot
>
> You are invited to the Microsoft Intune pilot beginning [DATE]. The pilot
> helps us confirm device enrollment, required applications, and security
> settings before a wider rollout.
>
> Device: [PLATFORM AND OWNERSHIP]
>
> Management approach: [MDM OR MAM]
>
> Enrollment method: [METHOD OR LINK]
>
> Complete by: [DATE]
>
> Before starting, install operating-system updates, have your MFA method
> available, and allow [EXPECTED TIME].
>
> Support: [CHANNEL, HOURS, AND CASE INSTRUCTIONS]
>
> The earlier toolkit preview did not change your device. Your action starts
> only when you follow this approved pilot invitation.

### Template B: enrollment day

> **Subject:** Intune pilot starts today
>
> The Intune pilot is open. Follow [APPROVED ENROLLMENT INSTRUCTIONS] from your
> [COMPANY-OWNED OR PERSONAL] [PLATFORM] device.
>
> You may be asked to sign in, complete MFA, install Company Portal, accept a
> management profile, or wait for required applications and policies. Keep the
> device online until Company Portal finishes its first check.
>
> Do not factory reset the device or remove another management profile unless
> support confirms the migration step.
>
> Support: [CHANNEL AND CASE REFERENCE]

### Template C: remediation notice

> **Subject:** Action needed for your managed device
>
> Intune reports that your [PLATFORM] device needs attention for [APPROVED
> PLAIN-LANGUAGE REQUIREMENT]. Complete these steps by [DATE]:
>
> [APPROVED REMEDIATION STEPS]
>
> After the change, open Company Portal and select the approved device check or
> synchronization action. Policy evaluation can take time.
>
> Contact [SUPPORT CHANNEL] if the device still reports noncompliant. Do not
> send passwords, MFA codes, recovery keys, or access tokens.

### Template D: access enforcement notice

> **Subject:** Managed-device access requirements begin [DATE]
>
> Beginning [DATE], access to [RESOURCES] requires [MFA AND/OR A COMPLIANT
> DEVICE] for [APPROVED USER SCOPE]. This follows the completed pilot and
> report-only review.
>
> Before that date, open Company Portal and confirm your device has no pending
> compliance action. If you need help, contact [SUPPORT CHANNEL].
>
> Do not send this notice until the identity owner has verified exclusions,
> emergency access, support readiness, and rollback approval.

## Microsoft references

- [Microsoft Intune enrollment guide](https://learn.microsoft.com/intune/device-enrollment/guide)
- [What information can my organization see when I enroll my device?](https://learn.microsoft.com/mem/intune/user-help/what-info-can-your-company-see-when-you-enroll-your-device-in-intune)
- [Check access in Company Portal](https://learn.microsoft.com/intune/user-help/compliance/validate-device-access-windows)
- [App protection policies overview](https://learn.microsoft.com/intune/app-management/protection/overview)

For deployment-team controls, use the
[change-management playbook](Change-Management-Playbook.md). For service desk
triage, use the [support-team guide](Support-Team-Guide.md).