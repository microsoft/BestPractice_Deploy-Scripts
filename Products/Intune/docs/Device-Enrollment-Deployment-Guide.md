---
title: Intune device enrollment deployment guide
layout: default
parent: Intune
---

# Intune device enrollment deployment guide

Use this guide to prepare a customer tenant for device enrollment using the
Device Management Deployment Guide for Small Business. It separates the guide's
required outcome from the current toolkit capability.

The current toolkit is **write-capable and pilot-first**. Run the single
orchestrator with `-WhatIf` first to assess available state, preview the
selected writes, and create private HTML and JSON evidence:

```powershell
cd Products/Intune
.\Deploy-IntuneBestPractice.ps1 `
  -TenantAdminUpn admin@contoso.onmicrosoft.com `
  -PilotGroupId '<entra-group-object-id>' `
  -WhatIf
```

Do not interpret a successful preview as confirmation that all guide tasks are
complete. Review the report, apply the approved pilot scope, complete guided
portal and third-party work, retain customer change approval, and rerun to
confirm readback and idempotency.

For your first run, follow [pilot group setup](Operator-Guide.md#prepare-a-pilot-group).
For automation, use the [separate high-risk stage commands](Operator-Guide.md#add-high-risk-changes-one-at-a-time),
not all portal changes on this page in one session. The guide's references to
All users are source recommendations, not the safe scope for a first pilot.

## Before starting

1. Confirm the customer tenant, intended platforms, and deployment owner.
2. Confirm Business Premium or Intune Plan 1 licensing for the affected users.
3. Identify emergency-access accounts before changing compliance or Conditional
   Access settings.
4. Decide which platforms are supported. Do not configure a platform that the
   customer will not enroll and support.
5. Store reports and change evidence in the approved private customer location.
   Do not commit reports, exports, credentials, or approval records to source
   control.

## Priority 1: enrollment foundation

### Windows automatic enrollment

In the Intune admin center, go to **Devices > Device onboarding > Enrollment >
Windows > Automatic Enrollment**. Set the MDM user scope for the Microsoft
Entra users whose Windows devices the customer intends to manage. Use `All` or
`Some` when Windows BYOD enrollment is intended.

Leave the WIP user scope set to `None`. Windows Information Protection is
deprecated and is not a substitute for Microsoft Purview Information Protection
or Endpoint DLP.

**Toolkit boundary:** guided. The repository has no approved GA shell
write-and-readback path for this setting. The report records the work as guided
until the operation is verified.

### Apple MDM push certificate

For iOS/iPadOS and macOS, go to **Devices > Device onboarding > Enrollment >
Apple > Apple MDM Push Certificate**:

1. Grant Microsoft permission to send user and device information to Apple.
2. Download and securely retain the certificate signing request.
3. Use the Apple Push Certificates Portal to create or renew the certificate.
4. Return to Intune, enter the Apple ID that owns the certificate, and upload
   the certificate.

Use a customer-owned Apple ID with a documented renewal owner. A certificate
expiry can interrupt Apple device management.

See [Get an Apple MDM push certificate](https://learn.microsoft.com/intune/device-enrollment/apple/create-mdm-push-certificate)
for the current Microsoft procedure and annual renewal requirements.

**Toolkit boundary:** the script reads certificate health and warns before
expiry. It does not automate Apple sign-in, certificate creation, or certificate
upload because those recovery and ownership steps require separate validation.

### Managed Google Play

For Android Enterprise, go to **Devices > Device onboarding > Enrollment >
Android > Managed Google Play**:

1. Grant Microsoft permission to send user and device information to Google.
2. Select **Launch Google**.
3. Confirm the Microsoft Entra account associated with Android Enterprise
   management for this tenant.
4. Complete Google Admin account creation and select **Allow and create
   account** when prompted.

Use a customer-controlled identity with a working mailbox and record at least
two appropriate Google enterprise owners for continuity.

**Toolkit boundary:** guided. Google consent and account association are
interactive. The toolkit does not automate browser steps or a destructive
disconnect.

### Default compliance policy settings

Go to **Devices > Manage devices > Compliance > Compliance settings**. The same
settings are also available under **Endpoint security > Device compliance >
Compliance policy settings**. Set **Mark devices with no compliance policy
assigned as** `Not compliant`. The guide's default compliance-status period is
30 days. Retain it unless the deployment team has a documented reason to select
a value from 1 through 120 days.

This setting becomes access-impacting once device-based Conditional Access is
enforced. Confirm enrolled devices receive the intended compliance policy before
enabling Priority 3 enforcement. It affects the whole tenant even when
`-PilotGroupId` is supplied; review existing Conditional Access and devices
outside the pilot before changing it.

**Toolkit boundary:** the script always assesses `secureByDefault`. With
`-IncludeHighRisk -EnableComplianceEnforcement` and a customer approval ID, it
sets the value to true and reads it back.

## Priority 2: device policies

### Enrollment restrictions

Go to **Devices > Device onboarding > Enrollment > Enrollment options > Device
platform restriction**. Create a restriction for each platform that needs one:

1. Select Windows, Android, macOS, or iOS/iPadOS.
2. Name and describe the restriction.
3. Configure platform enrollment, personally owned enrollment, Android
   manufacturer blocks, and allowed operating-system version range as needed.
4. Add scope tags only when the customer's RBAC design requires them.
5. Assign at least one group. The guide permits All users.

When MAM is used for personal devices, consider blocking personal-device MDM
enrollment so users do not enroll devices unintentionally.

**Toolkit boundary:** the script inventories existing restrictions and
assignments. With
`-IncludeHighRisk -EnableEnrollmentRestrictions -CustomerApprovalId <id>`, it
creates the configured Android and iOS/iPadOS personal-enrollment restrictions
and assigns the selected scope.

### App protection policies

Go to **Apps > Manage apps > Protection > Create** and select the intended
platform. The guide's basic recommendation targets Core Microsoft Apps:

- Block organization-data backup to iTunes and iCloud.
- Allow organization-data transfer only to policy-managed apps.
- Block saving organization-data copies.
- Allow OneDrive and SharePoint as selected save destinations.

Configure the platform's access-requirement and conditional-launch settings,
then assign the policy to a user group. Android and iOS/iPadOS settings are
different and must be reviewed independently.

**Toolkit boundary:** the script inventories Android and iOS/iPadOS policy,
assignment, and target-app state. It also creates the configured Level 1
policies, targets the core Microsoft apps, and assigns the selected scope.
Modern Windows MAM remains outside the supported write scope.

### Device compliance policies

For Windows 10/11, create a Windows 10/11 compliance policy and require:

- BitLocker, Secure Boot, and code integrity.
- Firewall, TPM, antivirus, and antispyware.
- Defender antimalware, current security intelligence, and real-time
  protection.

Set **Mark device noncompliant** to one day. The guide assigns the policy to
All users. For other platforms, require passcode, device encryption, and code
integrity where those controls are available.

Do not apply a broad compliance policy until the customer understands the
effect on existing Conditional Access. A policy can immediately affect access
for devices that fail it.

**Toolkit boundary:** the script inventories supported policy types. With
`-IncludeHighRisk -CustomerApprovalId <id>`, it creates and assigns the
approved per-platform compliance payloads. It does not apply the broader
imported policy catalog or unsupported platform types.

### Microsoft 365 Apps

Go to **Apps > All Apps > Create**, select **Windows 10 and later** under
Microsoft 365 Apps, then:

1. Review the suite information.
2. Set default file format to **Office Open Document Format**.
3. Set update channel to **Monthly Enterprise Channel**.
4. Assign the deployment. The guide uses All users.

**Toolkit boundary:** the toolkit creates the configured Microsoft 365 Apps
deployment through the validated beta `officeSuiteApp` path, assigns the
selected scope, and reads back the display name and update channel.

### Enterprise State Roaming

The source guide enables **Users may sync settings and app data across devices**
for All users. Windows devices must use Windows 10 version 21H2 or later, or
Windows 11, and authenticate with a Microsoft Entra identity. Hybrid-joined
devices require the documented Entra hybrid setup.

Microsoft has since moved this management area to Windows Backup for
Organizations policy management. Follow the current Microsoft administration
guidance for the customer's Windows estate.

In the Intune admin center, open **Devices > Device onboarding > Enrollment >
Windows > Windows Backup and Restore**. The restore page requires backup to be
configured in Settings Catalog before it can restore a user's settings.

**Toolkit boundary:** guided while the policy payload, assignment, readback,
and recovery contract remain unverified.

## Priority 3: Conditional Access for Intune enrollment

Create this policy only after Priority 1 and the selected Priority 2 compliance
policies are validated. Start with a small test group as the guide recommends.

1. In Intune, go to **Devices > Conditional Access > Create new policy**.
2. Include the approved test users or groups and exclude emergency-access
   accounts.
3. Under target resources, select **Microsoft Intune Enrollment**.
4. Grant access only when **Require multifactor authentication** and **Require
   device to be marked compliant** are both satisfied. Select **Require all the
   selected controls**.
5. Set sign-in frequency to **Every time**.
6. Validate sign-in behavior, enrollment, and emergency-access accounts before
   enabling the policy for a broader group.

New tenants may not have the Microsoft Intune Enrollment service principal. An
Entra administrator must create it before targeting the application. Its app ID
is `d4ebce55-015a-49b5-a083-c84d1797ae8c`.

**Toolkit boundary:** with every documented high-risk gate, the module ensures
the service principal exists and creates the policy in the configured
report-only state. The operator supplies the verified exclusion object IDs
through `-BreakGlassUserIds` or `-BreakGlassGroupIds`; the module writes and
reads those exclusions back. Verify them and the sign-in results in the portal
before any separate enforcement decision.

After creating a missing Microsoft Intune Enrollment service principal, the
toolkit verifies that Graph can read it back before submitting the Conditional
Access policy. If the service principal is not visible yet, wait for Entra
propagation, confirm the Enterprise application in the portal, and rerun.
Conditional Access policy readback can also briefly return `404` immediately
after creation; the toolkit retries that specific post-create readback before
failing closed.

## Enroll devices and support adoption

After the tenant baseline is ready, follow the platform-specific enrollment
guides:

- [Windows enrollment guide](https://aka.ms/WindowsEnrollmentGuide)
- [iOS/iPadOS enrollment guide](https://aka.ms/iOSEnrollmentGuide)
- [Android enrollment guide](https://aka.ms/AndroidEnrollmentGuide)
- [macOS enrollment guide](https://aka.ms/macOSEnrollmentGuide)

The [Intune Adoption Kit](https://aka.ms/intuneadoptionkit) provides additional
customer communication and demonstration material but requires a Microsoft
sign-in. Use the local [end-user adoption guide](End-User-Adoption-Guide.md) for
copy-ready pilot and enforcement templates. Confirm that the support desk,
customer deployment owner, and platform owners know where to route enrollment
failures before inviting users to enroll.

## After each tenant

1. Review the HTML and JSON reports with the customer deployment owner.
2. Record guided portal actions, target groups, exceptions, and validation
   results in the customer change record.
3. Rerun with the same effective parameters after toolkit or portal changes
   and confirm readback and idempotency.
4. Stop and escalate if a report shows a wrong tenant, missing role or license,
   malformed response, blocked safety gate, or unexpected noncompliance.

See [Evidence and troubleshooting](Evidence-Troubleshooting.md) for recovery
guidance and [Future Intune write capabilities](Future-Write-Capabilities.md)
for the verified-write release gates.
