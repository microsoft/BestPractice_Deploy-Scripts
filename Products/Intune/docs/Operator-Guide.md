---
title: Intune operator guide
layout: default
parent: Intune
---

# Intune operator guide

## What this toolkit is

The Microsoft Intune Best Practice Toolkit assesses the ten tasks in the Device
Management Deployment Guide for Small Business and applies the six supported
tenant-write paths. It records what is already configured, changed, blocked,
or guided. It is intended for partners, MSPs, and in-house IT teams onboarding
Microsoft 365 Business Premium or Intune Plan 1 tenants.

The current release is **write-capable and pilot-first**. Start with
`-WhatIf`. Standard writes configure Microsoft 365 Apps and Android/iOS app
protection. High-risk writes remain behind explicit approval, category,
assignment, emergency-access, and rollback gates.

## When to use it

Use the toolkit during discovery, onboarding design, readiness assessment,
change review, and pilot planning. Do not use it as proof that a production
tenant is compliant without reviewing the generated evidence and completing
the guided tasks.

## Before you run

1. Use PowerShell 7 or later in an interactive desktop session.
2. Confirm Intune is the MDM authority, affected users are licensed, and each
   intended device platform is supported.
3. Obtain customer authorization and confirm the expected tenant.
4. Use a delegated administrator with the documented Graph scopes and only the
   Intune or Entra roles needed for the selected operations.
5. Select an approved private location for HTML and JSON evidence.
6. Identify supported platforms, pilot users, support ownership, Apple and
   Google identity owners, and emergency-access accounts.
7. Do not use a production tenant for future write testing.

Check the required local modules:

```powershell
$requiredModules = @(
  'Microsoft.Graph.Authentication',
  'Microsoft.Graph.DeviceManagement'
)
$requiredModules | ForEach-Object {
  Get-InstalledModule -Name $_ -ErrorAction SilentlyContinue |
    Select-Object Name, Version
}
```

In a fresh PowerShell 7 session, install both modules from the same SDK release
for the current user:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
$graphVersion = (Get-Module -ListAvailable Microsoft.Graph.Authentication |
  Sort-Object Version -Descending | Select-Object -First 1).Version
Install-Module Microsoft.Graph.DeviceManagement -RequiredVersion $graphVersion -Scope CurrentUser
```

Do not install or update modules during a customer change window without first
testing the selected versions on the deployment workstation or in a lab. Pass
`-AutoInstallModules` to the orchestrator to install a missing module to
`CurrentUser` without a prompt; without it and without `-NonInteractive`, the
toolkit prompts once before installing.

The toolkit uses the loaded Authentication version when one exists, otherwise
the highest installed version. DeviceManagement is imported or installed at
that exact version, even if a newer copy is installed side by side.
Installation still requires consent or `-AutoInstallModules`. If conflicting
modules or assemblies are already loaded, close the shell and use the
[fresh-session recovery steps](Evidence-Troubleshooting.md#graph-module-version-conflicts);
`Remove-Module` does not unload the .NET assemblies.

The current delegated Graph API permission set requests six read scopes --
`User.Read`, `LicenseAssignment.Read.All`,
`DeviceManagementConfiguration.Read.All`, `DeviceManagementApps.Read.All`, and
`DeviceManagementServiceConfig.Read.All`, and `Policy.Read.All` -- plus five
write scopes tied to specific, currently gated write paths --
`DeviceManagementApps.ReadWrite.All`,
`DeviceManagementServiceConfig.ReadWrite.All`,
`DeviceManagementConfiguration.ReadWrite.All`,
`Policy.ReadWrite.ConditionalAccess`, and `Application.ReadWrite.All`. The
orchestrator requests every one of these eleven scopes at connect time for every
run, including `-WhatIf`; Graph consent is fixed at authentication, not
re-evaluated per module. `ShouldProcess`, the assignment scope, and the
high-risk gates still decide whether a write runs. Interactive sign-in also
uses the standard `openid`, `profile`, and `email` identity scopes.

Earlier Intune 0.2.0 pilot builds requested only the original five read scopes,
matching the read-only assessments implemented then. The current 0.3.0 authentication rewrite requests the full eleven-scope set up
front so the toolkit connects Microsoft Graph once per run, the same as
Purview. Standard and high-risk write paths use that verified context; the
imported policy catalog remains the reserved fail-closed path.

Authentication is delegated UPN/GDAP only, the same session-guard behavior as
Purview. The orchestrator connects exactly once before any task runs: it
reuses a cached Microsoft Graph context only when the account, tenant, and
every required scope already match, disconnects a stale context, and verifies
the live tenant identity through `/organization` before continuing. There is
no `-ClientId`, `-TenantId`, or `-CertificateThumbprint` parameter, and no
`ContextScope Process` override: the default Graph PowerShell authentication
persistence applies, matching Purview. Windows Authentication Manager (WAM)
usually reduces a repeat sign-in to a one-click prompt on a supported
interactive desktop; a first consent, missing scope, account change, or
customer-tenant switch can still require a full browser prompt.

For **A window handle must be configured**, follow the
[interactive-terminal recovery steps](Evidence-Troubleshooting.md#windows-sign-in-needs-a-window-handle).
`-NonInteractive` does not fix a missing sign-in window.

## Prepare a pilot group

Skip this section for a discovery-only preview. Complete it before any assigned
pilot apply. The scripts accept a group ID but do not create the group or
approve its membership for you.

1. In the customer tenant, open the [Microsoft Entra admin center](https://entra.microsoft.com)
   and go to **Entra ID > Groups > All groups > New group**. Use an approved
   group owner or administrator with permission to create and manage groups.
2. Choose **Security** and **Assigned** membership. Give the group a clear pilot
   name and an accountable owner. Do not make it role-assignable.
3. Add only the agreed, Intune-licensed test users. Use direct user membership
   for these examples, not nested groups, a device group, or an all-user dynamic
   rule. Keep deployment administrators and emergency-access accounts out.
4. Create the group, open its **Overview**, and copy **Object ID**. This is the
   value for `-PilotGroupId`, not the group name, tenant ID, or a user ID.
5. Check **Members** against the approved list and confirm the group appears
   in the Intune admin center. A user-targeted policy can reach that user's
   other applicable devices, so test users must not use production devices.
6. Retain the group ID and membership record privately. Confirm the group again
   before each apply; the script does not prove its membership is safe.

Use Microsoft's [group creation guide](https://learn.microsoft.com/entra/fundamentals/how-to-manage-groups)
and [Intune group guidance](https://learn.microsoft.com/intune/fundamentals/tenant-administration/add-groups)
if the portal layout differs. Group creation is a separate approved portal
action; do not broaden the toolkit's Graph permissions to create it.

## Run a preview

```powershell
cd Products/Intune
./Deploy-IntuneBestPractice.ps1 `
  -TenantAdminUpn admin@contoso.onmicrosoft.com `
  -PilotGroupId '<entra-group-object-id>' `
  -WhatIf
```

Use `-DelegatedOrganization` for a GDAP-managed customer tenant. A wrong or
ambiguous tenant must fail closed. `-NonInteractive` suppresses toolkit
confirmation and module-install prompts; it fails fast instead of installing a
missing module unless `-AutoInstallModules` is also supplied, and it cannot
guarantee a prompt-free first sign-in. Pre-authenticate in an approved
interactive session first when running unattended.

Use the [deployment framework](Deployment-Framework.md) and
[change-management playbook](Change-Management-Playbook.md) before a customer
onboarding. They separate assessment, guided portal work, device enrollment,
compliance observation, and later access enforcement.

## Apply to a pilot

Apply the standard baseline:

```powershell
./Deploy-IntuneBestPractice.ps1 `
  -TenantAdminUpn admin@contoso.onmicrosoft.com `
  -PilotGroupId '<entra-group-object-id>'
```

This creates and assigns Microsoft 365 Apps plus the configured Android and
iOS/iPadOS Level 1 app-protection policies. First run the same command with
`-WhatIf`, review the exact targets, and obtain approval before removing it.
Existing toolkit-managed objects are left unchanged, not repaired or
reassigned. A missing pilot ID can leave standard objects unassigned; do not
treat creation alone as a successful pilot.

## Add high-risk changes one at a time

These are separate change windows, not a script to paste and execute in full.
Complete the standard pilot and verify device behavior first. Before each
stage, retain its before-state and approved recovery plan using
[partial-deployment recovery](Evidence-Troubleshooting.md#recover-a-partial-pilot-deployment).
The examples deliberately skip unrelated writers to isolate the change, not
to hide a failure.

Define the approved inputs in the same PowerShell session. Replace every
placeholder, including the approval reference, with the real private record:

```powershell
$approved = @{
  TenantAdminUpn = 'admin@contoso.onmicrosoft.com'
  PilotGroupId = '<entra-group-object-id>'
  IncludeHighRisk = $true
  CustomerApprovalId = '<approved-change-reference>'
  SkipAppProtectionPolicies = $true
  SkipAppDeployment = $true
}
```

**Stage 1: device compliance policies (task 7).** Review existing Conditional
Access first: a new compliance policy can affect access immediately. Verify
policy delivery and device compliance before advancing.

```powershell
.\Deploy-IntuneBestPractice.ps1 @approved `
  -SkipComplianceBaseline -SkipEnrollmentRestrictions -SkipDeviceConditionalAccess `
  -WhatIf
```

**Stage 2: enrollment restrictions (task 5).** Confirm the intended personal
versus corporate enrollment behavior on each supported pilot platform.

```powershell
.\Deploy-IntuneBestPractice.ps1 @approved `
  -SkipComplianceBaseline -SkipDeviceCompliancePolicies -SkipDeviceConditionalAccess `
  -EnableEnrollmentRestrictions `
  -WhatIf
```

**Stage 3: default compliance setting (task 4).** This is a **tenant-wide
singleton**, not a pilot-scoped policy. The pilot ID does not limit its effect.
Proceed only after separate tenant-wide approval and review of existing
compliant-device Conditional Access and devices without a compliance policy.
Record both the previous default and compliance-status validity period.

```powershell
.\Deploy-IntuneBestPractice.ps1 @approved `
  -SkipDeviceCompliancePolicies -SkipEnrollmentRestrictions -SkipDeviceConditionalAccess `
  -EnableComplianceEnforcement `
  -WhatIf
```

**Stage 4: report-only Conditional Access (task 10).** The identity owner must
verify working emergency-access accounts and obtain their object IDs from
**Entra ID > Users > All users > the account > Overview**. Supply those IDs,
not UPNs, and confirm the written policy exclusions after creation.

```powershell
.\Deploy-IntuneBestPractice.ps1 @approved `
  -SkipComplianceBaseline -SkipDeviceCompliancePolicies -SkipEnrollmentRestrictions `
  -EnableConditionalAccessEnforcement `
  -BreakGlassExclusionsConfirmed `
  -BreakGlassUserIds '<emergency-access-user-object-id>' `
  -RollbackAcknowledged `
  -WhatIf
```

For **each stage**, inspect its preview first. Only after approval, rerun that
one command without `-WhatIf`, verify portal/device state, and archive the
reports. Rerun the same stage to check for unintended changes before moving
on. Do not add `-AssignTenantWide` to these examples.

The last stage creates a report-only policy, not enforcement. Review
[report-only sign-in results](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-report-only)
and the [access-decision checklist](Change-Management-Playbook.md#phase-7-make-the-access-decision-separately).
Enabling the policy is a separate human-approved portal change.

## What to expect

The run connects to Microsoft Graph, validates tenant identity, checks license
capabilities, executes the supported assessments, applies or previews selected
writes, records guided steps, and writes:

- `Reports/intune-run-report.html`, for operator review.
- `Reports/intune-run-log.json`, for machine processing and audit evidence.
- `Reports/intune-applicability.json`, for internal module applicability.

The final output prints full paths for the saved HTML and JSON run reports
and a copyable command to open the HTML manually. These messages also appear
for previews and failures after logging starts, not just successful deployments.
If saving either report fails, a warning identifies the problem without
hiding the original deployment error. Keep the console output and do not
mistake a previous run's file for current evidence. The browser is never
opened automatically, and the configured filenames are unchanged.

Current automated assessments cover Apple MDM push certificate health, the
default compliance setting, enrollment restrictions, Android/iOS app
protection, and per-platform compliance policies. Supported apply paths cover
Microsoft 365 Apps, Android/iOS app protection, default compliance, enrollment
restrictions, per-platform compliance policies, and enrollment Conditional
Access. Remaining tasks produce explicit guided evidence.

An Apple certificate singleton response of `404` is recorded as `GuidedOnly`,
not as proof that the certificate is absent. Verify the Apple MDM Push
certificate page in the Intune admin center. This response does not stop the remaining assessments or selected writes.

Graph can return a nullable `SecureByDefault` value even when the portal has a
configured state. The toolkit therefore records the state as unknown,
`GuidedOnly`, and does not change it. An explicit Boolean false can proceed
through the approved high-risk write path. If the post-write readback is null
or unavailable, the run is blocked until the portal state is verified.

The v1.0 service can return `400` for the documented compliance-policy
`scheduledActionsForRule` relationship. The toolkit continues policy and
assignment inventory, records `ScheduledActionReadback=Unavailable`, and does
not report an unknown action count as zero.

Enrollment restriction configuration IDs are service-defined opaque values,
not always GUIDs. The toolkit safely URL-encodes them for assignment reads and
excludes them from reports.

The enrollment restriction assessment reports `AssignedScope` and
`ExclusionCount` across the combined assignments it read. It inspects every
assignment before reporting, so an assignment that Graph returns without a
`target` fails the assessment instead of being skipped. Microsoft Graph does not
guarantee assignment ordering, so the reported exclusion count does not depend
on the order the service returns assignments in. See
[evidence and troubleshooting](Evidence-Troubleshooting.md) for the meaning of
each scope value.

Android and iOS/iPadOS app-protection policy IDs are also service-defined opaque
values. The toolkit URL-encodes them for assignment and target-app reads and
never includes them in evidence.

## Interpret outcomes

| Outcome | Meaning | Operator action |
|---|---|---|
| `AlreadyCompliant` | The implemented assessment proved the narrow checked state. | Review evidence; do not infer broader compliance. |
| `GuidedOnly` | A portal/external step, beta-only boundary, incomplete comparison, or unapproved write remains. | Follow the documented workflow and retain verification evidence. |
| `Skipped` | A license, operator switch, or applicability decision prevented the task. | Resolve the exact reason before rerunning. |
| `Blocked` | A safety prerequisite prevented the operation. | Do not bypass the gate; obtain approval or correct scope. |
| `Failed` | The assessment could not establish trustworthy state. | Correct authentication, permission, response, or service failure and rerun. |

## Safety and change control

Supported writes default to one approved pilot group. High-risk operations
require explicit customer approval and the documented category gates. Tenant
wide assignment requires rollback acknowledgment and configuration approval.
Conditional Access is created report-only by default. Certificate replacement,
the imported policy catalog, unsupported beta resources, and unmanaged-object
overwrite are not safe defaults.

## Guided tasks

Use [Future Intune write capabilities](Future-Write-Capabilities.md) to identify
the supported current workflow, API gap, stakeholder owner, and evidence needed
for every task that is not automated.

## After the run

Review every module verdict and every `Created`, `Updated`, or `Adopted`
entry. Confirm the target and assignment scope match the approved change.
Check module readback where it is emitted, and verify app-protection targeting
and assignment in the portal. Store reports privately, complete portal-guided
steps, and rerun with the same effective parameters to confirm idempotency. Do not publish tenant
reports or include customer identifiers, exports, credentials, or approval
artifacts in source control.

For compliance and enrollment restrictions, `Verified` requires managed
settings and the exact assignment to match, including on an idempotent rerun.
Compliance verification also reads scheduled-action children. Missing reads,
additional targets or drift block continuation; the create-only writer does
not repair existing objects. Enrollment inventory and readback use the same
beta API as the single-platform writer and distinguish legacy multi-platform
objects. Review beta compatibility in the approved pilot.

Existing managed app-protection policies remain unchanged and require portal
review. Their inventory is `GuidedOnly`, not verified compliance.

Verify the five automated assessments in the portal without changing them:

| Assessment | Current portal route |
| --- | --- |
| Apple certificate | **Devices > Device onboarding > Enrollment > Apple > Apple MDM Push Certificate** |
| Default compliance | **Devices > Manage devices > Compliance > Compliance settings** or **Endpoint security > Device compliance > Compliance policy settings** |
| Enrollment restrictions | **Devices > Device onboarding > Enrollment > Enrollment options > Device platform restriction** |
| App protection | **Apps > Manage apps > Protection** |
| Device compliance | **Devices > Manage devices > Compliance > Policies** or **Endpoint security > Device compliance > Policies** |

Use the linked Microsoft Learn procedures in the
[device enrollment deployment guide](Device-Enrollment-Deployment-Guide.md)
if portal navigation changes. A portal discrepancy blocks closure; it is not a
reason to edit the tenant until the report, API behavior, and approved intent
are reconciled.
