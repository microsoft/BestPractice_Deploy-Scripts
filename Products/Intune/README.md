---
title: Intune
layout: default
nav_order: 4
has_children: true
permalink: /intune/
---

# Microsoft Intune Best Practice Deployment Toolkit

> ⚠️ **Write-capable. Pilot first, and read the safety gates below.**
> This product applies real tenant changes for six baseline tasks. Every write
> is gated by `-WhatIf`/`ShouldProcess`, wrapped in the shared transient-retry
> boundary, and recorded in structured evidence. Modules use supported
> readback where the service exposes a reliable projection. High-risk items
> (default compliance, device compliance, enrollment restrictions, Conditional
> Access) stay behind `-IncludeHighRisk` and their category switches, and the
> Conditional Access policy is created report-only by default. Preview with
> `-WhatIf`, run against a pilot group, and confirm break-glass exclusions
> before enforcing. The hash-verified policy catalog remains apply-blocked.

PowerShell automation that assesses and deploys Microsoft's recommended
**device enrollment and device management baseline** for a Microsoft 365
**Business Premium** tenant. Built for anyone who needs a repeatable way to
understand current state, apply the supported baseline to a pilot, complete
guided tasks, and retain deployment evidence, whether that is a partner, an
MSP, or an in-house IT team.

The intended experience is a guided onboarding flow rather than a collection of
unconnected scripts. The toolkit will assess prerequisites and licenses,
preview the recommended baseline, apply supported settings safely, guide you
through steps that require human sign-in or have no supported API, verify the
result, and produce client-ready deployment evidence.

The configuration is taken from the Microsoft **Device Management Deployment
Guide for Small Business** (Device Enrollment Best Practices, Business Premium /
Intune Plan 1).

## First time here? Start with a preview

You do not need to read every guide before evaluating the toolkit. This first
run reads tenant state and writes local reports; it does not deploy a baseline.

1. Download the repository version containing `Products\Intune` (on GitHub,
   **Code > Download ZIP**, then **Extract All**), or use your approved clone.
   Keep the whole product folder, including `Modules` and `Config`. If Intune
   is absent from the downloaded release, stop and obtain a release that
   includes it. Do not mix scripts and documentation from different versions.
2. Open **PowerShell 7** in an interactive desktop terminal, not Windows
   PowerShell 5.1. Change directory to the extracted repository root.
3. Review [prerequisites](#prerequisites), especially the tenant roles and
   permissions requested during Microsoft sign-in.
4. Replace the sample UPN and run the command below. `-AutoInstallModules`
   installs missing Graph modules for your Windows user; omit it if your
   organization manages those dependencies.

```powershell
cd .\Products\Intune
.\Deploy-IntuneBestPractice.ps1 `
  -TenantAdminUpn admin@contoso.onmicrosoft.com `
  -AutoInstallModules `
  -WhatIf
```

Use the printed open command for the saved HTML report, by default
`Reports\intune-run-report.html`. No tenant action should be `Created`,
`Updated`, or `Adopted`. High-risk writes being withheld is expected.
`GuidedOnly` means follow-up work, not completed configuration; any `FAILED`
module needs investigation.

If a prerequisite or sign-in fails before setup, the baseline has not been
assessed or deployed. `ConfiguredItem` messages describe selected
recommendations, not completed work. Follow the
[module-version recovery guidance](docs/Evidence-Troubleshooting.md#graph-module-version-conflicts)
for an Authentication/DeviceManagement assembly conflict.

No pilot group is needed for this discovery run. A preview saying **no target
(none provided)** is not an assignment plan. Before removing `-WhatIf`, follow
the [pilot group setup](docs/Operator-Guide.md#prepare-a-pilot-group) and
[standard pilot apply](docs/Operator-Guide.md#apply-to-a-pilot) instructions.
For sign-in or report problems, start with
[troubleshooting](docs/Evidence-Troubleshooting.md).

## What the baseline covers

Ten tasks across three priorities.

| # | Task | Priority | Configured in |
|---|---|---|---|
| 1 | Automatic MDM enrollment for Windows | 1 | Entra |
| 2 | Apple MDM push certificate | 1 | Intune + Apple |
| 3 | Managed Google Play connection | 1 | Intune + Google |
| 4 | Treat devices with no compliance policy as not compliant | 1 | Intune |
| 5 | Device platform enrollment restrictions | 2 | Intune |
| 6 | App protection policies for core Microsoft apps | 2 | Intune |
| 7 | Per-platform device compliance policies | 2 | Intune |
| 8 | Microsoft 365 Apps deployment | 2 | Intune |
| 9 | Enterprise State Roaming | 2 | Entra |
| 10 | Require MFA and a compliant device for Intune enrollment | 3 | Entra |

Task 10 is configured in the Entra admin center. Microsoft moved task 9,
Enterprise State Roaming, to Windows Backup for Organizations policy management
after June 2026. Both remain in this product because the source guide treats
them as part of the same endpoint baseline, and task 10 is what makes tasks 4
and 7 enforce access.

## Current guided and partial-automation boundaries

**The Apple MDM push certificate** needs an Apple ID, a downloaded certificate
signing request, a session on the Apple Push Certificates Portal, and a manual
certificate exchange. It is also an annual renewal owned by the customer.
Graph v1.0 can read certificate status, download a signing request, and upload
a certificate, but the overall task remains guided. Optional upload automation
would require separate pilot proof because replacement has no safe automatic
rollback. The certificate status read is now implemented as an automated,
read-only assessment with a configurable pre-expiry renewal warning (see below).

**The managed Google Play connection** needs an interactive browser consent flow
binding a Google account to the tenant. Use a customer-controlled Microsoft
Entra account with an active mailbox and either the Intune Administrator role
or a custom Intune role with organization read and update permissions. Google
recommends at least two enterprise owners for redundancy. A GDAP relationship
can provide the Intune role boundary, but it does not replace the
customer-owned Google identity, mailbox, or interactive consent.

No GA Graph connect and readback pair exists; the candidate resource is
beta-only. The toolkit therefore records `GuidedOnly` and directs the operator
to **Devices > Device onboarding > Enrollment > Android > Managed Google
Play**. After connection, verify that Microsoft Intune, Microsoft
Authenticator, Intune Company Portal, and Managed Home Screen appear as
managed Google Play apps. Disconnect is a destructive recovery action:
Microsoft documents that it disables Android Enterprise management and
unenrolls Android Enterprise devices, so the toolkit does not automate it.

Official source capture on 10 August 2026 also found no supported GA write and
readback pair for **Windows automatic MDM enrollment** or **Enterprise State
Roaming**. Those tasks remain `GuidedOnly`.

The Microsoft 365 Apps and Android/iOS app-protection write paths use the
specific beta resources validated by the current release. That approval does
not extend to the imported 19-payload policy catalog, modern Windows MAM, or
other beta-only resources. Those broader paths remain blocked or guided.

See [Future Intune write capabilities](docs/Future-Write-Capabilities.md) for a
source-conscious roadmap of API gaps, pilot blockers, and the stakeholder help
needed before each task can gain tenant-write behavior.

## Choose your starting point

- **Evaluating coverage:** use
  [scenarios and capabilities](docs/Scenarios.md) for the current status,
  tenant impact, and operator action for all ten guide tasks.
- **Running the assessment:** use the
  [operator guide](docs/Operator-Guide.md) for prerequisites, commands, reports,
  and outcome interpretation.
- **Planning the rollout:** use the
  [deployment framework](docs/Deployment-Framework.md) for task dependencies
  and the [change-management playbook](docs/Change-Management-Playbook.md) for
  customer decisions, pilot execution, portal verification, and closure.
- **Completing portal work:** use the
  [device enrollment deployment guide](docs/Device-Enrollment-Deployment-Guide.md)
  for the ordered Intune, Entra, Apple, and Google procedures.
- **Preparing support and users:** use the
  [support-team guide](docs/Support-Team-Guide.md) for triage and ownership and
  the [end-user adoption guide](docs/End-User-Adoption-Guide.md) for approved
  pilot and enforcement communications.
- **Reviewing configuration:** use the
  [configuration reference](docs/Configuration-Reference.md) for active,
  classification-only, reserved, and blocked controls.
- **Using copy-ready commands:** use the
  [assessment and deployment examples](Examples/Read-Only-Assessment.md).
- **Resolving a failure:** use
  [evidence and troubleshooting](docs/Evidence-Troubleshooting.md).
- **Assessing future automation:** use
  [future write capabilities](docs/Future-Write-Capabilities.md) for the API,
  permission, pilot, readback, and rollback gates.

The safe first run is the orchestrator with `-WhatIf`. It connects to the
expected tenant, performs the supported assessments, previews every selected
write, records guided boundaries, and writes local evidence without changing
the tenant. It does not complete guided portal tasks and it does not authorize
a later manual change.

## Read-only assessments implemented today

Five guide task areas now run automated, read-only assessments as part of this
toolkit. None of these reads changes tenant state, and each fails closed rather
than guessing when a result is missing or malformed.

The repository also contains a normalized 19-payload candidate policy catalog:
seven Baseline mobile payloads, seven Advanced mobile payloads, and five
Windows compliance or hardening payloads. The catalog was imported from a
contributor implementation, stripped of export-only object metadata, assigned stable
file names, and protected by SHA-256 digests. Three Settings Catalog payloads
that the original script silently skipped now carry the required Graph
discriminator.

This import does not make the payloads deployable. Every catalog entry is
marked `Blocked`, and the source used Microsoft Graph beta commands.
`-EnablePolicyCatalogWrite` therefore always denies the run until API and
tenant-permission review, pilot assignment, readback, preservation, rollback,
and recovery evidence are recorded.

**Guide task 2, Apple MDM push certificate health.**
`Setup-EnrollmentPrerequisites.ps1` reads
`GET /deviceManagement/applePushNotificationCertificate`. It reports
`AlreadyCompliant` when a valid certificate is outside the configured renewal
warning window, and `GuidedOnly` with renewal direction when the certificate is
within that window or expired. `ApplePushCertificate.RenewalWarningDays`
defaults to 30 days. Microsoft Graph can return `404` when the certificate
singleton is unavailable. Because Microsoft does not document that response as
proof that setup is incomplete, the assessment records `GuidedOnly`, retains
only the status code, and directs the operator to verify the Intune admin
center. Missing, null, or malformed certificate fields and authorization
failures still fail closed.
The certificate signing request download and certificate upload described
above remain guided and are out of scope for this assessment. The required
permission is `DeviceManagementServiceConfig.Read.All`. Confirm the operator's
Intune role and GDAP mapping for the target customer before relying on it.

**Guide task 4, default compliance setting.** `Setup-ComplianceBaseline.ps1`
reads the `secureByDefault` setting through the documented
`Get-MgDeviceManagement` cmdlet. It reports `AlreadyCompliant` when the
setting is already true, `GuidedOnly` when Graph returns a nullable or missing
projection that cannot prove the current state, and an explicit false state as
drift. An unknown state never triggers a tenant write. With
`-IncludeHighRisk -EnableComplianceEnforcement -CustomerApprovalId <id>`, the
module sets `secureByDefault` to true, preserves the configured check-in
period, and reads the setting back into evidence. If Graph does not return a
verifiable post-write value, the module blocks the run and directs portal
verification. Without those gates, the assessment still runs and records that
the write was withheld.

Withholding `-IncludeHighRisk` or `-EnableComplianceEnforcement` does not block
the task 4 read. It is recorded as informational `WriteRiskGate` evidence and
a `WriteBlockedItemKeys` entry, separate from the assessment result.

**Guide task 5, device enrollment restriction inventory.**
`Setup-EnrollmentRestrictions.ps1` reads the GA platform-restriction
configuration collection and each configuration's assignment collection. It
reports only normalized configuration count, assignment scope, platform-blocked
signals, and personal-enrollment-blocked signals. It ignores the unrelated
device enrollment limit resource and does not retain policy or group
identifiers. Intune can return opaque 64-character configuration IDs rather
than GUIDs. The toolkit validates them as non-empty identifiers, URL-encodes
them before assignment reads, and never writes them to evidence. The assessment
result remains `GuidedOnly` because the inventory does not by itself prove the
desired platform baseline. With
`-IncludeHighRisk -EnableEnrollmentRestrictions -CustomerApprovalId <id>`, the
module creates the configured iOS/iPadOS and Android personal-enrollment
restrictions, assigns them to the selected scope, and reads them back. The
required read permission is `DeviceManagementServiceConfig.Read.All`.

Withholding `-IncludeHighRisk` or `-EnableEnrollmentRestrictions` does not block
the inventory. Missing write authorization is recorded separately as
`WriteRiskGate` evidence.

**Guide task 6, Android and iOS/iPadOS app protection inventory.**
`Setup-AppProtectionPolicies.ps1` reads Android and iOS/iPadOS managed app
protection policies, each policy's assignments, and the documented per-policy
targeted-app list. It emits one assessment entry per platform with normalized
policy count, toolkit-managed policy count, assignment scope, and target-app
readback state. The assessment never calls the app protection `assign` or
`targetApps` actions, never changes a policy, and never treats target-app
readback unavailability as compliance. Intune can return opaque non-GUID policy
IDs. The toolkit requires a non-empty value, URL-encodes it for relationship
reads, and excludes it from evidence. The required read permission is
`DeviceManagementApps.Read.All`. Confirm the operator's Intune role, GDAP
mapping, and targeted-user licensing for the customer tenant.

The same module creates the configured Level 1 policy for each platform,
targets the configured core Microsoft applications, and assigns it to the
pilot group or approved tenant-wide scope. It skips an existing toolkit-managed
policy by default. The current create-only path does not update or merge an
existing app-protection policy. Modern Windows MAM remains outside this write
path.

Renamed toolkit-managed app-protection and Microsoft 365 Apps objects are left
unchanged. Renamed managed compliance or enrollment objects block further
creation until their recorded IDs and configured names are reconciled.
An exactly equivalent report-only Conditional Access policy is left unchanged
even if renamed. Do not remove management markers to bypass these protections.

**Guide task 7, per-platform device compliance policy inventory.**
`Setup-DeviceCompliancePolicies.ps1` independently reads the GA policy and
assignment collections. Microsoft documents a scheduled-action collection,
but a pilot iOS policy returned `400` because the v1.0 service had no matching
GET route. The toolkit records scheduled-action readback as unavailable rather
than reporting a false zero or failing the remaining inventory. It reports
normalized counts for Android device administrator, Android work profile,
iOS/iPadOS, macOS, Windows, beta-only, and unknown policy types without
retaining policy names, IDs, settings, groups, rules, or raw responses. Android
Device Owner and AOSP policy types remain guided because their v1.0
documentation links fall back to beta. The required read permission is
`DeviceManagementConfiguration.Read.All`.

The task 7 evidence also reports the seven candidate compliance payloads in
the imported catalog: three Baseline, three Advanced, and one Windows. The
write path uses the separately approved payload set under
`Config/CompliancePayloads`; it does not authorize the broader imported policy
catalog.

Withholding `-IncludeHighRisk` does not hide this inventory. Missing write
authorization is recorded separately as `WriteRiskGate` evidence. When the
gate is supplied, the module creates the approved per-platform compliance
policies, assigns them to the selected scope, and verifies each created object.
Scheduled-action mutation, unsupported platform types, and the broader catalog
remain outside the supported path.

Each run now produces per-task assessment evidence for these items, alongside
the existing preflight and safety-gate evidence.

App protection and compliance are platform-specific. Android and iOS/iPadOS
Level 1 app-protection writes are supported in the validated release, but
modern Windows MAM remains beta-only. The approved compliance payloads cover
the supported release platforms; Android Device Owner, AOSP, and the imported
advanced catalog remain guided or blocked.

## Where this deliberately differs from the guide

The guide repeatedly says to assign policies to **all users**. For a first
automated run against a live tenant that is an unacceptable blast radius,
particularly for enrollment restrictions, compliance enforcement, and
Conditional Access.

**This toolkit defaults to a pilot group.** Supply `-PilotGroupId`. Assigning
tenant-wide is an explicit opt-in through `-AssignTenantWide`, which also
requires `-RollbackAcknowledged`. If you want the guide's behavior literally,
you have to ask for it.

## Safety gates

Four tasks can affect enrollment or access, so their write paths are gated
rather than default-on.

| Gate | Required for | Also requires |
|---|---|---|
| `-IncludeHighRisk` | Any high-risk item, including task 7 compliance policy creation | `-CustomerApprovalId` |
| `-EnableComplianceEnforcement` | Task 4 | `-IncludeHighRisk` |
| `-EnableEnrollmentRestrictions` | Task 5 | `-IncludeHighRisk` |
| `-EnableConditionalAccessEnforcement` | Task 10 policy creation; the configured default remains report-only | `-IncludeHighRisk`, `-BreakGlassExclusionsConfirmed`, at least one `-BreakGlassUserIds` or `-BreakGlassGroupIds` value, `-RollbackAcknowledged` |
| `-AssignTenantWide` | Tenant-wide assignment | `-RollbackAcknowledged`, plus `Assignment.AllowTenantWideAssignmentForHighRisk` in configuration |
| `-EnablePolicyCatalogWrite` | Reserved imported-catalog apply path | Always blocked pending API, permission, pilot, and rollback evidence |

Four of the ten baseline items are classified high risk: the default
compliance setting (task 4), enrollment restrictions (task 5), device
compliance policies (task 7), and Conditional Access (task 10).

Conditional Access is blocked unless `-IncludeHighRisk` is supplied. A blocked
item is recorded in the report with a `Blocked` disposition and the reason,
rather than silently omitted.

The default compliance setting, enrollment restriction inventory, and device
compliance policy inventory always run their reads when licensed, even when
high-risk write authorization is withheld. Missing write authorization is
recorded separately as informational `WriteRiskGate` evidence, so the current
tenant state remains visible.

**Task 7 is high risk even though the guide presents it as routine.** Creating a
compliance policy can mark existing devices noncompliant, and if the customer
already operates Conditional Access requiring a compliant device, whether or not
this toolkit created it, those users lose access immediately.

**Conditional Access is the highest blast-radius action in the baseline.** A
policy requiring a compliant device, applied before devices are enrolled and
evaluated, denies access to users and can lock administrators out of the tenant.
The current module creates the policy only after every high-risk gate is
supplied. It ensures the Microsoft Intune Enrollment service principal exists,
creates the policy in the configured default state
(`enabledForReportingButNotEnforced`), and reads the state back. Promotion to
enforcement remains a separate decision after emergency-access exclusions,
device compliance, sign-in evidence, propagation, and rollback are verified.

**Task 4 and task 10 are coupled.** Marking unevaluated devices as not compliant
does nothing on its own, and becomes an access denial the moment the Conditional
Access policy exists. Apply compliance policies and confirm devices are actually
being evaluated before enabling enforcement.

A run refused by a gate still writes its report. The refusal, and the customer
approval reference when one was supplied, are recorded as evidence.

## Prerequisites

- PowerShell 7 or later. Windows PowerShell 5.1 is not supported.
- Microsoft 365 Business Premium or Intune Plan 1. Task 10 additionally needs
  Microsoft Entra ID P1, which Business Premium includes.
- An administrator with the appropriate roles for device management and, for
  task 10, Conditional Access.
- Delegated consent for the full configured Graph permission set in
  `Config\IntuneConfig.psd1`'s `Api.GraphScopes`: six read scopes --
  `User.Read`, `LicenseAssignment.Read.All`,
  `DeviceManagementConfiguration.Read.All`, `DeviceManagementApps.Read.All`,
  `DeviceManagementServiceConfig.Read.All`, and `Policy.Read.All` -- plus
  five write scopes tied to the supported, gated write paths --
  `DeviceManagementApps.ReadWrite.All`,
  `DeviceManagementServiceConfig.ReadWrite.All`,
  `DeviceManagementConfiguration.ReadWrite.All`,
  `Policy.ReadWrite.ConditionalAccess`, and `Application.ReadWrite.All`.
  `Connect-IntuneServices.ps1` requests every one of these scopes at connect
  time for every run, including `-WhatIf`, because Graph consent is fixed at
  authentication rather than re-evaluated per module. The safety gates and
  `ShouldProcess` still decide whether a state-changing call runs.
  Conditional Access listing and readback require the documented
  `Policy.Read.All` plus `Policy.ReadWrite.ConditionalAccess` pair.
  Interactive sign-in also uses the standard `openid`, `profile`, and `email`
  identity scopes. See
  [Authentication](#authentication) for the version history behind this
  scope set.
- The `Microsoft.Graph.Authentication` and `Microsoft.Graph.DeviceManagement`
  PowerShell modules from the same SDK release. Use the
  [version-aligned installation commands](docs/Operator-Guide.md#before-you-run),
  or pass `-AutoInstallModules` to install a missing matching module to
  `CurrentUser` without a prompt. The toolkit keeps an already-loaded
  Authentication version and pins DeviceManagement to it, rather than loading
  an incompatible newer release.

## Authentication

Intune uses the same delegated Microsoft Graph sign-in behavior as Purview.
Supply the administrator UPN for a direct tenant run, or add the customer
tenant's verified domain through `-DelegatedOrganization` for GDAP:

```powershell
.\Deploy-IntuneBestPractice.ps1 `
    -TenantAdminUpn delegatedadmin@partner.onmicrosoft.com `
    -DelegatedOrganization customer.onmicrosoft.com `
    -WhatIf
```

The orchestrator connects once before any setup module runs. It requests the
full configured scope set in `Config\IntuneConfig.psd1`'s `Api.GraphScopes` up
front, before any task runs and regardless of `-WhatIf`, and reuses a cached
Graph context only when the account, every required scope, and the live
tenant (confirmed through `/organization`) all match the run's target -- the
administrator UPN's domain for a direct run, or the customer domain for GDAP.
This tenant check runs for every reuse attempt, not GDAP alone, so a cached
context left over from a different tenant is rejected and reconnected on a
direct run too. For GDAP, the toolkit authenticates directly to the customer
domain.

**Scope-set version history.** Intune 0.2.0's pilot requested only the five
read scopes needed by the read-only assessments implemented at the time.
Intune 0.3.0's authentication rewrite requests the full eleven-scope set as a
single up-front connect, matching Purview's one-connection-per-run model.
Consenting to those scopes does not bypass the product gates. Standard writes
remain subject to `ShouldProcess` and assignment scope, high-risk writes
require the documented approval switches, and
`-EnablePolicyCatalogWrite` still fails closed.

Current Microsoft Graph Authentication modules use Windows Authentication
Manager (WAM) on a supported interactive Windows desktop. A first consent,
missing scope, account change, or customer-tenant switch can still require a
browser prompt. Use `-AutoInstallModules` to install a missing Graph module
(`Microsoft.Graph.Authentication` or `Microsoft.Graph.DeviceManagement`) to
`CurrentUser` without a toolkit prompt.

If a different SDK version or assembly is already loaded, the toolkit stops
with fresh-session recovery guidance instead of reinstalling repeatedly or
attempting to replace loaded assemblies. See
[Graph module version conflicts](docs/Evidence-Troubleshooting.md#graph-module-version-conflicts).
The session guard records the selected SDK version or prerequisite failure;
tenant scopes and sign-in behavior are unchanged.

If sign-in reports **A window handle must be configured**, use the
[interactive-terminal recovery steps](docs/Evidence-Troubleshooting.md#windows-sign-in-needs-a-window-handle).
The toolkit does not silently switch to device-code or app-only authentication.

`-NonInteractive` suppresses toolkit confirmation and module-install prompts.
It does not select application authentication and cannot guarantee a
prompt-free first sign-in. Pre-authenticate in an approved interactive session
before using it. Client IDs, certificates, and client secrets are not accepted;
authentication is delegated UPN/GDAP only.

Setup modules use the orchestrator's verified context and do not reconnect. To
run a setup module directly, establish the Graph connection first in the same
PowerShell session. The [operator guide](docs/Operator-Guide.md) documents the
supported connection and invocation sequence.

## Usage

Preview every assessment and selected write without changing the tenant:

```powershell
cd Products/Intune
.\Deploy-IntuneBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com -WhatIf
```

Apply the standard Microsoft 365 Apps and Android/iOS app-protection baseline
to an approved pilot group:

```powershell
.\Deploy-IntuneBestPractice.ps1 `
  -TenantAdminUpn admin@contoso.onmicrosoft.com `
  -PilotGroupId '<entra-group-object-id>'
```

Do not combine the first high-risk changes into one command. Use the
[staged high-risk commands](docs/Operator-Guide.md#add-high-risk-changes-one-at-a-time)
after customer approval and a [recovery record](docs/Evidence-Troubleshooting.md#recover-a-partial-pilot-deployment)
are complete. Default compliance is a tenant-wide setting even when a pilot
group is supplied. Conditional Access creation stays report-only; enforcement
is a later, separately approved portal decision.

For a GDAP-delegated preview against a customer tenant:

```powershell
.\Deploy-IntuneBestPractice.ps1 `
  -TenantAdminUpn admin@partner.onmicrosoft.com `
  -DelegatedOrganization customer.onmicrosoft.com `
  -AutoInstallModules `
  -WhatIf
```

Every module is independently runnable and takes `-Config` plus its own
switches, so you can iterate on one task without running the orchestrator,
but it requires an already-authenticated Graph context in the same session
(a setup module no longer reconnects Graph itself).

## Output

Each run writes an HTML report and a JSON sidecar to `Reports/`. Both record
every started, created, updated, adopted, skipped, retried, and failed action
with its disposition and reason. Secrets, tokens, and raw tenant exports are
not retained. Pattern-based redaction protects tenant identifiers, tenant
domains, administrator identities, and GUID-shaped identifiers. Review any
service-authored error excerpt before sharing it because arbitrary future error
text is not guaranteed to match a known redaction pattern. Microsoft service
endpoints stay readable so a failure remains diagnosable.

Run reports contain tenant evidence. Keep them in the approved private evidence
location and do not commit or publish them.

The final output prints the full paths of successfully saved
`intune-run-report.html` and `intune-run-log.json`, plus a copyable
`Invoke-Item -LiteralPath` command to open the HTML. The browser never opens
automatically, including with `-NonInteractive`. Reporting also runs during
`-WhatIf`, blocked work, and failures after logging has initialized.
Report-write warnings remain visible and do not replace an earlier deployment
error. An existing file is not proof that the current run saved it.

The `Report` configuration controls the directory and filenames; defaults
remain under the product's `Reports` folder. Reruns overwrite these files.
Preserve the evidence privately before rerunning.

## Configuration

All tunables live in `Config/IntuneConfig.psd1`: the baseline item inventory,
license capability mapping, Graph scopes, assignment defaults, policy catalog
manifest, preflight dispositions, and Conditional Access defaults. Do not
hardcode a policy name, identifier, or duration in a module.

The license SKU and service plan names in that file are **candidates, not
verified facts**. Microsoft catalog names drift, and verifying them is part of
the outstanding work.

## Status and what is outstanding

The product is **Available** at the documented pilot-first scope. Six guide tasks have write-capable paths with `ShouldProcess`, retry, and
structured evidence. Five paths have direct post-write readback; app-protection
targeting and assignment require portal verification. The remaining guided
boundaries are Windows automatic
MDM enrollment, Apple certificate setup or replacement, Managed Google Play,
Windows Backup for Organizations, modern Windows MAM, unsupported compliance
platforms, and the imported policy catalog.

Before broader rollout, complete the per-customer role and GDAP review, confirm
licensing and service availability, and retain pilot evidence. Historical
direct-tenant validation applies to the original write implementation, not to
later authentication or safety-contract changes. The current alignment is
fixture-tested, but a fresh direct/GDAP cold and warm sign-in record and a new
pilot `-WhatIf` remain release follow-ups. Promote Conditional Access only
after report-only sign-in results and emergency-access recovery are verified.
