---
title: Intune configuration reference
layout: default
parent: Intune
---

# Intune configuration reference

`Config/IntuneConfig.psd1` is the source of product behavior. Modules must not
hardcode policy names, licenses, assignment scope, or report paths.

| Section | Purpose | Release note |
| --- | --- | --- |
| `ProductName`, `ProductVersion`, `ManagedByTag` | Product identity and future managed-object ownership marker. | The tag never authorizes adoption by itself. |
| `BestPracticeItems` | Ten guide tasks, priority, module, license capability, risk, and guide mapping. | Task keys are toolkit identifiers, not Microsoft recommendation IDs. |
| `LicenseCapabilities` | Candidate SKU and service-plan mappings. | Candidates require human and pilot verification; catalog names can change. |
| `Api` | Graph v1.0 and beta base URIs, delegated scopes, and required commands. | Requests all eleven configured scopes (six read, five write) at connect time for every run. Runtime gates and `ShouldProcess` still control each write. |
| `Assignment` | Pilot-first and tenant-wide safety policy. | Tenant-wide high-risk assignment is disabled by default. |
| `PolicyCatalog` | Path and required entry count for the normalized 19-payload candidate catalog. | Payload hashes are verified at load time. Every entry remains blocked for apply. |
| `Preflight` | Guided dispositions for unsupported or interactive tasks. | Values must use the approved disposition vocabulary. |
| `ApplePushCertificate` | Pre-expiry warning interval. | `RenewalWarningDays` must be an integer from 1 through 90. |
| `DefaultCompliance` | Device-without-policy treatment and compliance check-in threshold. | The write is high risk; `CheckinThresholdDays` defaults to 30. |
| `ConditionalAccess` | Report-only state, emergency-access review requirement, policy name, and Intune Enrollment app ID. | The current release rejects any default state other than `enabledForReportingButNotEnforced`; promotion to enforcement is a separate portal decision. |
| `AppDeployment`, `AppProtection`, `DeviceCompliance`, `EnrollmentRestrictions` | Desired state for the six supported write paths. | Names, settings, payload paths, assignments, and application targets remain configuration-driven. |
| `Report` | HTML, JSON, and output-directory names. | Reports contain private tenant evidence. |

## Command-line controls

`-Skip*` switches omit modules intentionally; they are not fixes for module
failures. `-NoLicenseAutoDetect` disables automatic SKU checks and reduces the
strength of applicability evidence. `-PilotGroupId` is the safe default
assignment scope for supported writes and is also used to classify assessment
results. A separately approved tenant-wide path requires rollback
acknowledgment and the configuration permission for tenant-wide high-risk
assignment.

`-ClientId`, `-TenantId`, and `-CertificateThumbprint` are not accepted.
Authentication is delegated UPN/GDAP only: supply `-TenantAdminUpn` for the
target administrator identity, and add `-DelegatedOrganization` when the run
is a GDAP-delegated administration of a separate customer tenant. See
[Authentication](../README.md#authentication) for the session-guard and
reconnect behavior.

`-AutoInstallModules` installs a missing `Microsoft.Graph.Authentication` or
`Microsoft.Graph.DeviceManagement` module to `CurrentUser` without prompting.
DeviceManagement is pinned to the Authentication version selected for the
run. An already-loaded Authentication version takes precedence over newer
installed copies; a conflicting loaded module requires a fresh PowerShell 7
session. No module is removed or upgraded in place to bypass that conflict.
`-NonInteractive` suppresses toolkit confirmation and module-install prompts;
without `-AutoInstallModules` it fails fast instead of installing a missing
module, and it never selects application/certificate authentication.

`-IncludeHighRisk`, category enable switches, customer approval, emergency
access confirmation, and rollback acknowledgment are independent gates. One
gate never substitutes for another.

`Report.OutputDirectory`, `Report.HtmlReportFileName`, and
`Report.JsonLogFileName` keep their existing behavior. The final console output
prints the resolved paths only after successful writes and includes a manual
open command for the HTML. Report-write warnings do not turn failed
persistence into a success message or hide an earlier deployment failure.

`-EnablePolicyCatalogWrite` is a reserved fail-closed switch. It never enables
a tenant write today. The catalog source used Graph beta commands, so apply
behavior remains blocked.

### Control state in version 0.3.0

| Control | Current state | Effect |
| --- | --- | --- |
| `-TenantAdminUpn` | Active, required | Selects the expected administrator identity for delegated sign-in and tenant verification. |
| `-DelegatedOrganization` | Active | Supplies the expected customer domain for a GDAP-delegated administration run; Graph authenticates directly to this tenant. |
| `-AutoInstallModules` | Active | Installs a missing `Microsoft.Graph.Authentication` or `Microsoft.Graph.DeviceManagement` module to `CurrentUser` without prompting. |
| `-ConfigPath` | Active | Loads an alternate validated Intune configuration file. |
| `-WhatIf` | Active | Performs assessments and records selected writes as `WillChange` without mutating the tenant. |
| `-NoLicenseAutoDetect` | Active, evidence-reducing | Skips automatic SKU discovery and weakens applicability evidence. |
| `-Skip*` | Active | Intentionally omits the selected module. It does not fix a module failure. |
| `-PilotGroupId` | Active | Assigns supported policies and applications to the approved pilot group and narrows assessment scope. |
| `-AdoptExisting` | Reserved compatibility parameter | Current Intune writers are create-only, leave same-purpose existing objects unchanged, and do not emit `Adopted`. |
| `-IncludeHighRisk` and `-CustomerApprovalId` | Active gate | Opens task 7 and is required by the task 4, 5, and 10 category switches. |
| `-EnableComplianceEnforcement` | Active high-risk gate | Allows `secureByDefault=True` after assessment. |
| `-EnableEnrollmentRestrictions` | Active high-risk gate | Allows the configured Android and iOS/iPadOS restrictions to be created and assigned. |
| `-EnableConditionalAccessEnforcement` | Active high-risk gate | Selects creation of the enrollment Conditional Access policy. The configured default state remains report-only. |
| `-BreakGlassExclusionsConfirmed` | Active high-risk gate | Records the operator's emergency-access confirmation before Conditional Access creation. |
| `-BreakGlassUserIds`, `-BreakGlassGroupIds` | Active, required for task 10 | Writes at least one operator-verified emergency-access user or group into the Conditional Access exclusion list. |
| `-AssignTenantWide` | Active, explicit | Uses all licensed users instead of the pilot group when configuration permits it and rollback is acknowledged. |
| `-EnablePolicyCatalogWrite` | Reserved, fail closed | Always refuses the run. |

`-TenantId`, `-ClientId`, and `-CertificateThumbprint` were removed in version
0.3.0. They no longer exist as parameters on the orchestrator or the Graph
connect helper; supplying them fails parameter binding.

Do not include dormant switches in a normal assessment command. Their presence
does not make a future operation supported.

## Delegated Microsoft Graph permissions

`Connect-IntuneServices.ps1` requests all eleven scopes configured in
`Api.GraphScopes` at connect time, up front, for every run -- including a
`-WhatIf` preview -- because Graph consent is fixed at authentication and is
not re-evaluated per module. Six are read scopes used by assessments,
preflight, and Conditional Access readback:

- `User.Read` for the selected tenant identity fields (`id`, `displayName` and
  `verifiedDomains`) from `/organization`. These fields do not require
  `Organization.Read.All` in a delegated session.
- `LicenseAssignment.Read.All` for subscribed SKU discovery.
- `DeviceManagementConfiguration.Read.All` for compliance-policy inventory.
- `DeviceManagementApps.Read.All` for app-protection inventory and the
  documented `Get-MgDeviceManagement` settings read.
- `DeviceManagementServiceConfig.Read.All` for Apple certificate and enrollment
  restriction inventory.
- `Policy.Read.All` for Conditional Access policy listing and readback.

The tenant-identity permission follows [List organizations](https://learn.microsoft.com/graph/api/organization-list?view=graph-rest-1.0),
checked September 25, 2026. Do not add broader consent solely because the
endpoint is `/organization`; verify the requested fields and authentication
mode first. Application permissions are a different contract.

The remaining five are write scopes used by the supported, gated write paths:

- `DeviceManagementApps.ReadWrite.All` for the M365 Apps and app protection
  write paths.
- `DeviceManagementServiceConfig.ReadWrite.All` for the enrollment restriction
  write path.
- `DeviceManagementConfiguration.ReadWrite.All` for the default compliance and
  device compliance policy write paths.
- `Policy.ReadWrite.ConditionalAccess` for the device-based Conditional Access
  write path.
- `Application.ReadWrite.All` to ensure the Intune enrollment service
  principal exists.

Consenting to a write scope does not execute a write. `ShouldProcess`, license
applicability, assignment scope, ownership checks, and the high-risk gates are
evaluated after connection. Earlier Intune 0.2.0 pilot builds requested only
the original five read scopes above. The 0.3.0 authentication rewrite requests
the full eleven-scope set as a single up-front connect, matching Purview's
one-connection-per-run model. Conditional Access reads use Microsoft's
documented `Policy.Read.All` plus `Policy.ReadWrite.ConditionalAccess`
permission pair; consenting only the write scope can produce `403` responses
when listing or reading policies.

Interactive authentication also uses the standard `openid`, `profile`, and
`email` identity scopes. These support sign-in identity and do not add an
Intune resource permission.

Delegated connections reuse a cached Graph context only when its account,
every required scope, and the live tenant (confirmed through `/organization`)
match the run's target -- exactly like Purview, and unconditionally for both
a direct run and a GDAP run. There is no `ContextScope Process` override: the
default Microsoft Graph PowerShell authentication persistence behavior
applies. Authentication is delegated UPN/GDAP only; no other authentication
mode is available.

## Policy catalog

`Config/PolicyCatalog/catalog.psd1` is the catalog manifest. It records every
payload's stable key, relative path, tier, platform, policy kind, source Graph
profile, original SHA-256 digest, normalized SHA-256 digest, and apply status.

`Modules/Get-IntunePolicyCatalog.ps1` verifies the manifest and payloads before
returning catalog metadata. It rejects path traversal, duplicate keys or paths,
hash mismatches, invalid JSON, unexpected Graph discriminators, exported
root-level IDs and timestamps, assignments, and group IDs.

The 19 JSON payloads are candidate configuration input, not tenant evidence and
not an approved desired state. They are separate from the approved compliance
payloads under `Config/CompliancePayloads`. Contributor reuse is approved. Do
not change an entry's `ApplyStatus` without the recorded product-owner,
security, permission, API, and pilot decisions.

## Changing configuration

Syntax-check the data file after editing it:

```powershell
pwsh -NoProfile -Command "Import-PowerShellDataFile '.\Config\IntuneConfig.psd1' | Out-Null"
```

Changing a default, task scope, permission, guided workflow, risk, assignment,
or report field requires a full `-WhatIf` review and an approved pilot before
production use. Repository contributors must also follow the private
maintainer verification process before promotion.
