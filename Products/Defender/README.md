---
title: Microsoft Defender
nav_order: 3
has_children: true
permalink: /defender/
---

# Microsoft Defender Best Practice Toolkit

> **Available at the approved release scope.** Default execution is read-only.
> The ASR Audit policy is the only managed tenant configuration path with
> approved pilot evidence and requires explicit switches plus an approved
> pilot security group. Safe Attachments, quarantine, MDE advanced, and MDCA
> writes remain `GuidedOnly`.

## Scope

The product boundary is designed for low-touch Microsoft Defender work across:

- Microsoft Defender for Office 365 and Exchange Online protection.
- Defender for Business and related Intune posture.
- Microsoft Defender for Endpoint advanced settings.
- Microsoft Defender for Cloud Apps discovery and low-touch posture.

The current release foundation performs tenant identity and API/workload
capability preflight, permission planning, safety-gate validation, structured
evidence, and guided-only classification. It also provides the explicitly
enabled ASR Audit configuration path described under Safety gates. Licensing
prerequisites are documented with Microsoft Learn links; the toolkit does not
infer entitlement from SKU or service-plan names or treat other write
endpoints as supported.

## Prerequisites

- PowerShell 7 or later on Windows.
- An approved tenant administrator or delegated administrator.
- Microsoft Graph PowerShell modules providing `Connect-MgGraph`,
  `Invoke-MgGraphRequest`, and `Get-MgContext`.
- Delegated consent and workload roles for the selected operations.

See [Deployment](docs/deployment.md) for authentication, module flow, safety
gates, and recovery. See
[Permissions and supportability](docs/permissions.md) for Graph scopes,
Exchange RBAC, licensing references, and API boundaries.

## Deployment parameters

The tables below cover every parameter exposed by
`Deploy-DefenderBestPractice.ps1`. Switches default to off. Optional strings
default to empty unless a default is stated.

### Tenant, authentication, and configuration

| Parameter | Required/default | Purpose |
|---|---|---|
| `-TenantAdminUpn` | Required | Sign-in UPN used to derive and verify the expected tenant domain. |
| `-TenantId` | Optional GUID | Targets a tenant explicitly. Required with certificate arguments. |
| `-DelegatedOrganization` | Optional domain | Targets the customer organization for delegated Graph and Exchange Online administration. Graph uses this domain when no explicit `-TenantId` is supplied. |
| `-ConfigPath` | `Config\DefenderConfig.psd1` | Uses an alternate Defender configuration data file. |
| `-UseDeviceAuthentication` | Off | Uses delegated device code instead of the default browser flow for Graph and Exchange Online. |
| `-AutoInstallModules` | Off | Allows the connection helper to install missing supported PowerShell modules. |
| `-ClientId` | Optional GUID | Certificate client ID. Certificate execution is blocked until app-only operation evidence is approved. |
| `-CertificateThumbprint` | Optional 40-character hexadecimal value | Certificate thumbprint. Supply it with `-TenantId` and `-ClientId`; the current preview then fails closed before app-only connection. |
| `-NonInteractive` | Off | Requests noninteractive authentication. The current preview rejects this path because app-only authorization is not approved. |

### Module selection

| Parameter | Default | Purpose |
|---|---|---|
| `-SkipPreflight` | Off | Skips Defender preflight capability assessment. Use only when its evidence is not required for the selected run. |
| `-SkipMdoEop` | Off | Skips the Defender for Office 365 and Exchange Online baseline module. |
| `-SkipDefenderForBusiness` | Off | Skips Defender for Business and Intune ASR assessment or configuration. |
| `-SkipMdeAdvanced` | Off | Skips the guided Microsoft Defender for Endpoint advanced-settings module. |
| `-SkipDefenderForCloudApps` | Off | Skips the guided Defender for Cloud Apps module. |

### State and safety controls

| Parameter | Default | Purpose and interaction |
|---|---|---|
| `-AdoptExisting` | Off | Allows supported state-management definitions to adopt an unmanaged object after exact checks. It never permits quarantine-policy adoption. |
| `-IncludeHighRisk` | Off | Opens the high-risk category gate. It does not make a GuidedOnly or unimplemented operation writable. |
| `-RollbackAcknowledged` | Off | Confirms recovery planning. Required for mail-flow-impacting selection and irreversible ASR recovery. |
| `-EnableMailFlowImpactingChanges` | Off | Selects the guarded MDO/EOP write category. Current outbound auto-forwarding, Safe Attachments, and quarantine production writes remain `GuidedOnly`. Requires `-IncludeHighRisk` and `-RollbackAcknowledged`. |
| `-EnableAutomatedRemediation` | Off | Selects the high-risk MDE remediation category. Current MDE advanced automation remains guided-only. Requires `-IncludeHighRisk`. |
| `-EnableAsrAuditPolicy` | Off | Creates or reuses the toolkit-owned ASR Audit policy and assigns it only to `-PilotGroupId`. Cannot be combined with recovery. |
| `-RecoverAsrAuditPolicy` | Off | Permanently deletes the captured toolkit-owned ASR Audit policy after exact isolation checks. Requires `-RecoveryPolicyId`, `-PilotGroupId`, and `-RollbackAcknowledged`. |
| `-EnableAsrBlockMode` | Off | Reserved high-risk gate. Block mode is not implemented; even with `-IncludeHighRisk`, the run stops before a tenant change. |
| `-EnableMdcaEnforcement` | Off | Selects the high-risk MDCA enforcement category. Current MDCA automation remains guided-only. Requires `-IncludeHighRisk`. |
| `-CloudDiscoveryReviewed` | Off | Records that cloud-discovery results were reviewed for the guided MDCA workflow. It does not authorize enforcement. |
| `-PilotGroupId` | Optional GUID string | Approved security-group ID required for ASR Audit apply and recovery. The orchestrator validates it before requesting write scopes. |
| `-RecoveryPolicyId` | Optional GUID string | Captured managed ASR policy ID required only for recovery. |

Because the script uses `SupportsShouldProcess`, it also accepts the common
`-WhatIf` and `-Confirm` parameters. Start with `-WhatIf`. Confirmation does
not bypass operation status, permission, ownership, readback, or recovery
gates.

## Safe preview

Graph authentication is bound to the requested operator and tenant. An explicit
`-TenantId` takes precedence; otherwise the target is `-DelegatedOrganization`
or the domain in `-TenantAdminUpn`. Cached sessions must match the operator,
delegated authentication mode, required scopes and verified tenant before
reuse. Selecting another account during sign-in stops the run before deployment.
This does not grant GDAP roles or consent; those remain operator prerequisites.

```powershell
cd Products\Defender
.\Deploy-DefenderBestPractice.ps1 `
  -TenantAdminUpn admin@contoso.onmicrosoft.com `
  -WhatIf
```

## Operator guides

- [Deployment](docs/deployment.md)
- [Permissions and supportability](docs/permissions.md)
- [Scenarios and boundaries](docs/scenarios.md)
- [Best-practice scope and guided references](docs/best-practices.md)
- [Evidence and reports](docs/evidence.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Read-only deployment playbook](docs/Defender-Deployment-Playbook.md)
- [Adoption readiness guide](docs/Defender-End-User-Adoption-Guide.md)

Every run is intended to produce a redacted JSON sidecar and HTML report under
`Products\Defender\Reports\`. See [Evidence and reports](docs/evidence.md) for
the schema, verdicts, retry records, redaction boundary, and evidence-retention
rules.

If a module contains both failed and blocked actions, its summary is `FAILED`.
The HTML report and JSON sidecar use the same precedence; a blocked action
does not hide an operation or readback failure.

## Safety gates

Default execution is read-only. Unsupported automation and unproven writes
remain blocked or `GuidedOnly`. ASR Audit apply is the only approved managed
configuration path. Recovery is irreversible and separately gated. Review the
parameter table before invocation and follow [Deployment](docs/deployment.md)
for the complete apply, collision, failure, and recovery behavior.

## Explicit exclusions

This release does not automate custom KQL, third-party SaaS credentials,
recurring SOC operations, custom OAuth policy authoring, SaaS DLP architecture,
SSPM onboarding, BitLocker enforcement, Conditional Access blocking, or ASR
block mode. See [Best-practice scope and guided references](docs/best-practices.md)
for the canonical coverage matrix and Microsoft deployment-guide links.

Pilot evidence must remain in the approved private validation location and must
not be committed to this repository.
