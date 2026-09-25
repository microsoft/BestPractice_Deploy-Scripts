---
title: Defender deployment
parent: Microsoft Defender
nav_order: 1
---

# Defender deployment

Microsoft Defender is **Available at the approved release scope**. The
deployment script performs Graph tenant-identity and API/workload capability
preflight, then records licensing documentation links and guided-only
decisions. Default execution is read-only and does not infer licensing from
SKU names. The ASR Audit policy is the only managed tenant configuration path
with approved pilot evidence and requires explicit switches plus an approved
pilot security group.

## Safe preview

The [README parameter tables](../README.md#deployment-parameters) list every
orchestrator parameter, default, and interaction. Start with the read-only
preview:

```powershell
cd Products\Defender
.\Deploy-DefenderBestPractice.ps1 `
  -TenantAdminUpn admin@contoso.onmicrosoft.com `
  -WhatIf
```

Certificate-based authentication and `-NonInteractive` execution are blocked in
this release. Use delegated sign-in through browser authentication or device
code flow.

### Browser authentication

Browser authentication is the default path. Use an explicit tenant and a
process-scoped context:

```powershell
Connect-MgGraph `
  -TenantId 'contoso.onmicrosoft.com' `
  -Scopes 'User.Read' `
  -ContextScope Process `
  -NoWelcome
```

Run it from a standalone PowerShell 7 process. An interactive browser prompt
may appear to succeed even when WAM cannot hand the token back to PowerShell.

### Device code fallback

If browser authentication or WAM is unavailable, use:

```powershell
Connect-MgGraph `
  -TenantId 'contoso.onmicrosoft.com' `
  -Scopes 'User.Read' `
  -ContextScope Process `
  -UseDeviceAuthentication `
  -NoWelcome
```

Complete the code at [microsoft.com/devicelogin](https://microsoft.com/devicelogin).
Device code flow does not bypass delegated consent, licensing, workload
availability, or the Defender guided-only safety boundary. To select this path
for the orchestrator, add `-UseDeviceAuthentication` to the deployment command.

### Operator and delegated-customer verification

The toolkit passes the explicit `-TenantId` to Graph when supplied. Otherwise
it uses the `-DelegatedOrganization` customer domain, or the administrator UPN
domain for a direct tenant run. For GDAP, supply the customer domain and sign
in with the requested partner operator. An explicit tenant ID must identify
the same customer whose domain is being verified.

Cache reuse requires the requested account, delegated authentication and all
operation-scoped permissions. The connected organization's ID and verified
domains must also confirm the requested tenant. A different account or tenant
causes a fresh connection; an unreadable tenant check fails closed.
After sign-in, the actual Graph account must match `-TenantAdminUpn`.
Preflight checks that identity again before recording successful capability
evidence. No tenant configuration changes occur during these checks.

The scopes and GDAP requirements are unchanged. Confirm effective roles and
consent in an approved pilot; offline tests do not establish customer access.
The target is passed through the documented
[`Connect-MgGraph` tenant parameter](https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0).

The default path is read-only. `-IncludeHighRisk`, `-RollbackAcknowledged`,
pilot-group identifiers, and the relevant category switches are required for
future high-impact work; they do not authorize the current guided-only operations.
`-EnableAsrBlockMode` is a reserved safety gate. Block mode is not implemented,
so supplying that switch first requires `-IncludeHighRisk` and then stops the
run before tenant changes. Satisfying the high-risk gate does not enable Block
mode. Audit mode is the only supported managed ASR configuration.

Before permission planning or Microsoft Graph connection, the orchestrator
rejects conflicting ASR apply and recovery switches, invalid pilot-group or
recovery-policy identifiers, and recovery without explicit rollback
acknowledgment. These deterministic failures record blocked evidence without
starting a write-scope consent request.

## Exchange Online protection boundary

The MDO/EOP module uses a separate delegated Exchange Online session because a
Microsoft Graph context does not establish Exchange connectivity. Browser/WAM
is the default. `-UseDeviceAuthentication` selects device code explicitly, and
`-DelegatedOrganization` targets a delegated customer organization. The module
verifies the target through Exchange organization and accepted-domain
readbacks before reading the built-in `Default` outbound spam-filter and ATP
policies.

The outbound auto-forwarding slice can report `AlreadyCompliant`, `Blocked`, or
`GuidedOnly`. It captures the tenant's actual prior value without requiring
setter permission. Immediately before an approved write, it verifies the
operator with `Get-ManagementRoleAssignment -RoleAssignee`; it never assigns a
role. The managed-write, retry, exact-readback, and recovery path is present
but cannot dispatch while `mdo-auto-forward-apply` remains configured as
`GuidedOnly`.

The Safe Attachments slice separately reads `EnableATPForSPOTeamsODB` and no-ops
when the value is already `$true`. It verifies effective RBAC for that exact
setter parameter only before an approved write. Its prepared write uses the
same built-in-object, `ShouldProcess`, retry, exact-readback, and recovery
contracts. The production operation remains `GuidedOnly`; a readback
disagreement is blocked with guidance to allow the documented propagation
window before an operator decides whether to restore the captured prior
Boolean. The setting covers SharePoint, OneDrive, and Teams together, so there
is no separate Teams write.

The quarantine slice enumerates quarantine policies and selects the exact
custom policy name `SMBTool-Quarantine-LimitedAccess`. The configured desired state uses limited
access (`EndUserQuarantinePermissionsValue = 43`), enables end-user spam
notifications, excludes blocked-sender messages from notifications, and makes
no protection-policy assignments. Because the module never creates an
assignment, a policy it creates does not affect any recipient until an
administrator assigns it in an anti-spam, anti-phishing, anti-malware, or Safe
Attachments policy. The module also cannot read existing assignments, so it
cannot tell whether a policy that already exists is in use. Production write
dispatch remains `GuidedOnly`.

A same-name policy that the toolkit does not own blocks the run.
`-AdoptExisting` does not lift that block for quarantine policies: because the
existing policy's references cannot be read, updating its end-user permissions
could change what recipients can do with quarantined mail. Rename or remove the
existing policy, or configure a different quarantine policy name, then re-run.
A configured name that differs from an existing policy only by capitalization
is also blocked, because Exchange Online treats those as the same policy and
would reject the create.

The module supports creation and compliant no-op only. If a policy the toolkit
already owns differs from the selected state, the run blocks rather than call
`Set-QuarantinePolicy`. This protects recipients when an administrator has
assigned the policy to anti-spam, anti-phishing, anti-malware, or Safe
Attachments after creation. The toolkit cannot see those references, so it
does not update any existing quarantine policy. Restore the selected values
manually after reviewing assignments, or configure a different policy name.

Creation remains unavailable unless `mdo-quarantine-policy-apply` is verified
and is also present in the permission plan selected for the run. Promoting the
global operation record alone does not authorize a write.

If the quarantine slice cannot proceed, the Safe Attachments and outbound
auto-forwarding assessments still run and record their evidence; the module
then reports the quarantine failure and the overall run fails. A configuration
that does not define `DefenderForOffice365.QuarantinePolicy` records a skipped
quarantine entry and the remaining assessments continue.

Quarantine message release is not baseline configuration and remains outside
the module. Built-in quarantine policies are never changed. AIR pending action
approval remains a manual Defender portal workflow because Microsoft does not
expose a supported approval API or cmdlet.

## Validation lifecycle

The cumulative SFI review is reconstructed from the legacy and current Defender
pull-request evidence in the private historical reconciliation record. It
covers source evidence, deterministic tests, review findings, remediation, and
documented operating boundaries without changing original GitHub review
states. Operation-specific tenant evidence and promotion gates remain separate.

## Module flow

The orchestrator invokes preflight, MDO/EOP, Defender for Business, MDE
advanced, and Defender for Cloud Apps modules as separate script invocations
in sequence within the current PowerShell runspace. Each module is also
independently runnable on its own. A module that is skipped or unavailable
writes its exact continuation guidance to the run log.

A standalone ASR write requires a context containing the verified apply or
recovery operation from the selected permission plan. Supplying a Microsoft
Graph request alone does not authorize a write.

Authorization, validation, ownership-collision, and other deterministic module
failures are fail-fast. The orchestrator records the failed module and does not
dispatch later modules. Its cleanup path still writes the available redacted
JSON and HTML evidence so the deployment team can review the partial run.
