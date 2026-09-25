---
title: Security Defaults and app-protection migration
parent: Microsoft Entra
layout: default
nav_order: 4
permalink: /entra/security-defaults-transition/
---

# Security Defaults and app-protection migration

Entra reads Security Defaults before setup and again at each selected
write boundary. It never enables or disables Security Defaults. If the state
is enabled or cannot be verified, all toolkit tenant writes are withheld:
Conditional Access creation/adoption, emergency-account creation and the four
tenant-setting opt-ins. Supported reads and local reporting can continue
unless another prerequisite or service failure stops the run.

This gate also applies to standalone modules. A supplied context value,
`-AdoptExisting`, `-NonInteractive`, a tenant-setting `Apply` flag or all CA
approval switches cannot bypass the live state check. `-WhatIf` remains
mandatory for preview: disabled Security Defaults is not approval to write.

## Start without changing protection

In an interactive PowerShell 7 terminal, from `Products\Entra`:

```powershell
.\Deploy-EntraBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -WhatIf
```

For GDAP, add `-DelegatedOrganization` with the customer domain. Confirm the
target tenant, consent, roles and licensing independently. The configured
Graph scopes, including write scopes, are still requested at sign-in even
during `-WhatIf`; no new scope was added for the Security Defaults read.

Review `Reports\entra-run-report.html` and `Reports\entra-run-log.json`.
After each successful report write, the final output prints its full path
and a command to open the HTML manually. This includes blocked and `-WhatIf`
runs; report generation does not mean the tenant is ready for deployment.
If a report write fails, retain the console warning and do not use an older
file at that path as evidence of this run.

The numbered tenant-discovery stage shows this state explicitly. The
prerequisite stage also explains the apply parameters, even on a first preview
without configured emergency-access IDs. See the
[preview-to-apply checklist](../README.md#usage). No console instruction or
approval switch disables this safety gate.

| Observed state | Meaning and operator action |
| --- | --- |
| `SecurityDefaultsState=Enabled` | Assessment-only. Keep protection in place and plan the transition; do not disable it just to clear this gate. |
| `SecurityDefaultsState=Disabled` | Only this readiness check passed. Existing approval, pilot, recovery, license and role requirements still apply. It does not prove replacement protection is active. |
| `SecurityDefaultsState=Unknown` | The GET failed, was unauthorized, or did not return Boolean `isEnabled`. Writes are blocked. Verify effective access/service state and rerun. |

`TenantWritesAllowed` in the evidence describes this gate only, not overall
authorization. The health summary includes the state and never returns
`Healthy` when it is enabled or unknown. With no more severe finding, enabled
produces `DriftDetected` with a blocked disposition, and unknown produces
`Indeterminate`. Enabled Security Defaults is not itself a security defect;
it is a blocker for this toolkit's deployment path. A module or run may
complete while reporting blocked work. Read the dispositions and health
verdict, not just process completion.

The reads are point-in-time checks, not a transaction with the service.
Earlier writes are not undone if the state changes later or another operation
fails. Retain before-state evidence and an approved recovery plan.

## Do not assume the P1 baseline replaces Security Defaults

Microsoft documents these Security Defaults protections. The table is a
review checklist, not an assertion of identical policy behavior or licensing
equivalence. Verify the current tenant and Microsoft guidance before cutover.

| Security Defaults protection | Current toolkit coverage | Required transition review |
| --- | --- | --- |
| Require everyone to register for MFA | Registration-protection policy, but no complete enrollment workflow | The new policy requires MFA during member registration; it does not enroll everyone, configure methods or issue Temporary Access Passes. Confirm bootstrap and coverage for all intended users. |
| Require administrator MFA | Admin/portal templates | Compare effective role/user targets, exclusions and enforcement. Pilot targeting is not organization-wide replacement. |
| Require user MFA when Microsoft determines it necessary | All-user MFA template, with different targeting/trigger semantics | Do not claim to reproduce Microsoft's prompting logic. Compare the intended user experience and coverage. |
| Block legacy authentication | Legacy-client template | Verify protocols, all affected users and active enforcement. |
| Block device code flow | Dedicated P1 template, report-only by default and pilot-scoped | Inventory dependencies, review sign-in impact and independently approve enforcement/exception coverage. A report-only pilot is not active tenant-wide protection. |
| Protect privileged activities, such as Azure management | Azure-management/admin-portal templates | Validate actual applications, role targets and sign-in behavior. |

P1 provides Conditional Access capability. It does not prove that this
particular template set reproduces every Security Defaults behavior.
Risk-based policies and Microsoft-managed policy eligibility have their own
requirements; check the current documentation and tenant rather than treating
P1/P2 or a product license as a blanket coverage result.

## Approved transition, not automatic disabling

1. Keep Security Defaults enabled during discovery. Inventory existing
   customer and Microsoft-managed policies, authentication methods, MFA
   registration, legacy/device-code clients and emergency access.
2. Agree the coverage matrix, customer owner, recovery route and cutover
   criteria. Verify emergency accounts independently using Microsoft's
   current guidance; a directory ID is not a recovery test.
3. Test the intended replacement in an isolated, approved nonproduction
   environment. Review policy semantics, actual targets and sign-in effects.
   Report-only is useful evaluation but does not enforce replacement controls.
4. Have the authorized identity owner perform an approved transition using
   current Microsoft guidance. Microsoft says to immediately enable replacement
   Conditional Access protection after disabling Security Defaults. Do not
   disable it and then wait for a later toolkit pilot or report-only review.
   Confirm Microsoft-managed policies' actual availability, state, exclusions
   and coverage; do not assume they are already active.
5. After the transition is independently confirmed, rerun `-WhatIf`. Review
   the exact configuration and pilot scope before a separately approved apply.
   Keep the default new-policy state report-only for toolkit evaluation;
   enforcement promotion remains a separate decision.

This toolkit does not execute the cutover, certify protection equivalence,
enable Microsoft-managed policies, or automatically restore previous writes.
If replacement coverage cannot be demonstrated, leave the existing protection
in place and record the deployment as blocked.

The 0.4.0 P1 additions reduce documented coverage gaps but do not automate this
transition or prove equivalence. The optional phishing-resistant admin policy
also requires method readiness; its P1 authentication strength is not a P2
risk policy. See [the additions and prerequisites](Coverage.md#p1-additions-and-p2-boundary).

## Corrected app-protection policy and existing tenants

New policies use the name **Require app protection policy** and the
`compliantApplication` grant. Android and iOS are included without excluding
those same platforms. The configuration key and JSON filename
`require-approved-client-apps` remain stable for compatibility; they do not
mean the retired `approvedApplication` control is requested.

The current Microsoft migration notice recommends only **Require app
protection policy** for new policies. Its dated notice places policies using
the approved-client grant in a read-only state from June 30, 2026, while
allowing disable/delete and continued enforcement of existing enabled
policies. Some procedural text on the same page still mentions both controls;
use the current new-policy notice and obtain product clarification for legacy
service behavior rather than assuming an old edit recipe works.

The toolkit recognizes both the corrected display name and the legacy name
**Require approved client apps or app protection policies**. It reads all
policy pages and refuses ambiguous matches. It does not automatically rename,
repair or duplicate either existing policy, including with `-AdoptExisting`.
Incorrect mobile filters or grant logic produce `GuidedOnly` migration
evidence instead of a compliance claim. Health recognizes the legacy policy
as present but records `LegacyPolicies` and requires migration review.

For an existing policy:

1. Record its exact state, targets, grants, exclusions and customer settings
   privately. Inspect the actual grant: the old name alone does not mean it
   contains the retired control.
2. Establish compatible client applications and assigned Intune app-protection
   policies, licensing and user readiness. The Entra policy does not create
   those Intune policies. Unsupported apps can be blocked after enforcement.
3. Agree a manual, staged migration in an isolated test scope. Removing
   conflicting exclusions can activate protection for users who were
   previously outside effective scope. Do not silently broaden an enforcing
   policy or edit/delete a retired control based only on its display name.
4. Verify platforms, application behavior, grants and emergency-access
   exclusions before any production change or rename. Rerun assessment to
   confirm the resulting policy. Multiple current/legacy matches remain
   blocked until the identity owner reconciles them.

Custom configuration must retain the current policy reference's
`LegacyDisplayNames` and `ReviewExistingOnly = $true`. Older custom references
fail with an upgrade message rather than losing migration protection.

## API and validation record

Source verification date: **2026-09-21**. No live tenant validation is implied.

| Operation | Surface and permission | Evidence / failure behavior |
| --- | --- | --- |
| Read Security Defaults | Graph v1.0 `GET /policies/identitySecurityDefaultsEnforcementPolicy`; delegated `Policy.Read.All`, already configured | Require Boolean `isEnabled`. Only normalized state and HTTP status are logged; malformed/unauthorized/unavailable results are `Unknown`. Shared bounded retry applies to transient failures, not 403. |
| Create corrected CA policy | Existing Graph v1.0 CA collection and `Policy.ReadWrite.ConditionalAccess` | Existing operator roles and high-risk gates still apply. Requires disabled Security Defaults, pilot scope and exclusions. New app-policy readback compares state, grants/operator, targets/platforms and required exclusions. |
| Existing app-policy migration | Human-approved workflow, not a new API writer | No automatic mutation by this change. Preserve customer settings until the approved migration is verified. |

The GET documentation lists `Policy.Read.All` for delegated and application
access. This product remains delegated UPN/GDAP only; API permission support
does not add an authentication mode. The GET method page does not establish
a tested minimum directory/GDAP role for every customer. Verify effective
access in the approved pilot instead of inventing a new role requirement.

Offline tests cover enabled/disabled/unknown state, missing/null/non-Boolean
responses, 403, bounded transient retry, standalone writers, full orchestration,
WhatIf, reruns, partial failure, corrected readback, existing aliases,
pagination, duplicate blocking and HTML/JSON evidence. Fresh direct/GDAP
pilot preview, app/device behavior, effective role/license checks and manual
transition/recovery evidence remain human release gates.

## Microsoft references

- [Security Defaults and moving to Conditional Access](https://learn.microsoft.com/entra/fundamentals/security-defaults)
- [GET Security Defaults policy](https://learn.microsoft.com/graph/api/identitysecuritydefaultsenforcementpolicy-get?view=graph-rest-1.0)
- [Approved-client grant migration](https://learn.microsoft.com/entra/identity/conditional-access/migrate-approved-client-app)
- [Microsoft-managed Conditional Access policies](https://learn.microsoft.com/entra/identity/conditional-access/managed-policies)
- [Report-only evaluation](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-report-only)
- [Emergency-access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)
