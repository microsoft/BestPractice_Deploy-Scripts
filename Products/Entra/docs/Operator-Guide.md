---
title: Entra operator guide
parent: Microsoft Entra
layout: default
nav_order: 2
permalink: /entra/operator-guide/
---

# Entra operator guide

Use this guide to move from a first assessment to an approved, report-only
Conditional Access pilot. The toolkit can make real tenant changes.
Report-only policies evaluate sign-ins but do not enforce protection.
Existing customer policies continue to apply.

## Before you run

- Use PowerShell 7 in an interactive desktop terminal, not Windows
  PowerShell 5.1 or a background agent process.
- Keep the full `Products\Entra` folder from one approved release. Do not
  mix configuration templates, scripts, or documentation from different versions.
- Confirm Business Premium or the appropriate Microsoft Entra ID P1
  entitlement for the selected Conditional Access capabilities. Configuration
  selection is not proof of licensing. P2 risk policies are not deployed.
- Obtain authorization for the target tenant and verify the effective
  directory roles and delegated Graph permissions needed for the selected
  operations. See the [coverage](Coverage.md) and
  [Security Defaults API record](Security-Defaults-Transition.md#api-and-validation-record).
- Install `Microsoft.Graph.Authentication` for the current user, or approve
  the toolkit's missing-module prompt. `-AutoInstallModules` permits that
  installation without a toolkit prompt; it is not permission to change the tenant.
- Choose a private evidence location. Reports and private configuration must
  not be committed or published.

The orchestrator connects Graph once. It requests `Api.GraphScopes` from
`Config\EntraConfig.psd1`, including the configured write scopes even during
`-WhatIf`. Consent does not authorize a write: the configuration, approval
gates, and `ShouldProcess` still control tenant changes.

Use an existing approved emergency-access arrangement for a pilot.
Preparing privileged accounts and proving recovery are separate identity-owner
tasks, not something a successful report can substitute for.

## First read-only preview

From the repository root:

```powershell
cd .\Products\Entra
.\Deploy-EntraBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -WhatIf
```

No pilot group or high-risk switches are needed for this discovery run.
Complete Microsoft sign-in in the interactive window and confirm the expected
tenant. Read the numbered stages and final module summary. A blocked
Conditional Access stage is expected when emergency-access exclusions or
write approvals have not been supplied. Failed reads still need investigation.

The toolkit never disables Security Defaults. If its state is enabled or
unknown, tenant writers stay assessment-only. Follow the
[transition procedure](Security-Defaults-Transition.md) rather than disabling
existing protection to make a preview look successful.

## Prepare private configuration and a pilot

Copy the complete `Config\EntraConfig.psd1` to an approved private location
outside the repository, then supply its path through `-ConfigPath`.
Edit the existing fields in that copy, not a replacement partial hashtable.
Keep the following settings for the initial pilot:

| Setting | Preparation |
|---|---|
| `ConditionalAccess.DefaultState` | Keep `enabledForReportingButNotEnforced`. |
| `ConditionalAccess.RequireBreakGlassExclusion` | Keep `$true`. |
| `ConditionalAccess.BreakGlass.ExcludeUserIds` / `ExcludeGroupIds` | Supply independently verified emergency-access object IDs. Do not use display names or assume an empty list proves no accounts exist. |
| `ConditionalAccess.BreakGlass.CreateAccountIfMissing` | Keep `$false` when using verified existing accounts. Account creation requires separate preparation and manual completion. |
| `TenantSecurity.*.Apply` | Keep `$false` unless the individual tenant-wide change has its own approval and recovery plan. |
| `Assignment.AllowTenantWideAssignmentForHighRisk` | Keep `$false` for the pilot. |

In the Entra admin center, prepare a dedicated security group containing only
approved pilot users and record its object ID. Confirm membership, owners,
licenses, and the intended test accounts before using it as `-PilotGroupId`.
Keep emergency-access identities out of normal pilot activity and verify
their exclusions independently.

The pilot group narrows all-users-style templates, not every policy.
Role- and app-scoped templates retain their configured targeting. In
particular, the optional phishing-resistant admin policy targets privileged
roles, not the intersection of those roles and the pilot group. Review
every selected policy's actual conditions before apply.

The standard admin MFA and Microsoft admin-portal policies also target
directory roles across the tenant, without adding pilot-group members.
Azure-management MFA targets all users for that application, even when a
pilot group is supplied. New policies remain report-only unless you change
the configured default. Do not treat the pilot switch as a cap on these
role- or application-scoped policies.

Optional P1 hardening requires method readiness; P2 risk controls remain out
of scope. App-protection enforcement depends on compatible applications and
assigned Intune app-protection policies. See [Scenarios](Scenarios.md).

## Preview the approved deployment

Only after existing protection and emergency access have been independently
verified, or an approved Security Defaults transition has completed:

```powershell
.\Deploy-EntraBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -ConfigPath 'C:\ApprovedConfig\EntraConfig.psd1' `
    -IncludeHighRisk -CustomerApprovalId 'CHG0001234' `
    -BreakGlassExclusionsConfirmed -RollbackAcknowledged `
    -PilotGroupId '<entra-group-object-id>' `
    -WhatIf
```

Replace placeholders with the approved private configuration, change
reference, and group ID. The confirmation switches record operator decisions;
they do not create a pilot group, test recovery, assign emergency roles, or
prove active replacement protection.

Review the HTML report for scope, existing-policy collisions, failed reads,
and blocked work. `TenantWritesAllowed=True` only means the Security Defaults
gate passed. It is not overall deployment authorization.

## Apply and verify

After the preview is reviewed and apply is separately approved, run the exact
same command with the same private configuration, tenant, and scope,
omitting only `-WhatIf`. Keep the default report-only policy state.

Verify the resulting policies, state, targeting, emergency exclusions, and
readback evidence in the Entra admin center. Rerun with `-WhatIf` and
investigate unexpected changes. Existing-policy matches can require manual
review even when fields match; `-AdoptExisting` does not bypass review-only
policies or ambiguous matches.

Use the current configuration's `ReviewExistingOnly = $true` for admin MFA,
admin portals, Azure management, device-or-MFA and browser-session policies.
Old custom references without this gate must be updated before running.
The toolkit leaves existing matches unchanged, including with adoption.
Review their effective scope and grants manually before migrating them.
Browser-session comparisons include the session controls and device filter;
successful readback is no longer based on policy state alone.

Enforcement is a separate change after review of report-only sign-ins,
application compatibility, user readiness, and tested recovery. Do not leave
a tenant relying on report-only policies after removing existing protection.
Tenant-wide assignment also requires explicit configuration permission and
`-AssignTenantWide`; it is not a shortcut around pilot preparation.

## GDAP and unattended use

For an approved delegated administration relationship, add the customer
tenant's verified domain:

```powershell
.\Deploy-EntraBestPractice.ps1 `
    -TenantAdminUpn delegatedadmin@partner.onmicrosoft.com `
    -DelegatedOrganization customer.onmicrosoft.com `
    -WhatIf
```

The connection must verify the customer tenant, not just the administrator's
home tenant. `-NonInteractive` suppresses toolkit prompts but does not provide
app-only authentication or guarantee a prompt-free first sign-in. Standalone
setup modules require a verified Graph connection in the same session.

## Reports and stopping conditions

The final output announces successfully saved HTML and JSON run reports and
prints a manual open command. Defaults are `Reports\entra-run-report.html`
and `Reports\entra-run-log.json` under the product folder. The emergency-access
module can also write `Reports\entra-breakglass.json`; this contains resolved
IDs for module coordination and is not proof that recovery works.

Preserve each run's files privately before rerunning because the default
filenames are overwritten. Reporting can still finish after deployment
fails; a saved report does not mean a successful deployment.

Stop apply or expansion for a wrong tenant, an unreadable prerequisite,
unverified emergency access, unexpected targeting, failed readback, or a
`LockoutRisk`/`Indeterminate` health verdict. Do not add skip switches or
broader permissions to hide the failure. Follow
[evidence and recovery](Evidence-Troubleshooting.md) with the identity owner.
