---
title: Microsoft Entra
layout: default
nav_order: 5
has_children: true
permalink: /entra/
---

# Microsoft Entra Best Practice Toolkit

> ⚠️ **Write-capable. Pilot first, and keep a break-glass account.**
> This product creates real Conditional Access policies in your tenant. Every
> new policy is **report-only** by default and the default configuration
> requires an emergency-access exclusion. Configuration and existing enforcing
> policies still matter; this is not a lockout guarantee. Security Defaults
> must be verified disabled before any tenant write. The toolkit never disables
> it or performs the transition automatically.

PowerShell automation that deploys the **Conditional Access baseline** from the
Microsoft **Identity Protection Best Practice Deployment** guide for a Microsoft
365 **Business Premium** tenant (Microsoft Entra ID P1). Built to the same
operator contract as the Purview and Intune toolkits: configuration-driven,
`-WhatIf`/`ShouldProcess` on every write, a shared transient-retry boundary,
read-back verification, and structured JSON/HTML evidence.

## First time here? Start with a preview

1. Download or clone the approved repository version containing
   `Products\Entra`. Keep the entire product folder, including `Modules` and
   `Config`, and use the documentation from that same version.
2. Open PowerShell 7 in an interactive desktop terminal and change to the
   repository root. Review the
   [operator prerequisites](docs/Operator-Guide.md#before-you-run) before sign-in.
3. Replace the sample administrator UPN and run:

```powershell
cd .\Products\Entra
.\Deploy-EntraBestPractice.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -WhatIf
```

This first preview needs no pilot group or high-risk approval switches.
It reads available tenant state and writes local evidence without changing
tenant configuration. It can still require sign-in and approved Graph consent.
If a required module is missing, approve its installation only if permitted,
or add `-AutoInstallModules` when CurrentUser installation is already approved.

Use the printed command to open the saved HTML report. The defaults are
`Reports\entra-run-report.html` and `Reports\entra-run-log.json`. Missing
emergency-access configuration can block deployment and make health
`Indeterminate`; that is not proof that the tenant has no emergency accounts.
No tenant action should be `Created`, `Updated`, or `Adopted` in a preview.

Do not disable Security Defaults or remove `-WhatIf` just to clear a warning.
Follow the [pilot preparation and apply sequence](docs/Operator-Guide.md)
and use [evidence and troubleshooting](docs/Evidence-Troubleshooting.md) to
interpret blocked work or a failed health check.

## Choose your starting point

| Need | Guide |
|---|---|
| Run the first preview, prepare a pilot, or apply an approved change | [Operator guide](docs/Operator-Guide.md) |
| Understand the policies and their user impact | [Scenarios](docs/Scenarios.md) |
| Interpret a report or recover from a failure | [Evidence and troubleshooting](docs/Evidence-Troubleshooting.md) |
| Configure and test emergency access | [Break-glass guide](docs/Break-Glass-Guide.md) |
| Plan Security Defaults transition or app-protection migration | [Transition guide](docs/Security-Defaults-Transition.md) |
| Check licensing, API boundaries, and remaining gaps | [Coverage](docs/Coverage.md) |

## What it deploys

Twelve P1 Conditional Access policies: the ten guide templates plus device-code
blocking and security-information registration protection. Each is created in the state configured by
`ConditionalAccess.DefaultState` (report-only by default):

| Policy | Recommended target |
|---|---|
| Require MFA for admins | On |
| Block legacy authentication | On |
| Require MFA for all users | On |
| Require MFA for guest access | On |
| Require MFA for Azure management | On |
| Require MFA for Microsoft admin portals | On |
| Block access for unknown/unsupported device platform | On |
| No persistent browser session | Report-only |
| Require app protection policy | Report-only |
| Require compliant/hybrid device or MFA for all users | Report-only |
| Block device code flow | Report-only, review device-code dependencies before enforcement |
| Protect security information registration | Report-only, verify combined registration and MFA bootstrap |

The optional **phishing-resistant MFA for privileged/admin roles** policy is
also P1, but is not selected by default. Set its policy reference's `Enabled`
to `$true` in your private config after reviewing method readiness. It targets
the configured directory roles, not the pilot group, and defaults to
report-only. SMS, voice and ordinary MFA do not satisfy this strength.

P2 / Identity Protection risk policies are **not deployed**. Console output
distinguishes `P1Baseline`, `P1Hardened` and the P2 guidance boundary. See
[coverage, prerequisites and current Microsoft references](docs/Coverage.md#p1-additions-and-p2-boundary).

Plus **emergency access (break-glass)** handling (guide Priority 1): the toolkit
verifies a configured break-glass account/group, or creates a dedicated
cloud-only one, and excludes it from every policy.

The **"Require MFA for Intune enrollment"** Conditional Access policy is
intentionally **not** part of this product — it belongs to the Intune toolkit,
which owns device-enrollment Conditional Access.

## Safety model

- **Security Defaults gate.** Enabled or unknown means assessment-only across
  every tenant writer, including emergency-account creation and opted-in
  tenant settings. `Policy.Read.All` reads the state before setup and again at
  selected write boundaries. See the
  [coverage and transition guide](docs/Security-Defaults-Transition.md).
- **Report-only by default.** `ConditionalAccess.DefaultState` is
  `enabledForReportingButNotEnforced`. Nothing is enforced until you promote it.
- **Break-glass is mandatory.** `RequireBreakGlassExclusion` is `true`; the
  baseline refuses to create any policy until an emergency-access exclusion
  exists, and it injects that exclusion into every policy. See the
  [break-glass guide](docs/Break-Glass-Guide.md).
- **High-risk gates.** The Conditional Access write requires `-IncludeHighRisk`
  (with `-CustomerApprovalId`), `-BreakGlassExclusionsConfirmed`, and
  `-RollbackAcknowledged`. Without them the module reports what it would create
  and changes nothing.
- **Pilot scope by default.** All-users-style policies are scoped to a
  `-PilotGroupId`; tenant-wide is an explicit `-AssignTenantWide` opt-in.
  The admin MFA and admin-portal policies target their configured directory
  roles across the tenant. Azure-management MFA targets all users for that
  application. Guest MFA targets all guests and external users acting in this
  tenant, not workforce members of the pilot group. These policies are not
  capped by the pilot group; review their
  scope and emergency exclusions before creating or enforcing them.
- **Existing policies.** Current and configured legacy names are matched
  across all result pages; ambiguous matches block creation. The app-protection
  policy is review-only when present, including with `-AdoptExisting`.
  It is not silently repaired, renamed or duplicated.

The corrected guest MFA, admin MFA, admin-portal, Azure-management, device-or-MFA and
browser-session policies also require `ReviewExistingOnly = $true` in custom
configuration. Existing matches remain unchanged and require manual review,
including with `-AdoptExisting`. This avoids silently changing the coverage or
grant requirements of an enforcing policy. The device-or-MFA template uses
an OR between compliant device, hybrid-joined device and MFA, not a requirement
to satisfy all three.

Creation readback checks the compared grants, targeting and emergency
exclusions as well as state. For browser-session policies it also checks the
configured session controls and device filter. Missing or changed fields are
reported as a mismatch, not successful verification. Existing authentication
strength policies remain manual-review only; ordinary MFA is not substituted
for phishing-resistant authentication.

Guest MFA uses the documented `includeUsers = ["GuestsOrExternalUsers"]`
selector without group or role includes. It remains report-only by default.
The toolkit does not combine a guest selector with the pilot group, because
Conditional Access includes are a union, not a guest/group intersection.
Existing group-scoped guest policies are left unchanged for manual migration
review, including when they are enforcing or `-AdoptExisting` is supplied.

These templates are not a proven one-for-one replacement for Security
Defaults. Protecting registration does not enroll everyone, and report-only
device-code blocking does not block sign-ins. Both need explicit coverage
review. Do not disable active protection and leave only report-only
policies in its place. Use an approved transition with verified active
replacement controls, not the toolkit's first preview, for cutover.

New app-protection policies use `compliantApplication` and include Android/iOS
without excluding those same platforms. They require compatible apps and
assigned Intune app-protection policies. The legacy key/file
`require-approved-client-apps` is retained for configuration compatibility.
Use the [migration procedure](docs/Security-Defaults-Transition.md#corrected-app-protection-policy-and-existing-tenants)
for existing policies and update custom policy references to the current
`LegacyDisplayNames` / `ReviewExistingOnly` fields.

## Authentication

Entra uses the same delegated Microsoft Graph sign-in behavior as Purview.
Supply the administrator UPN for a direct tenant run, or add the customer
tenant's verified domain through `-DelegatedOrganization` for GDAP:

```powershell
.\Deploy-EntraBestPractice.ps1 `
    -TenantAdminUpn delegatedadmin@partner.onmicrosoft.com `
    -DelegatedOrganization customer.onmicrosoft.com `
    -WhatIf
```

The orchestrator connects once before any setup module runs. It requests the
delegated scopes in `Config\EntraConfig.psd1`, reuses a cached Graph context
only when the account and every required scope match, and verifies the live
tenant through `/organization`. For GDAP, it authenticates directly to the
customer domain and rejects a cached context for another customer.

Current Microsoft Graph Authentication modules use Windows Authentication
Manager (WAM) on a supported interactive Windows desktop. A first consent,
missing scope, account change, or customer-tenant switch can still require a
browser prompt. Use `-AutoInstallModules` to install a missing Graph
authentication module to `CurrentUser` without a toolkit prompt.

`-NonInteractive` suppresses toolkit confirmation and module-install prompts.
It does not select application authentication and cannot guarantee a
prompt-free first sign-in. Pre-authenticate in an approved interactive session
before using it. Client IDs, certificates, and client secrets are not accepted.

Setup modules use the orchestrator's verified context and do not reconnect. To
run a setup module directly, establish the Graph connection first in the same
PowerShell session.

## Usage

Start in `Products\Entra` in an interactive PowerShell 7 terminal:

```powershell
# Preview: no tenant configuration writes; sign-in and local reports still run.
.\Deploy-EntraBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com -WhatIf
```

The first preview prints all missing Conditional Access apply parameters before
sign-in, even when no break-glass IDs are configured. Removing `-WhatIf` alone
does not authorize Conditional Access deployment.

| Apply prerequisite | What to supply or verify |
|---|---|
| Private configuration | Copy the complete `Config\EntraConfig.psd1` outside the repository, then supply `-ConfigPath`. Keep `DefaultState` report-only and tenant-setting `Apply` flags false unless separately approved. |
| Emergency access | Configure verified `ConditionalAccess.BreakGlass.ExcludeUserIds` or `ExcludeGroupIds`. Independently test recovery and keep the emergency-access verification module selected. |
| Change approval | `-IncludeHighRisk -CustomerApprovalId '<approved-change-reference>'`. Only a hash of the reference enters evidence. |
| Safety confirmations | `-BreakGlassExclusionsConfirmed -RollbackAcknowledged`. These record operator decisions; they do not configure recovery for you. |
| Pilot scope | `-PilotGroupId '<entra-group-object-id>'`. Role-, guest- and app-scoped templates retain their configured targeting; the pilot is not an intersection with privileged roles or guest users. |
| Live readiness | Verified tenant identity, effective Graph scopes/roles, P1 entitlement and disabled Security Defaults. Disabled is not proof of active replacement protection. |

After an approved Security Defaults transition, or independent confirmation of
an already-disabled tenant's protection, preview the exact intended write:

```powershell
# Later pilot preview: only after an approved Security Defaults transition
# or independent confirmation of an already-disabled tenant's protection.
# Use a complete private config with verified existing break-glass IDs,
# report-only DefaultState, and tenant-setting Apply flags still false.
.\Deploy-EntraBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -ConfigPath '<private-config-path>' `
    -IncludeHighRisk -CustomerApprovalId 'CHG0001234' `
    -BreakGlassExclusionsConfirmed -RollbackAcknowledged `
    -PilotGroupId '<entra-group-object-id>' -WhatIf
```

Read the reports before a separately approved apply. Disabled Security
Defaults passes one gate, not all safety or authorization checks. The state
is never automatically changed, and there is no bypass switch.

The final output prints the full paths of successfully saved HTML and JSON
reports and a copyable `Invoke-Item -LiteralPath` command to open the HTML.
This also runs for `-WhatIf`, blocked work, and failures after logging has
initialized. The browser never opens automatically. A report-write warning
means that file was not confirmed saved; an older file at the same path is
not evidence of the current run.

The default files are `Reports\entra-run-report.html` and
`Reports\entra-run-log.json`, relative to `Deploy-EntraBestPractice.ps1`.
Override them in the private configuration's `Report` section if needed.
Reruns overwrite these filenames, so preserve each run's evidence in an
approved private location before rerunning. Do not commit tenant reports.

For that approved apply, run the same command with the same private config,
parameters and tenant, omitting only `-WhatIf`. Creating report-only policies
and promoting them to enforcement are separate changes. `-NonInteractive`
does not waive any approval or readiness requirement.

Tenant-wide assignment is not the default: it requires `-AssignTenantWide`,
`-RollbackAcknowledged` and
`Assignment.AllowTenantWideAssignmentForHighRisk = $true` in configuration.
Do not use it merely to avoid preparing a pilot group.

### Reading the console

Numbered stages show prerequisites, tenant discovery/Security Defaults,
emergency access, Conditional Access assessment/deployment, optional tenant
settings, read-only validation and the final summary. The CA stage separates
existing-policy discovery, P1 baseline and optional P1 hardening.

Information is cyan, successful operations and verified reads are green,
warnings/blocked/guided-only/retry outcomes are yellow, failures are red and
skips are gray. Text status/disposition labels remain visible without color.
`VALIDATED` means the recorded readback check passed, not full tenant security
validation. Stages and module results also appear in the HTML/JSON evidence.
The summary uses `OK`, `FAILED`, `SKIPPED` and `BLOCKED`; a completed process
does not mean every requested operation was applied.

### Policy naming and selection

Existing names remain the default. For new policies, set
`ConditionalAccess.DisplayNamePrefix = 'SMB-CA-'` in your complete private
configuration. Each reference supplies a stable tier, sequence and scope
`NameCode`, producing names such as
`SMB-CA-P1-11-Users-Block device code flow`.

Naming is descriptive, not an assignment or licensing gate. The purpose
comes from the template; actual scope is determined by its conditions and the
approved run parameters. The toolkit recognizes both prefixed and original
names and does not rename existing policies. Multiple matches block the run.
If you later change or remove a prefix, retain the old value in
`PreviousDisplayNamePrefixes`; for a changed `NameCode` or manual rename, add
the exact previous full name to that reference's `LegacyDisplayNames`.

Policy references can set Boolean `Enabled = $false` to exclude an item from
deployment and the selected-policy health inventory. This does not disable or
delete a tenant policy. Existing enforcing policies are still checked for
emergency-access risk. The new device-code, registration and hardened-admin
references require `ReviewExistingOnly = $true`: existing matches are assessed
without automatic migration, including with `-AdoptExisting`.
Even when compared fields match, these policies report `GuidedOnly` manual
review rather than verified compliance. Matching fields do not establish
application, registration or authentication-method readiness.

## Deployment health check

After earlier tasks complete, the run finishes with a **read-only health
check** for Security Defaults readiness and emergency-access drift. It issues GET requests
only, changes nothing, and is safe to run on a schedule. Skip it with
`-SkipDeploymentHealth`.

The check exists mainly to catch one thing: **break-glass exclusion drift**.
Every policy the toolkit creates excludes your emergency-access principals. If
someone later edits a policy and removes that exclusion, nothing appears broken
while the policy is report-only, and then the tenant locks every administrator
out the moment that policy is promoted to enforcing.

It reports a verdict rather than stopping the run:

| Verdict | Meaning |
|---|---|
| `Healthy` | Security Defaults is verified disabled, no legacy migration remains, and the implemented policy-presence, state and emergency-access checks passed. This is not a full coverage or sign-in guarantee. |
| `DriftDetected` | A readiness or drift finding needs review, including enabled Security Defaults, a legacy name, missing/duplicate policy, unknown policy state or an exclusion gap. Enabled Security Defaults alone is not a security defect; toolkit writes remain blocked. |
| `LockoutRisk` | Emergency access is compromised right now. An enforcing policy (managed **or** customer-authored) does not exclude a break-glass principal; a break-glass account is disabled, has lost Global Administrator, or cannot be read; or a break-glass group has no enabled member or no longer provides Global Administrator. Act on this first. |
| `Indeterminate` | Security Defaults or an emergency-access control could not be fully evaluated. Never accept an unknown state as `Healthy`. More severe lockout findings retain priority. |

The summary line carries the counts behind the verdict, for example:

```
Verdict=Healthy; ExclusionsEvaluated=True; UnmanagedPoliciesEvaluated=True;
ManagedPoliciesConfigured=12; Present=12; Missing=0; Unevaluable=0;
DuplicateNames=0; Enforcing=0; Disabled=0; UnknownState=0;
EnforcingPoliciesInTenant=0;
BreakGlassExclusionGaps=0; LockoutRisks=0; UnmanagedEnforcingRisks=0;
BreakGlassAccountsDisabled=0; BreakGlassAccountsWithoutRole=0;
BreakGlassGroupsUnusable=0; BreakGlassGroupsWithoutRole=0;
BreakGlassPrincipalsUnreadable=0; Assessment=ReadOnly.
SecurityDefaultsState=Disabled; TenantWritesAllowed=True; LegacyPolicies=0.
```

`TenantWritesAllowed` covers the Security Defaults gate only. Enabled or
unknown state adds a blocked disposition; every selected writer independently
checks the live state. A completed run can still contain blocked findings.

Read `ExclusionsEvaluated` first. When it is `False` no break-glass principal
was available, so every exclusion-related counter is `0` because the check did
not run, not because nothing was found. `EnforcingPoliciesInTenant` is still
counted in that case, and a tenant that is enforcing access with no configured
break-glass principal is reported as a finding in its own right.

`UnmanagedPoliciesEvaluated=False` means the unmanaged-policy check could not
run. This happens when no break-glass principal is available, or when the
toolkit could not build the complete managed-policy name set and therefore
could not safely distinguish toolkit policies from customer-authored ones. The
overall verdict is `Indeterminate`, never `Healthy`.

The check fails closed everywhere it can:

- If the policy list cannot be read, or any page of it fails, no verdict is
  produced at all.
- A policy state outside the three documented Conditional Access states is
  treated as potentially enforcing rather than assumed report-only.
- A break-glass principal that cannot be read, or whose role cannot be
  confirmed, is treated as unavailable rather than assumed intact.
- Enforcing policies the toolkit does **not** manage are checked too, because a
  customer-authored policy can lock the tenant out just as easily. Their display
  names are customer data and are not written to evidence, so the finding points
  at the portal instead.

### What it does not cover

The check now includes Security Defaults state, but it does **not** prove
replacement coverage, perform a transition, or verify complete per-policy body
or assignment drift beyond the emergency-access checks. Legacy policy
presence is recorded for migration review, not proof of effective protection.
Treat the verdict as readiness and emergency-access health, not a full tenant
security assessment.

Break-glass **role** verification (permanently assigned Global Administrator)
runs twice by design: `Setup-EmergencyAccess` verifies it before policy
creation, and the health check verifies it again to catch later drift. The two
modules use the same shared direct-or-group role check. The check reads active
role assignment schedule instances and accepts only tenant-wide assignments
with no expiry. Temporary PIM activations and expiring assignments do not
qualify. Pagination covers role assignments and group memberships.

## Known gaps (Product Group asks)

See [docs/Coverage.md](docs/Coverage.md) for the full mapping and the
Product-Group ask list, including:

- **Registration readiness**: the new policy protects registration with MFA,
  but does not enable combined registration, issue Temporary Access Passes,
  configure authentication methods or force every user to register.
- **Guest migration readiness**: the guest MFA policy targets guests and
  external users across the tenant. An existing group-scoped policy needs
  manual migration review; the toolkit does not prove guest MFA enrollment,
  cross-tenant trust or sign-in compatibility.
