---
title: Configuration Validation
layout: default
parent: Purview
nav_order: 10
permalink: /purview/configuration-validation/
---

# Configuration Validation
{: .no_toc }

`Test-PurviewTenantConfiguration.ps1` reads current Purview tenant
configuration. With a plan, it compares live state with the plan's sanitized
`IntendedState`. Without a plan, it performs a guide-only Good, Better, and Best
assessment and does not load default configuration intent.

It never changes anything. There is no apply path and no repair switch.

For installation, module requirements, run commands, report locations, and
module-version troubleshooting, start with
[Running the Tenant Validation Report](Tenant-Validation-Report.md).

## What it is and is not

| It is | It is not |
|---|---|
| A comparison with one approved Deployment Plan | A compliance assessment |
| Scoped to fields the toolkit owns | A judgement on your own settings |
| A read-only readback you can run any time | The end-of-run deployment report |
| Evidence you can attach to a change record | A measure of how well the controls work |

The report says so on its front page. Nobody should be able to forward it to a
customer and have it read as a compliance statement.

## Prerequisites

A plan is optional. Plan comparison accepts a Deployment Plan JSON sidecar at
**schema 1.2 or later**. Artifact type, plan reference, schema, plan-input
fingerprint, intended-state fingerprint, and intended-state content are checked
before authentication.

Regenerating is offline and deterministic. Run the orchestrator with the same
configuration and switches, and the plan fingerprint is reproduced:

```powershell
.\Deploy-PurviewBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com -WhatIf
```

## Permissions

Validation uses its own read-only connection profile rather than the deployment
one. It requests two delegated Microsoft Graph scopes:

| Scope | Why |
|---|---|
| `Organization.Read.All` | tenant identity check |
| `GroupSettings.Read.All` | the container-label directory setting |

The deployment profile's `Directory.ReadWrite.All` is deliberately not
requested. Exchange Online, Security & Compliance, and SharePoint Online do not
offer per-operation scopes, so those sessions can read whatever the operator's
directory role allows. `Get-SPOTenant` has no documented least-privileged read
role, which is why the SharePoint session is optional: without it, the two
SharePoint-backed actions report `Not evaluated` and the rest of the run
continues.

Requesting two scopes is not enough if the effective token contains older,
broader consent. The validator checks the connected Graph context and stops
before tenant collection when any other Graph resource permission is present.
Standard OpenID identity scopes (`openid`, `profile`, `email`, and
`offline_access`) are allowed.

When the existing context is broader, the validator disconnects it and directs
the operator to close the process. Start a fresh `pwsh -NoProfile` session and
rerun so a new delegated token is requested. This clears the in-process
context, but the shared Microsoft Graph client or Windows broker can still
return an earlier broad grant across processes. The new token is therefore
checked again.

If the fresh sign-in is still broader, use an approved tenant-local public
client whose delegated grant contains only `Organization.Read.All` and
`GroupSettings.Read.All`. Pass its application ID with `-ClientId`; use
`-UseDeviceAuthentication` when the host cannot display the default WAM or
browser flow. The validator never creates an app registration, grants consent,
or stores a credential. It does not automatically clear the shared Windows
broker because that could sign the user out of other broker-enabled tools.

For module requirements and the public sign-in instructions, see
[Permissions and sign-in](Tenant-Validation-Report.md#permissions-and-sign-in).
Verify the service roles in an approved pilot before relying on validation results.

## When to run it

Not immediately after a deployment. Purview label, DLP, and tenant settings can
take up to 24 hours to become visible to a read, and the tool has no
"propagating" result: a setting that is still rolling out is reported as drift.
Run it after the propagation window, or on a schedule, or before a change
review. The report repeats this warning at the top so nobody acts on a run made
ten minutes after a deployment.

## Running it

```powershell
cd Products/Purview

.\Test-PurviewTenantConfiguration.ps1 `
    -PlanPath .\Deploy-PurviewBestPractice-Plan-PUR-20260814-091500-1234ABCD.json `
    -TenantAdminUpn admin@contoso.onmicrosoft.com
```

Partner GDAP, with an explicit report location:

```powershell
.\Test-PurviewTenantConfiguration.ps1 `
    -PlanPath .\plan.json `
    -TenantAdminUpn partneradmin@fabrikam.onmicrosoft.com `
    -DelegatedOrganization contoso.onmicrosoft.com `
    -OutputPath .\evidence\contoso-validation.html
```

| Parameter | Purpose |
|---|---|
| `-PlanPath` | optional schema 1.2 plan JSON to compare |
| `-TenantAdminUpn` | required; sign-in identity |
| `-OutputPath` | HTML path. The JSON sidecar uses the same basename |
| `-DelegatedOrganization` | customer tenant domain for GDAP sign-in |
| `-SharePointAdminUrl` | for multi-geo, renamed, or vanity-domain tenants |
| `-ClientId` | approved tenant-local public client restricted to the two validation Graph permissions |
| `-UseDeviceAuthentication` | use the Graph device-code flow when WAM or browser authentication cannot open |
| `-AutoInstallModules` | install missing read-only modules without prompting |
| `-NonInteractive` | fail instead of prompting |

## Reading the results

Each action records three independent axes.

| Axis | Values |
|---|---|
| Observation | `Present`, `Absent`, `Unreadable`, `Unsupported` |
| Intended state | `Match`, `Mismatch`, `NotInPlan`, `NotEvaluated` |
| Guide baseline | `Meets`, `DoesNotMeet`, `Indeterminate`, `NotApplicable` |

The report also retains the legacy operational status used for exit codes:

| Result | Meaning | What to do |
|---|---|---|
| **Matched** | every managed field matches the plan | nothing |
| **Drift** | a managed field differs, after transient retries | find out whether the deployment action failed or the setting was changed afterward |
| **Not evaluated** | entitlement is explicitly known to be absent, or a required service session, property, or capability was unavailable | confirm entitlement, session availability, or property support before treating it as drift |
| **Informational** | the plan excluded this action or did not configure it | nothing, unless you now want the feature in scope |
| **Collection failed** | the read did not succeed after retries | check permissions, modules, and service health, then rerun |

Two of these deserve emphasis.

**Informational is not a pass and not a failure.** If your plan excluded
retention and the tenant has a retention policy, that policy is reported as
informational context. The plan did not ask for it, so the tool has no opinion
about whether it should be there.

**There is no "pending propagation" result.** Transient read failures are
retried with backoff. Anything that still does not match is reported as drift.
A result meaning "it might be right later" is a result nobody acts on. This is
why the timing advice above matters.

**Not evaluated covers unavailable prerequisites.** If entitlement is explicitly
known to be absent, the action is not evaluated because the tenant is not
expected to expose that feature. If a required session, property, or capability
is unavailable, investigate connectivity, consent, roles, or module support.
Unreadable or missing license inventory is provisional and does not block a
workload read that can prove support.

### Scored and unscored

Only fields the toolkit owns are scored. A DLP policy comment you edited by
hand, a notification setting you tuned, a label policy that is not the
toolkit's: those appear as redacted unscored differences so you can see them,
and they never count against the result. A report that fails your own settings
is a report you stop reading.

## Exit codes

The exit code is a bitmask, so one run can report both drift and a read gap.

| Code | Meaning |
|---|---|
| 0 | no drift, no collection failures |
| 2 | drift present |
| 4 | collection failure present |
| 6 | both |
| 1 | fatal input, schema, tenant-identity, or connection failure |

Exit code 1 means the run stopped before it read anything useful: a missing or
unusable plan, a schema the validator will not accept, a tenant that is not the
one you asked for, or a failed connection. No artifact is written, because
there is nothing to report.

## Output

A self-contained HTML report and a matching JSON sidecar, both rendered from one
model so they cannot disagree. The HTML has no external stylesheet, font, or
script, so it can be emailed, attached to a ticket, or opened offline.

Both artifacts are written even when some collectors failed. A run where four
reads failed is exactly the run whose report you need.

The report correlates with its plan through the plan ID, the plan input
SHA-256, and the configuration SHA-256. Check those before acting on a report
somebody else produced.

The JSON artifact type is `PurviewTenantValidation`, schema `1.0`. Its short
reference starts with `PUR-VAL-`. HTML and JSON use the same canonical model.
The report includes service status, current configuration, optional plan
comparison, guide tiers, extensions, manual checks, and a technical appendix.

Validation output contains tenant observations. Keep it in the approved private
evidence location. Do not commit or publish it.

## Current limitations

- Pilot validation against a live tenant has not been performed for this
  release. The deterministic fixtures prove the toolkit's own logic; they do
  not establish Microsoft supportability or real permission behaviour.
- The shared Microsoft Graph PowerShell client can return previously consented
  permissions in the effective token. The validator fails closed in that case;
  retry first from a fresh PowerShell process. If the new token is still broad,
  an approved isolated public client is required rather than accepting the
  broader context.
- Least-privileged read roles for the Exchange Online, Security & Compliance,
  and SharePoint Online cmdlets are not documented by Microsoft per cmdlet and
  still need pilot confirmation.
- There is no propagation grace window. Run validation after the propagation
  window described above.
- Actions the plan excluded are reported without a tenant read, so the report
  says nothing about a feature the plan did not ask for. If you need to know
  whether an excluded feature is configured, check it directly.
- A label the toolkit adopted from a pre-existing label with a GUID-shaped
  internal name will report drift, because the plan expects the configured
  internal name. The direction of that error is a false alarm rather than a
  missed problem, but it is a real gap.
- The tool reports drift. It does not fix it, and it will not gain a repair
  switch without a separate design and approval.
