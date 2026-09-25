---
title: Running the Tenant Validation Report
layout: default
parent: Purview
nav_order: 9
permalink: /purview/tenant-validation-report/
---

# Running the Tenant Validation Report
{: .no_toc }

`Test-PurviewTenantConfiguration.ps1` reads the current Purview configuration
and writes a Tenant Validation Report. It can compare the tenant with one
approved Deployment Plan or assess the pinned Priority 1 (Good), Priority 2
(Better), and Priority 3 (Best) guide controls without a plan.

The command is read-only. It has no repair switch and does not change tenant
state. The report describes configuration alignment, not compliance or control
effectiveness.

Use this page for installation, run commands, output locations, and module
troubleshooting. See [Configuration Validation](Configuration-Validation.md)
for the comparison model, result axes, scoring rules, permissions, and known
limitations.

## Before you run

1. Use PowerShell 7.
2. Wait for Purview changes to propagate. Labels, DLP, and tenant settings can
   take up to 24 hours to become visible to a read.
3. Decide whether to compare with a Deployment Plan or run a guide-only
   assessment.
4. Confirm the required PowerShell modules are installed.
5. Use an account with the required read permissions and service roles.
6. Choose a private location for the HTML and JSON evidence.

The validator confirms tenant identity before collecting configuration. A
wrong-tenant result is fatal and no report is written.

## Required PowerShell modules

The validator first checks whether each required command is already available.
If a command is not loaded, it imports an installed copy of the module that
provides it. When the module is missing, the validator prompts to install it or
installs it automatically when `-AutoInstallModules` is set. The current
validator does not pin exact module versions or maintain a tested-profile
allowlist.

| Module | Used for | Requirement |
|---|---|---|
| `Microsoft.Graph.Authentication` | Graph sign-in and tenant identity | Core. Every validation run uses Graph. |
| `ExchangeOnlineManagement` | Exchange Online and Security & Compliance PowerShell sessions | Core. Every validation run uses both sessions. |
| `Microsoft.Graph.Beta.Identity.DirectoryManagement` | Reading the `Group.Unified` container-label directory setting | Conditional. Without it, the container-label action is `Not evaluated`. |
| `Microsoft.Online.SharePoint.PowerShell` | Reading SharePoint and OneDrive label integration and the PDF setting | Conditional. It is needed when scored actions use `Get-SPOTenant`. A connection failure makes those actions `Not evaluated` while other actions continue. |

`Connect-IPPSSession` is supplied by `ExchangeOnlineManagement`, so there is no
separate Security & Compliance module to install.

### Check installed versions

Run this in a fresh PowerShell 7 session:

```powershell
Get-Module `
    Microsoft.Graph.Authentication, `
    Microsoft.Graph.Beta.Identity.DirectoryManagement, `
    ExchangeOnlineManagement, `
    Microsoft.Online.SharePoint.PowerShell `
    -ListAvailable |
    Sort-Object Name, Version -Descending |
    Select-Object Name, Version, Path
```

Check which versions are already loaded:

```powershell
Get-Module `
    Microsoft.Graph.Authentication, `
    Microsoft.Graph.Beta.Identity.DirectoryManagement, `
    ExchangeOnlineManagement, `
    Microsoft.Online.SharePoint.PowerShell |
    Select-Object Name, Version, Path
```

### Install missing modules

The simplest operator path is to let the validator install missing modules:

```powershell
.\Test-PurviewTenantConfiguration.ps1 `
    -TenantAdminUpn admin@contoso.onmicrosoft.com `
    -AutoInstallModules
```

For manual installation:

```powershell
Install-Module Microsoft.Graph.Authentication `
    -Scope CurrentUser -Force

Install-Module Microsoft.Graph.Beta.Identity.DirectoryManagement `
    -Scope CurrentUser -Force

Install-Module ExchangeOnlineManagement `
    -Scope CurrentUser -Force

Install-Module Microsoft.Online.SharePoint.PowerShell `
    -Scope CurrentUser -Force
```

Install Graph Authentication and the Graph Beta directory module from the same
Microsoft Graph PowerShell SDK release. The Beta module manifest can require an
exact Authentication version. A mixed Graph pair can fail during import even
though both modules are installed.

Close the PowerShell process after installing or changing Graph or Exchange
Online modules. Start a new `pwsh -NoProfile` process so an older MSAL assembly
does not remain loaded.

## Permissions and sign-in

The validation profile requests these delegated Microsoft Graph scopes:

| Scope | Purpose |
|---|---|
| `Organization.Read.All` | Resolve and verify the connected tenant. |
| `GroupSettings.Read.All` | Read the tenant-wide container-label directory setting. |

The validator deliberately does not request the deployment profile's Graph
write permissions.

After connection, the validator checks the effective Graph token. It permits
only the two resource scopes above and the standard OpenID identity scopes. A
cached or newly issued token containing another Graph permission is rejected
before tenant collection.

When an existing token is broader, close the PowerShell process and open a
fresh session:

```powershell
pwsh -NoProfile
```

Rerun the validator in that process. It requests the two read scopes and checks
the new effective token before any tenant collection. Starting a new process
clears the in-process context, but the shared Microsoft Graph PowerShell client
or Windows broker can still reuse an earlier grant. The validator deliberately
does not clear the shared broker automatically because that could sign the user
out of other broker-enabled applications.

If the fresh token remains broader, use an approved tenant-local public client
configured with only `Organization.Read.All` and
`GroupSettings.Read.All`. The validator does not create the app or grant
consent:

```powershell
.\Test-PurviewTenantConfiguration.ps1 `
    -TenantAdminUpn 'admin@contoso.onmicrosoft.com' `
    -ClientId '<approved-public-client-app-id>' `
    -UseDeviceAuthentication
```

Exchange Online, Security & Compliance PowerShell, and SharePoint Online use
the signed-in account's service roles. Microsoft does not document a
least-privileged role for every cmdlet used by the validator. Those role
mappings still require pilot verification. SharePoint Online access is
optional because a missing SharePoint session affects only the SharePoint
backed actions.

## Find a Deployment Plan

Deployment Plans are written to the working directory from which the deployment
script was invoked unless `-DeploymentPlanPath` selected another location.

The JSON filename normally resembles:

```text
Deploy-PurviewBestPractice-Plan-PUR-20260914-144842-1234ABCD.json
```

Find plans under a deployment folder:

```powershell
Get-ChildItem 'C:\Demo Deployment\BestPractice_Deploy-Scripts' `
    -Filter 'Deploy-PurviewBestPractice-Plan-*.json' `
    -Recurse
```

Plan comparison accepts a Deployment Plan JSON sidecar at schema 1.2 or later.
The validator checks artifact identity and fingerprints before authentication.

## Run a plan comparison

From the Purview product folder:

```powershell
cd 'C:\Demo Deployment\BestPractice_Deploy-Scripts\Products\Purview'

.\Test-PurviewTenantConfiguration.ps1 `
    -PlanPath 'C:\Demo Deployment\Evidence\Deploy-PurviewBestPractice-Plan-PUR-20260914-144842-1234ABCD.json' `
    -TenantAdminUpn 'admin@contoso.onmicrosoft.com'
```

The validator compares observable toolkit-owned fields with the plan's
sanitized intended state. Customer-managed differences are retained as
redacted, unscored context.

## Run a guide-only assessment

Omit `-PlanPath`:

```powershell
.\Test-PurviewTenantConfiguration.ps1 `
    -TenantAdminUpn 'admin@contoso.onmicrosoft.com'
```

Guide-only mode assesses the pinned guide controls without loading the default
Purview configuration or claiming what the deployment intended.

## Run through GDAP

```powershell
.\Test-PurviewTenantConfiguration.ps1 `
    -PlanPath 'C:\Demo Deployment\Evidence\plan.json' `
    -TenantAdminUpn 'partneradmin@fabrikam.onmicrosoft.com' `
    -DelegatedOrganization 'contoso.onmicrosoft.com'
```

The customer domain supplied through `-DelegatedOrganization` is used for the
tenant identity check.

## Specify SharePoint and output paths

Use an explicit SharePoint admin URL for multi-geo, renamed, or vanity-domain
tenants:

```powershell
.\Test-PurviewTenantConfiguration.ps1 `
    -PlanPath 'C:\Demo Deployment\Evidence\plan.json' `
    -TenantAdminUpn 'admin@contoso.onmicrosoft.com' `
    -SharePointAdminUrl 'https://contoso-admin.sharepoint.com'
```

Choose the HTML report location with `-OutputPath`:

```powershell
.\Test-PurviewTenantConfiguration.ps1 `
    -PlanPath 'C:\Demo Deployment\Evidence\plan.json' `
    -TenantAdminUpn 'admin@contoso.onmicrosoft.com' `
    -OutputPath 'C:\Demo Deployment\Evidence\Contoso-Purview-Validation.html'
```

The JSON sidecar uses the same directory and basename:

```text
C:\Demo Deployment\Evidence\Contoso-Purview-Validation.html
C:\Demo Deployment\Evidence\Contoso-Purview-Validation.json
```

Without `-OutputPath`, both files are written to the current working directory:

```text
Test-PurviewTenantConfiguration-<UTC timestamp>.html
Test-PurviewTenantConfiguration-<UTC timestamp>.json
```

Validation output contains tenant observations. Store it in the approved
private evidence location. Do not commit or publish the files.

## Run without prompts

Use `-NonInteractive` for automation:

```powershell
.\Test-PurviewTenantConfiguration.ps1 `
    -PlanPath 'C:\Demo Deployment\Evidence\plan.json' `
    -TenantAdminUpn 'admin@contoso.onmicrosoft.com' `
    -OutputPath 'C:\Demo Deployment\Evidence\validation.html' `
    -NonInteractive

$validationExitCode = $LASTEXITCODE
```

Install modules before a noninteractive run, or combine the command with
`-AutoInstallModules`.

## Read the result

Each action receives one operational result:

| Result | Meaning |
|---|---|
| `Matched` | Every scored toolkit-owned field matched. |
| `Drift` | A managed field differed after retries. |
| `Not evaluated` | Entitlement is explicitly known to be absent, or a required service session, property, or capability was unavailable. |
| `Informational` | The plan excluded or did not configure the action. |
| `Collection failed` | The tenant read failed after transient retries. |

Unreadable or missing license inventory is provisional and does not block a
workload read that can prove support. The validator does not request
license-assignment scope; it reports `Not evaluated` only when entitlement is
explicitly known to be absent, or when another required session, property, or
capability is unavailable.

Exit codes use a bitmask:

| Code | Meaning |
|---|---|
| `0` | No drift and no collection failures. |
| `2` | Drift is present. |
| `4` | A collection failure is present. |
| `6` | Both drift and a collection failure are present. |
| `1` | Fatal plan, schema, tenant identity, or connection failure. |

The validator has no propagation status. A setting that has not converged when
it is read is reported as drift. Wait for the documented propagation window
before acting on a new deployment's first validation report.

## Troubleshooting

### Deployment Plan JSON not found

The supplied path does not identify an existing file. Search for the generated
JSON sidecar and pass its exact path. Current plan filenames include the
`PUR-<timestamp>-<id>` reference.

### A required module is not installed

Install the named module or rerun with `-AutoInstallModules`. In
`-NonInteractive` mode, a missing core module is fatal.

### An exact approved module version is rejected

The current validator does not enforce exact module versions. This error
normally means you are running the earlier `Test-PurviewConfiguration.ps1`
prototype or another development branch. Confirm the script filename,
repository branch, and module path before installing or removing modules.

Do not bypass an exact-version guard in a script that contains one. Either run
the current `Test-PurviewTenantConfiguration.ps1` command or satisfy that
script's documented profile.

### Graph Authentication and Graph Beta do not load together

Check the Graph Beta manifest requirement:

```powershell
$beta = Get-Module Microsoft.Graph.Beta.Identity.DirectoryManagement `
    -ListAvailable |
    Sort-Object Version -Descending |
    Select-Object -First 1

(Import-PowerShellDataFile -LiteralPath $beta.Path).RequiredModules
```

Install a matching Graph Authentication and Graph Beta pair, close PowerShell,
and retry from `pwsh -NoProfile`.

### Exchange Online fails after Graph connects

Graph is connected first because Graph and Exchange Online can load different
MSAL versions. The validator passes `-DisableWAM` to Exchange Online and
Security & Compliance after Graph is loaded. If the process already loaded
conflicting assemblies, close it and retry in a fresh PowerShell 7 process.

### SharePoint Online cannot connect

The validator continues. Actions that depend on `Get-SPOTenant` are reported as
`Not evaluated`. Confirm the SharePoint module, admin URL, role, and service
health before rerunning.

### Tenant identity mismatch

Validation stops rather than produce a report for the wrong tenant. Confirm the
admin UPN suffix, `-DelegatedOrganization`, and the account selected during
interactive sign-in.

### Graph context contains permissions outside the validator allowlist

The validator found an effective token with a resource permission other than
`Organization.Read.All` or `GroupSettings.Read.All`. It disconnects that
context and stops before tenant collection. Close the process, start a fresh
`pwsh -NoProfile` session, and rerun. If the newly authenticated token still
contains broader permissions, use an approved tenant-local public client
restricted to the two validation permissions and pass its application ID with
`-ClientId`. Do not broaden the validator allowlist to accommodate an existing
deployment consent grant.

### A recent deployment reports drift

Wait up to 24 hours for Purview propagation, then rerun. The validator does not
guess that a mismatch is still propagating.

## Current module-version support issue

The current validator confirms module names and required commands, but it does
not distinguish between tested and untested version combinations. PowerShell
can auto-load the newest installed version, and a module that works by itself
can still conflict with another module through Graph SDK or MSAL dependencies.

There is no established list of approved module profiles. An installed
combination must not be described as qualified only because imports or
authentication succeeded once.

## Proposed tested module profiles

A future module profile should be a complete tuple rather than independent
minimum-version ranges. An illustrative record could contain:

```powershell
@{
    Id = 'validator-2026-09'
    Status = 'Candidate'
    PowerShell = @{
        MinimumVersion = '7.4'
        MaximumMajor = 7
    }
    Modules = @{
        MicrosoftGraphAuthentication = '<exact version>'
        MicrosoftGraphBetaDirectory = '<matching exact version>'
        ExchangeOnlineManagement = '<exact version>'
        SharePointOnline = '<exact version>'
    }
    Connection = @{
        Order = @('Graph', 'ExchangeOnline', 'IPPS', 'SharePoint')
        DisableWamAfterGraphLoad = $true
    }
    PilotEvidence = ''
}
```

This is a proposed support model, not a configuration recognized by the
current validator.

The selector should:

1. Consider only complete installed profiles.
2. Reject Graph Beta and Graph Authentication versions that do not match the
   Beta module manifest.
3. Prefer the newest profile with `Approved` status.
4. Never select a `Candidate` or `Rejected` profile automatically.
5. Record the selected profile and exact module versions in the report.
6. Run validation in a fresh child PowerShell process when loaded assemblies
   could conflict with the selected profile.

## Qualifying another profile

Do not build a Cartesian matrix of every module version. Maintain a short list:
the current approved profile, the previous approved profile for rollback, and
one candidate under qualification.

### 1. Check manifests and commands

- Confirm every exact version is available from the approved package source.
- Confirm Graph Beta requires the selected Graph Authentication version.
- Confirm each required command is exported by the expected module.
- Reject incomplete profiles and duplicate profile IDs.
- Keep executable commands and arbitrary module paths out of profile data.

### 2. Test imports in a clean process

The profile test should start `pwsh -NoProfile`, import each exact version in
the required order, and confirm command provenance. It must detect assembly
load failures, missing methods, command shadowing, and mixed Graph versions.

### 3. Run deterministic validator fixtures

Run:

```powershell
pwsh -File .\Products\Purview\Tests\Test-TenantConfigurationValidation.ps1
```

The fixtures must continue to cover schema rejection, matching state, drift,
unscored customer differences, prerequisites, retries, collection failures,
partial reports, redaction, and exit codes.

### 4. Test authentication and every collector

On an approved non-production tenant:

1. Connect Graph first with the validator's read-only scopes.
2. Read tenant identity and directory settings.
3. Connect Exchange Online and Security & Compliance PowerShell.
4. Connect SharePoint Online when required.
5. Exercise each validation collector.
6. Repeat the full run in another fresh process to catch cached-session and
   assembly-order problems.

### 5. Test operational scenarios

Record results for:

- a matching tenant;
- deliberate toolkit-managed drift;
- wrong-tenant rejection;
- supported and unsupported licensing;
- unreadable prerequisites;
- missing optional SharePoint access;
- transient and permanent service failures;
- customer-managed objects excluded from scoring;
- HTML and JSON parity and redaction;
- exit codes `0`, `2`, `4`, and `6`.

### 6. Record approval evidence

An approved profile record should include:

- exact module and PowerShell versions;
- operating system and build;
- test date and reviewer;
- deterministic test output;
- non-identifying pilot classification;
- collector coverage;
- known limitations;
- approval owner;
- review or expiration date.

Until this evidence exists, keep the profile at `Candidate` and do not present
it as supported.
