# Intune assessment and deployment examples

These examples use the current `0.3.0` write-capable release. Start with
`-WhatIf`, use an approved pilot group for assignment, and add high-risk
switches only after the customer approval and recovery record is complete.

Replace sample identities and GUIDs with values from the approved deployment
record. Do not put real tenant identifiers in source control.

New to the tool? Start with the [README preview](../README.md#first-time-here-start-with-a-preview).
Before using a pilot ID below, follow
[pilot group setup](../docs/Operator-Guide.md#prepare-a-pilot-group).

## Example 1: preview the full baseline

```powershell
cd Products/Intune
./Deploy-IntuneBestPractice.ps1 `
  -TenantAdminUpn admin@contoso.onmicrosoft.com `
  -PilotGroupId '<entra-group-object-id>' `
  -WhatIf
```

The preview performs the supported assessments and records every selected
write as planned intent. It does not change tenant state.

Expected local outputs:

- `Reports/intune-run-report.html`
- `Reports/intune-run-log.json`
- `Reports/intune-applicability.json`

Move completed tenant reports to the approved private evidence location. Do
not commit them.

The final output prints the saved HTML and JSON run-report paths and a
copyable command to open the HTML. Nothing opens automatically. These reports
also capture blocked work and failures after logging starts; a report-write
warning means the file was not confirmed saved by this run.

## Example 2: apply the standard pilot baseline

This command creates the Microsoft 365 Apps deployment and the Android and
iOS/iPadOS Level 1 app-protection policies, then assigns them to the pilot
group. High-risk writes remain withheld.

```powershell
./Deploy-IntuneBestPractice.ps1 `
  -TenantAdminUpn admin@contoso.onmicrosoft.com `
  -PilotGroupId '<entra-group-object-id>'
```

Review the report for `Created` and assignment evidence, then verify app
targeting and assignment in Intune. A missing pilot group does not make the
write tenant-wide. Standard objects can be created without assignment, so
supply the group for a useful pilot.

## Example 3: add one high-risk stage

Use the copy-ready [staged commands in the operator guide](../docs/Operator-Guide.md#add-high-risk-changes-one-at-a-time).
They separate device compliance, enrollment restrictions, the tenant-wide
default compliance setting, and report-only Conditional Access. Do not combine
them for a first deployment. Each stage starts with `-WhatIf` and requires its
own approval, before-state, verification, and recovery decision.

The default compliance setting is not limited by `-PilotGroupId`. Conditional
Access remains report-only; enforcement is a later portal decision.

## Example 4: GDAP-delegated preview

Use `-DelegatedOrganization` when the administrator signs in through a partner
tenant but must administer a customer tenant under Granular Delegated Admin
Privileges.

```powershell
./Deploy-IntuneBestPractice.ps1 `
  -TenantAdminUpn admin@partner.onmicrosoft.com `
  -DelegatedOrganization customer.onmicrosoft.com `
  -AutoInstallModules `
  -PilotGroupId '<customer-tenant-group-object-id>' `
  -WhatIf
```

Authentication is delegated UPN/GDAP only, matching Purview. A cached Graph
context is reused only when its account, tenant, and every required scope
match. A stale or wrong-tenant context is disconnected and replaced.

`-AutoInstallModules` installs DeviceManagement at the same SDK version as
Authentication rather than independently choosing the latest release. If
the current shell already contains incompatible Graph modules or assemblies,
open a fresh PowerShell 7 session and follow the
[module recovery steps](../docs/Evidence-Troubleshooting.md#graph-module-version-conflicts).

## Example 5: intentionally omit one task

Skip switches are for a documented scope decision, not for hiding a failure.

```powershell
./Deploy-IntuneBestPractice.ps1 `
  -TenantAdminUpn admin@contoso.onmicrosoft.com `
  -PilotGroupId '<entra-group-object-id>' `
  -SkipAppProtectionPolicies `
  -WhatIf
```

Record why the task was omitted and who approved the reduced scope.

## Example 6: review module and write results

```powershell
$report = Get-Content ./Reports/intune-run-log.json -Raw |
  ConvertFrom-Json

$report.moduleSummary |
  Sort-Object module |
  Format-Table module, result, entryCount

$report.entries |
  Where-Object status -in @('Created', 'Updated', 'Adopted') |
  Select-Object module, bestPracticeKey, action, target, readback, detail |
  Format-Table -Wrap
```

For a `-WhatIf` run, the second query must be empty. For an apply run, every tenant write must match the approved scope. Confirm
module readback where it is emitted and use the documented portal or device
verification for app-protection targeting and assignment.

## Example 7: list guided work

```powershell
$report.entries |
  Where-Object disposition -eq 'GuidedOnly' |
  Select-Object module, bestPracticeKey, action, detail |
  Format-Table -Wrap
```

Assign each guided item an owner and review date. Apple certificate work,
Managed Google Play, Windows automatic MDM enrollment, Windows Backup for
Organizations, and unsupported platform or catalog paths remain outside the
supported apply scope.

## Reserved command that must fail closed

The imported policy catalog is not an approved deployment surface:

```powershell
./Deploy-IntuneBestPractice.ps1 `
  -TenantAdminUpn admin@contoso.onmicrosoft.com `
  -EnablePolicyCatalogWrite
```

The command must refuse the run and write blocked evidence. Do not use it as a
capability probe in a customer change window.
