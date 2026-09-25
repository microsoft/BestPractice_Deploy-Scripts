---
title: Entra evidence and troubleshooting
parent: Microsoft Entra
layout: default
nav_order: 3
permalink: /entra/evidence-troubleshooting/
---

# Entra evidence and troubleshooting

## Find and preserve the reports

After logging initializes, the toolkit attempts to save HTML and JSON evidence
even when sign-in, deployment, or health evaluation fails. The final output
prints the full path of each successfully written report and a copyable
command to open the HTML manually. It never launches a browser automatically.

With the default configuration, run this from `Products\Entra`:

```powershell
Invoke-Item -LiteralPath '.\Reports\entra-run-report.html'
$report = Get-Content -LiteralPath '.\Reports\entra-run-log.json' -Raw |
    ConvertFrom-Json
$report.moduleSummary | Format-Table module, result, entryCount
```

The private configuration's `Report` section can change these paths.
A write warning means that file was not confirmed saved; an older file can
still exist at the same location. Check the run ID and timestamps, not just
file presence. Preserve reports before retrying because filenames are reused.

`entra-breakglass.json` is a local handoff containing resolved emergency-access
IDs. Empty lists mean no principals were resolved for that run, not that no
emergency accounts exist anywhere in the tenant. Never treat this file as
credential storage or as proof of successful recovery.

Reports are private tenant evidence. Redaction is pattern-based, not a
guarantee that every service-authored error is safe to share. Review excerpts,
and never commit reports, private configuration, tokens, or credentials.

## Interpret results without confusing execution and protection

| Result or field | Meaning |
|---|---|
| `OK` | Recorded module work completed without a recorded failure or block. It does not prove the baseline was applied or the tenant is secure. |
| `FAILED` | An operation failed or a safety/health assessment returned a failure. Read its action and detail; this does not always mean the script crashed. |
| `BLOCKED` | A prerequisite, safety gate, or assessment finding prevents proceeding. Resolve it under change control. |
| `SKIPPED` | Work was not executed or remained assessment/guidance-only. It is not proof that configuration is complete. |
| `GuidedOnly` | Human work or review remains. It is not verified compliance. |
| `VALIDATED` / `Readback=Verified` | The stated readback check passed, not an end-to-end sign-in or security test. |
| `TenantWritesAllowed=True` | The Security Defaults gate passed. Approval, scope, emergency access, permissions, and other gates still apply. |
| `ExclusionsEvaluated=False` | Exclusion checks were not completed. Zero gap counters do not mean no gaps exist. |

Review actual writes separately:

```powershell
$report.entries |
    Where-Object status -in @('Created', 'Updated', 'Adopted') |
    Select-Object module, action, status, readback, detail
```

A `-WhatIf` preview must have no applied tenant actions in that result.
For an apply, compare each entry with the approved change and confirm its
readback. `Started` or `Module process completed` alone is not deployment
evidence. Intentionally skipped modules reduce the assessment's coverage.

Selected modules that never start after an earlier failure are recorded as
`Skipped` with a `Blocked` disposition and an explicit reason. Console, HTML,
and JSON use the same module verdicts. Summaries of a failed child do not
change the orchestrator's own verdict, but genuine orchestrator failures and
readiness blocks remain visible. The child failure still requires action.

Report-write warnings remain nonterminating even with `-WarningAction Stop`,
so they cannot hide the original error or prevent the other report attempt.

## A first run is blocked and health is indeterminate

A first run can connect successfully, find no configured emergency-access
principals, report missing toolkit policies, and stop Conditional Access
deployment. If enforcing customer policies already exist, the health check
cannot verify their emergency exclusions without those principals and can
return `Indeterminate` with a failed module result.

This does not prove the tenant lacks emergency accounts or is currently
locked out. It means the tool lacks enough verified configuration to assess
recovery. Confirm the existing emergency accounts with the identity owner,
test them independently, and configure their object IDs in a complete
private config. Then rerun the preview. Do not create duplicate emergency
accounts or disable existing policies just to clear the report.

Missing managed policies are expected before the baseline is deployed.
The separate `EnforcingPoliciesInTenant` count includes existing policies,
so a missing toolkit baseline does not mean the tenant has no access controls.

For `LockoutRisk`, stop rollout and use the approved access incident/recovery
process immediately. For `DriftDetected`, reconcile the specific changes
before expansion. `Healthy` covers only the implemented readiness and
emergency-access checks, not full policy coverage or a sign-in guarantee.

## Common failures

| Symptom | What to do |
|---|---|
| Wrong tenant or verified-domain mismatch | Stop. Check the administrator UPN and, for GDAP, the customer domain. Do not bypass identity verification. |
| `401` / `403` or a failed read | Check the exact Graph operation, configured scopes, effective roles, GDAP access, and session. Do not add broad permissions speculatively. |
| Security Defaults enabled or unknown | Keep active protection. Use the [approved transition guide](Security-Defaults-Transition.md); the toolkit never disables it. |
| Missing apply parameters or pilot group | Complete the [operator checklist](Operator-Guide.md). Removing `-WhatIf` alone does not authorize writes. |
| No configured break-glass principal | Verify existing accounts/groups, populate the private configuration, and rerun. An ID is not a successful recovery test. |
| Existing or duplicate policy names | Review the exact objects and aliases. Do not use adoption or naming changes to bypass collisions or migration review. |
| Readback mismatch or unavailable readback | Treat the operation as failed or blocked. Inspect the tenant before retrying because the service might have accepted the preceding write. |
| Report-write warning | Keep the console output, verify the destination and permissions, and preserve any surviving report. Do not use stale files as current evidence. |

### Windows sign-in needs a window handle

`WAM broker available` describes Windows capability, not a guarantee that
the current host can display the sign-in window. If Graph reports
`A window handle must be configured`, open Windows Terminal with PowerShell 7
yourself, change to the same product folder, and rerun the same `-WhatIf`
command. Complete sign-in in the Microsoft window and verify tenant identity.

Do not disable MFA, add permissions, or switch to app-only authentication to
work around the host. `-NonInteractive` suppresses toolkit prompts but cannot
create a desktop sign-in window. See the
[Microsoft WAM parent-window guidance](https://aka.ms/msal-net-wam#parent-window-handles).

## Recover from a partial deployment

There is no automatic rollback. Before apply, privately record the exact
policy IDs, states, targeting, emergency exclusions, ownership, and any
tenant-setting values that may change. Reports are redacted evidence, not
a complete backup.

After a failure, stop expansion and preserve that run's reports. With the
identity owner, inspect the precise object and whether the service accepted
the write. Restore approved before-state or withdraw only the newly created
pilot object when safe. Do not delete by display name, remove broad sets of
policies, or disable existing protection. Emergency-account removal requires
verified replacement access and review of every dependent policy.

If an existing policy requires manual migration, follow the
[migration procedure](Security-Defaults-Transition.md#corrected-app-protection-policy-and-existing-tenants).
After recovery, rerun `-WhatIf`, reconcile its findings, and obtain approval
before another apply or enforcement change.

## Escalation

Provide the product version, run time, module/action, sanitized error,
selected scope, and reviewed report excerpt. Record whether the issue is
sign-in, permission, configuration, readback, or incomplete health evidence.
Never include secrets, raw exports, unreviewed tenant reports, or private IDs
in a public issue. Live sign-in, role, policy impact, and recovery validation
remain the deployment and identity owners' responsibility.
