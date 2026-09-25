---
title: Intune evidence and troubleshooting
layout: default
parent: Intune
---

# Intune evidence and troubleshooting

## Evidence handling

HTML and JSON reports are tenant evidence. Keep them in the approved private
customer location. Do not commit or publish them. The toolkit applies
pattern-based redaction to tenant IDs, domains, administrator identities,
tokens, GUID-shaped identifiers, and implemented normalized response fields.
It does not prove that every possible service-authored message is safe to
share. Review sanitized excerpts before escalation.

`-WhatIf` distinguishes preview intent from applied changes. A preview must not
contain `Created`, `Updated`, or `Adopted` tenant actions. An apply can contain
those statuses only for the selected supported write paths.

## Common failures

Compliance and enrollment restriction verification compares managed settings
and the exact assignment, including on reruns. A matching name, a successful
POST, or one matching group among several assignments is not proof of success.
The create-only writers stop on drift, duplicate ownership or missing evidence;
they do not repair existing policies automatically.

| Symptom | Likely cause | Resolution |
| --- | --- | --- |
| Tenant identity mismatch | Wrong account, tenant ID, or delegated organization. | Stop. Reconnect to the intended tenant and verify its canonical domain. |
| `401` or `403` | Missing consent, Graph scope, Entra role, Intune RBAC, GDAP assignment, or expired session. | Compare the exact operation with the API permission matrix; do not add broad permissions speculatively. |
| Conditional Access list/read returns `403` | The signed-in Graph context lacks the documented Conditional Access read/write permission pair, or the operator lacks the required Entra role. | Reconnect with the configured `Api.GraphScopes`, including `Policy.Read.All` and `Policy.ReadWrite.ConditionalAccess`, and confirm the operator has Conditional Access Administrator or Security Administrator. |
| License disposition is skipped | Required SKU/service plan was not detected or mapping needs review. | Confirm active subscriptions and current Microsoft catalog metadata. |
| Missing Graph command | Required Microsoft Graph PowerShell module is absent. | Install the documented module for the current user and rerun PowerShell 7. |
| `Microsoft.Graph.Authentication` assembly with the same name is already loaded | Graph SDK module versions differ, or a previous import left a conflicting assembly in this process. | Use a fresh PowerShell 7 session and matching Authentication/DeviceManagement versions. Follow the module recovery steps below; do not change tenant permissions. |
| `A window handle must be configured` during Graph sign-in | WAM cannot attach its sign-in window to the current host. | Use the interactive-terminal recovery steps below; do not change scopes or switch to app-only authentication. |
| Apple certificate assessment returns `GuidedOnly` with `404` | Graph did not return the certificate singleton, and Microsoft does not document `404` as proof of an unconfigured certificate. | Verify Apple MDM Push certificate status in the Intune admin center, complete setup or renewal if needed, and retain the guided result. |
| Default compliance assessment reports an unknown projection | Graph returned a nullable or missing `SecureByDefault` projection, which does not prove the portal's effective state. | Verify the Compliance policy settings page and retain the `GuidedOnly` result. The toolkit does not write from an unknown pre-write state. |
| Default compliance post-write readback is unavailable | Graph accepted the update but did not return a verifiable Boolean `SecureByDefault` value. | Treat the run as blocked, preserve the evidence, and verify **Devices > Compliance > Compliance settings** before rerunning or continuing deployment. |
| Compliance inventory reports scheduled-action readback unavailable | The documented v1.0 `scheduledActionsForRule` relationship returned `400` because no GET route matched. | Retain policy and assignment inventory, do not interpret the action count as zero, and keep scheduled-action automation blocked. |
| Compliance write or rerun cannot verify scheduled actions | The rule collection or its `scheduledActionConfigurations` child read is unavailable or differs from the payload. | Stop rollout and inspect the policy and assignments in Intune. Inventory may still be useful, but this is not `Verified`. Do not create another policy to bypass the failed read. |
| Enrollment assignment scope is `Unknown` with only exclusions | No inclusion target proves pilot scope. | Inspect assignments in Intune and record the approved include target. Do not infer pilot-only coverage from an exclusion. |
| Enrollment restriction type differs between older and newer objects | Graph beta exposes both a single-platform type with `platformType`/`platformRestriction` and a legacy multi-platform type with per-platform fields. | Use the current toolkit's beta inventory and readback. It handles the shapes separately and does not silently convert an existing object. |
| Enrollment restriction ID is not a GUID | Intune returned a service-defined opaque configuration ID. | Use the current toolkit, which URL-encodes non-empty opaque IDs and excludes them from evidence. Do not rewrite or expose the identifier. |
| Enrollment restriction assessment fails on an assignment with no target | Graph returned an assignment object without a `target`, so targeting cannot be described. The assessment stops rather than reporting a scope it could not read. | Treat as failed, retain the sanitized evidence, and reconcile the restriction's assignments in the portal before rerunning. Earlier toolkit versions could skip this check depending on the order Graph returned assignments, so a run that previously succeeded may now surface it. |
| App-protection policy ID is not a GUID | Intune returned a service-defined opaque Android or iOS/iPadOS policy ID. | Use the current toolkit, which URL-encodes non-empty opaque IDs for relationship reads and excludes them from evidence. |
| Existing object name blocks a create | A Microsoft 365 Apps deployment, app-protection policy, compliance policy, enrollment restriction, or Conditional Access policy already uses the configured name but is not a verified equivalent toolkit object. | Do not use `-AdoptExisting` to bypass the collision. Audit or rename the existing object, or choose a different configured name. |
| Conditional Access readback returns `404` immediately after create | Graph accepted the create, but the Conditional Access read endpoint has not synchronized yet. | Let the bounded retry complete. If the terminal readback still fails, inspect the portal and preserve the report before rerunning. |
| Managed enrollment/compliance object has an unexpected name | A toolkit-managed object was renamed, or configured names changed after deployment. | Stop and reconcile the original object ID with the deployment record before aligning names. Do not strip its marker or create a replacement blindly. Renamed apps/app-protection objects and exactly equivalent CA policies are no-ops instead. |
| Post-write readback fails or mismatches | The service did not return the created object or its critical fields did not match the approved intent. | Treat the run as failed. Stop expansion, inspect the portal and prior evidence, and use the documented recovery path before rerunning. |
| `429`, `5xx`, or timeout | Transient throttling or service failure. | Allow the shared bounded retry helper to run; rerun if the terminal failure remains. |
| Malformed or incomplete response | API contract drift or unsupported tenant state. | Treat as failed, retain sanitized evidence, and raise with the module/API owner. |
| `GuidedOnly` | The action is interactive, beta-only, incompletely comparable, or unapproved for writes. | Follow the roadmap workflow and capture independent verification evidence. |
| Safety gate refusal | Missing approval, pilot scope, emergency access, rollback acknowledgment, or category opt-in. | Do not bypass the gate. Complete change control and rerun. |

## Policy API references

The following contracts were checked September 25, 2026. Offline tests do not
establish tenant support, effective permissions or service propagation behavior.

- [Single-platform enrollment creation, beta](https://learn.microsoft.com/graph/api/intune-onboarding-deviceenrollmentplatformrestrictionconfiguration-create?view=graph-rest-beta)
- [Legacy multi-platform enrollment shape, beta](https://learn.microsoft.com/graph/api/resources/intune-onboarding-deviceenrollmentplatformrestrictionsconfiguration?view=graph-rest-beta)
- [Compliance scheduled-action rules, v1.0](https://learn.microsoft.com/graph/api/intune-deviceconfig-devicecompliancescheduledactionforrule-list?view=graph-rest-1.0)
- [Compliance scheduled-action children, v1.0](https://learn.microsoft.com/graph/api/intune-deviceconfig-devicecomplianceactionitem-list?view=graph-rest-1.0)

## Graph module version conflicts

DeviceManagement requires the matching Authentication SDK release. For
example, installing DeviceManagement 2.40.0 into a shell that has already
loaded Authentication 2.37.0 can fail before Graph sign-in. This is a local
PowerShell dependency problem, not a tenant role or consent failure.

1. Preserve the console output and any saved reports, then close the
   PowerShell session that reported the assembly conflict.
2. Open a fresh PowerShell 7 session (`pwsh -NoProfile`). Do not import other
   Graph versions first.
3. With the current toolkit, rerun the intended preview with `-WhatIf`. The
   prerequisite check selects a matching DeviceManagement version. Approve
   its CurrentUser installation if permitted, or use `-AutoInstallModules`
   only when that installation is already approved.
4. If installation is managed separately, use the
   [matching-version installation commands](Operator-Guide.md#before-you-run),
   then start a fresh shell before the preview.

The toolkit never removes other installed versions or tries to unload a
conflicting assembly. `Remove-Module` alone is not a restart. An import
failure stops before sign-in and is recorded as a failed prerequisite.
`-NonInteractive` without installation approval prints the exact
`Install-Module -RequiredVersion` command instead of prompting.

References, checked 2026-09-25:
[Install-Module version selection](https://learn.microsoft.com/powershell/module/powershellget/install-module)
and [PowerShell assembly conflicts](https://learn.microsoft.com/powershell/scripting/dev-cross-plat/resolving-dependency-conflicts).
The installed DeviceManagement 2.39.0 manifest was also checked: its
`RequiredModules` pins Authentication with `RequiredVersion = '2.39.0'`.
Offline fixtures cover the reported 2.37.0/2.40.0 mismatch. A fresh-session
preview on the affected workstation remains the live confirmation.

## Windows sign-in needs a window handle

The Graph SDK can require a parent window for WAM even when the toolkit reports
that the Windows version supports it. **WAM broker available** describes the
machine, not a guarantee that an embedded or background host can show a prompt.

1. Open **Windows Terminal > PowerShell 7** or the **PowerShell 7** desktop app
   yourself. Use an interactive user session, not a background job or service.
2. Change to the same `Products\Intune` folder and rerun the original
   `-TenantAdminUpn ... -WhatIf` command. Do not add high-risk or apply switches.
3. Complete the Microsoft account selection and any approved consent prompt.
   Verify the requested tenant and permissions. Enter credentials only in the
   Microsoft sign-in window.
4. Wait for **Tenant identity verified** and run completion. Repeat the command
   in that same shell; a matching context should log `reason=reused`.

`-NonInteractive` suppresses toolkit prompts; it does not provide a sign-in
window. A successful interactive sign-in may allow later cached runs, but it
does not guarantee unattended access after expiration or a tenant switch.
If the error persists in the desktop terminal, retain the redacted report and
PowerShell/Graph module versions for support. Do not disable MFA or tenant
Conditional Access, add permissions, or reuse another tenant's token.

This uses the same delegated Graph sign-in pattern as Purview. No device-code,
certificate, or secret-based fallback is automatically selected. Microsoft
documents the [WAM parent-window requirement](https://aka.ms/msal-net-wam#parent-window-handles).

## Review a completed report

Use the HTML file for the operator review and the JSON file for deterministic
checks.

The final console output announces each successfully saved report's full
path, even when sign-in or a later module fails after logging starts. Copy the
printed `Invoke-Item -LiteralPath` command to open the HTML; the toolkit does
not launch a browser. Default paths remain under the product's `Reports`
folder and can be changed in the private configuration's `Report` section.

A write warning means that report was not confirmed saved. An older file may
still exist at the same path, so do not treat its presence as current evidence.
Saving HTML and JSON is attempted independently, and an HTML-write failure
does not replace an earlier deployment error. Preserve any surviving report
and console output before retrying.

If an earlier prerequisite or module fails, selected modules that never start
are recorded as `Skipped` with a `Blocked` disposition and a reason. An
explicit skip retains its skip evidence. `ConfiguredItem` and `WriteRiskGate`
entries describe intent, not a completed assessment. Read the module result
and its lifecycle evidence before treating any step as complete.

Evidence-write warnings remain nonterminating even with `-WarningAction Stop`
so they cannot replace the original deployment error or prevent the other
report from being attempted. This does not suppress the warning.

```powershell
$report = Get-Content ./Reports/intune-run-log.json -Raw |
  ConvertFrom-Json

$report.moduleSummary |
  Sort-Object module |
  Format-Table module, result, entryCount

$report.entries |
  Where-Object status -in @('Created', 'Updated', 'Adopted')
```

Treat an empty second result as required for `-WhatIf`. For an apply, compare
every returned entry with the approved change and confirm its readback.

## Compare the five automated assessments

| Assessment | Portal comparison | When to stop |
| --- | --- | --- |
| Apple certificate | **Devices > Device onboarding > Enrollment > Apple > Apple MDM Push Certificate** | Portal and report disagree on active or renewal state. |
| Default compliance | **Devices > Manage devices > Compliance > Compliance settings** or **Endpoint security > Device compliance > Compliance policy settings** | Effective treatment of devices without a policy is unclear or differs. |
| Enrollment restrictions | **Devices > Device onboarding > Enrollment > Enrollment options > Device platform restriction** | Count or assignment scope cannot be reconciled without exposing identifiers. |
| App protection | **Apps > Manage apps > Protection** | Platform policy or target-app availability differs from the report. |
| Device compliance | **Devices > Manage devices > Compliance > Policies** or **Endpoint security > Device compliance > Policies** | Platform policy or assignment inventory differs, or scheduled-action state is assumed from an unavailable read. |

A discrepancy blocks closure and requires investigation; it is not approval to
edit the setting again.

## Task-specific recovery

### Apple certificate

If the assessment returns guided `404`, verify the portal. Do not create a new
certificate until the customer Apple identity owner confirms whether an
existing certificate should be renewed. Renew with the same Apple account and
certificate identity whenever possible.

### Default compliance

A nullable or missing Graph projection does not prove the effective setting and
remains a guided result. The toolkit will not write from that unknown state.
Before any change, confirm the portal state, ensure platform compliance
policies reach pilot devices, and review the effect of existing Conditional
Access. An unavailable post-write readback blocks continuation.

### Enrollment restrictions

Opaque configuration IDs are valid service identifiers. Do not rewrite or
publish them. Reconcile policy count, platform, priority, ownership controls,
and assignment scope in the portal.

The assessment reports `AssignedScope` and `ExclusionCount` across the combined
assignments of every platform restriction it read:

| `AssignedScope` | Meaning |
| --- | --- |
| `None` | No assignments were returned. |
| `PilotOnly` | Every include target resolved to the pilot group you supplied. |
| `Broad` | A target reaches all users or all devices, an include target resolved to a group other than the pilot group, or no pilot group was supplied. |
| `Unknown` | A target could not be read confidently, so the toolkit will not claim narrower targeting than it can prove. |

`Unknown` is a deliberate and safe result. It is reported when a target type is
unrecognized, when a group identifier is missing or empty, or when a target
carries two different group identifiers with no way to tell which one applies.

`ExclusionCount` counts exclusion group targets across those same assignments.
Every assignment is inspected before the scope is reported, so the count does
not depend on the order Microsoft Graph returns assignments in. Compare it
against the portal rather than assuming the two lists arrive in the same order.

### App protection

Policy inventory does not prove settings are correct. Review Android and
iOS/iPadOS independently. Target-app readback that is unavailable remains
unknown and must not be treated as an empty target list.

### Device compliance

If scheduled-action readback is unavailable, retain the platform policy and
assignment inventory and verify actions in the portal. Do not infer zero
actions and do not enable related automation.

## Recovery principles

Assessments are safe to rerun. Supported writes must preserve unrelated
customer properties and assignments, perform bounded readback, and converge on
an idempotent rerun. Use the documented manual or automated recovery for a
partial failure; a delete API alone is not proof of rollback.

## Recover a partial pilot deployment

There is **no automatic rollback command**. The current create-only writers
also do not repair assignment or targeting on an existing managed object.
An `AlreadyCompliant` rerun must not be used to dismiss an earlier partial
failure. Recovery is an approved portal operation, not a reason to add
`-AdoptExisting` or delete policies by name.

Before apply, record the exact object IDs, ownership markers, settings,
assignments, exclusions, and enrollment priorities that may be affected.
Record which objects did **not** exist. Store this privately; report redaction
means the toolkit log is not a complete backup or object-ID inventory.

After a failure, stop subsequent stages and preserve that run's reports before
rerunning, because the normal filenames are overwritten. Match the failed
action to the exact object in the portal and check whether the service accepted
the preceding create, targeting, or assignment request.

| Changed object | Approved recovery action | Evidence needed before closing |
|---|---|---|
| Microsoft 365 Apps | In **Apps > All apps**, open the exact new deployment. Remove only the pilot assignment added by this run. Delete the new app object only after confirming no other assignments or dependencies use it. Do not change a pre-existing app object. | Assignment is absent and device install status is reviewed. Removing a Required assignment or deleting the app definition does not undo an installation; uninstall is a separate approved device action. |
| Android/iOS app protection | In **Apps > Manage apps > Protection**, open the exact new policy and remove only its pilot assignment. If creation succeeded but targeting or assignment failed, either complete the approved configuration manually or remove the newly created, unassigned policy before a clean retry. | Targeted apps and assignments match the approved recovery state. Removing a policy does not restore data already wiped or reverse every app-side effect. |
| Device compliance policy | In **Devices > Manage devices > Compliance > Policies**, restore the prior known-good assignment and policy coverage before removing a new policy or assignment. Do not leave devices without coverage when the default is Not compliant. | Pilot devices check in and their compliance and sign-in results recover. Removing a policy can itself cause noncompliance; stop and involve the identity owner if access is affected. |
| Enrollment restriction | In **Devices > Device onboarding > Enrollment > Enrollment options > Device platform restriction**, remove only the new pilot assignment or new restriction after confirming the prior restriction and priority will apply. Do not delete or rewrite the built-in default. | Effective platform/ownership restrictions and priorities match the before-state; a representative enrollment behaves as expected. Existing enrollment is not undone by removing a restriction. |
| Default compliance setting | In **Devices > Manage devices > Compliance > Compliance settings**, restore the recorded treatment of devices with no policy and the recorded validity period. This is a tenant-wide change requiring the identity/change owner's approval, not a pilot-only undo. | Saved settings match the before-state and affected devices/sign-ins are reviewed after reevaluation. Do not blindly set Compliant as a universal recovery default. |
| Enrollment Conditional Access | In **Entra ID > Conditional Access > Policies**, verify the exact toolkit policy and its report-only state. With identity-owner approval, disable or delete only the newly created policy if it must be withdrawn. If someone separately enabled it, follow the access incident plan and restore the approved prior state, not a blanket disable of other policies. | Prior access protection and emergency-access paths still work; sign-in evidence matches the approved state. Do not delete the Intune Enrollment service principal as routine rollback: other policies or enrollment flows can depend on it. |

Do not proceed when ownership, before-state, or dependencies are uncertain.
Keep the rollout stopped and involve the deployment and identity owners.
After recovery, run the same stage with `-WhatIf`, reconcile every proposed
change, and obtain approval before any new apply. A fresh run must have its own
report pair and a device/portal confirmation; a successful API response alone
does not prove recovery.

## Escalation record

When raising an issue, include product version, UTC timestamp, module/action,
sanitized status code, selected authentication mode, Graph module version,
license class, expected disposition, and redacted report excerpt. Never include
tokens, certificate material, raw tenant exports, customer identities, or
unredacted payloads.

Use [Future Intune write capabilities](Future-Write-Capabilities.md) to route
API gaps to the correct Microsoft product group and validation gaps to the
product, security, permissions, or pilot owner.

Copy-ready commands are in
[assessment and deployment examples](../Examples/Read-Only-Assessment.md).

The deployment team running the toolkit owns tenant operations, customer
change control, and customer evidence retention. Report repository defects
through the [public issue tracker](https://github.com/microsoft/BestPractice_Deploy-Scripts/issues).
Report security vulnerabilities using [SECURITY.md](../../../SECURITY.md), not public issues.
