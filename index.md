---
title: Home
layout: home
nav_order: 1
description: "Best-practice deployment toolkits for Microsoft 365 SMB tenants."
permalink: /
---

# SMB Best Practice Tool

PowerShell automation that configures Microsoft 365 tenants against
Microsoft's recommended best-practice baselines for **Small / Medium**
customers. Built for repeatable, idempotent configuration of Microsoft 365
tenants — by partners/MSPs and in-house IT teams alike.

> ⚠️ **Always pilot in a test tenant before applying to production.** Many
> changes are tenant-wide and can take up to 24 hours to fully propagate.

---

## Available product toolkits

| Product | Toolkit | Status |
|---|---|---|
| [Microsoft Purview](purview/) — Data Security baseline (license-aware: Business Premium and up) | `Products/Purview/` | ✅ Available |
| [Microsoft Entra](entra/) — Conditional Access baseline (report-only, break-glass safe) | `Products/Entra/` | Candidate; release authorization required |
| [Microsoft Intune](intune/) — device management & enrollment baseline | `Products/Intune/` | Candidate; release authorization required |
| [Microsoft Defender](defender/) - read-only default with pilot-validated ASR Audit configuration | `Products/Defender/` | Candidate; release authorization required |

> 🗺️ **See the method at a glance:** the
> [**Purview Deployment Framework**](purview/deployment-framework/) is an
> interactive visual model of how the toolkit deploys — pre-deployment to
> post-deployment, with the simulate-then-promote safety gate front and centre.

Pick a product from the sidebar (or the table above) for its full
documentation: what it does, prerequisites, how to run, scenarios it
covers, change-management playbook, and end-user adoption material.

> 🆕 **What's new?** See the [**Changelog**](changelog/) for new features,
> changed defaults, and fixes across releases.

---

## Common prerequisites (all toolkits)

Each toolkit documents its own detailed prerequisites. Common requirements
across all of them:

* **PowerShell 7+** (`pwsh.exe`) to **run** the toolkits — the deploy
  scripts hard-fail on Windows PowerShell 5.1 because the Exchange
  Online v3 REST channel and Microsoft.Graph SDK depend on .NET Core
  APIs that PS 5.1 doesn't expose. Install with
  `winget install --id Microsoft.PowerShell` or from
  <https://aka.ms/PowerShell-Release>.
* **Windows** host with PS 5.1 still present — the
  `Microsoft.Online.SharePoint.PowerShell` module is Windows-only and
  is loaded automatically via `Import-Module -UseWindowsPowerShell`
  (a hidden PS 5.1 sub-process) so its bundled MSAL DLL never enters
  PS 7's AppDomain. macOS and Linux are not supported.
* **Tenant admin credentials** with the appropriate role(s) for the
  product being deployed (see each product's page for the exact role map).
* **Required PowerShell modules** - each product documents its supported
  installation path. Do not assume `-AutoInstallModules` is available unless
  that product's documentation explicitly says so.

### Shared delegated Graph authentication

Purview, Entra, and Intune use the same delegated Microsoft Graph operator
flow. Supply `-TenantAdminUpn` for a direct tenant run, or add
`-DelegatedOrganization` to target a GDAP customer tenant. Each product
connects Graph once per run, reuses a cached context only when its account,
scopes, and tenant match, and verifies live tenant identity before setup.

Each product still requests only its own configured Graph scopes. Use
`-AutoInstallModules` for documented module installation. `-NonInteractive`
suppresses toolkit prompts but does not enable app-only authentication or
guarantee a prompt-free first sign-in.

---

## Quick start

**Trying Intune?** Start with the
[Intune first-run guide](Products/Intune/README.md#first-time-here-start-with-a-preview).
It leads from prerequisites to a read-only preview, then to pilot group setup,
separate high-risk stages, and troubleshooting. A successful preview does not
prove that tenant writes or recovery have been validated.

**Trying Entra?** Use the
[Entra first-run guide](Products/Entra/README.md#first-time-here-start-with-a-preview)
for an assessment without tenant changes, then the
[operator guide](Products/Entra/docs/Operator-Guide.md) for emergency access,
pilot scope, and approval gates. A blocked first run or indeterminate health
verdict needs review, not removal of existing protection.

For a Purview preview:

```powershell
# Clone the repo, then run the toolkit for the product you want to configure.
# Example: Purview baseline against a Business Premium tenant.
git clone https://github.com/microsoft/BestPractice_Deploy-Scripts.git
cd BestPractice_Deploy-Scripts\Products\Purview
.\Deploy-PurviewBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com -WhatIf
```

---

## Disclaimer

This sample script is **not** supported under any Microsoft standard
support program or service. The sample script is provided AS IS without
warranty of any kind. The full disclaimer and license are in the
[repository LICENSE file](https://github.com/microsoft/BestPractice_Deploy-Scripts/blob/main/LICENSE).

Please do not contact Microsoft support with any issues or concerns
regarding this script.
