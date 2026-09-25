# SMBBestPracticeTool

PowerShell automation that configures Microsoft 365 tenants against
Microsoft's recommended best-practice baselines for Small / Medium customers.

Built for repeatable, idempotent configuration of Microsoft 365 tenants — by
partners/MSPs and in-house IT teams alike.

## Products

| Product | Toolkit | Docs | Status |
|---------|---------|------|--------|
| Microsoft Purview (Data Security baseline for Business Premium) | [`Products/Purview/`](Products/Purview/README.md) | [Site](https://microsoft.github.io/BestPractice_Deploy-Scripts/purview/) | Available |
| Microsoft Defender (read-only default with pilot-validated ASR Audit configuration) | [`Products/Defender/`](Products/Defender/README.md) | [Site](https://microsoft.github.io/BestPractice_Deploy-Scripts/defender/) | Candidate; release authorization required |
| Microsoft Intune (device management & enrollment baseline) | [`Products/Intune/`](Products/Intune/README.md) | [Site](https://microsoft.github.io/BestPractice_Deploy-Scripts/intune/) | Candidate; release authorization required |
| Microsoft Entra (Conditional Access baseline for Business Premium) | [`Products/Entra/`](Products/Entra/README.md) | [Site](https://microsoft.github.io/BestPractice_Deploy-Scripts/entra/) | Candidate; release authorization required |

> 📖 **Full documentation site:** <https://microsoft.github.io/BestPractice_Deploy-Scripts/>
> — searchable HTML version of every product's docs, with sidebar
> navigation and per-product landing pages. Source markdown stays in
> `Products/<Product>/docs/`; the site is built by GitHub Pages from
> the same files.

## Prerequisites (at a glance)

Each product toolkit documents its own detailed prerequisites in its README.
Common requirements across all toolkits:

* **PowerShell 7+** (`pwsh.exe`) — Windows PowerShell 5.1 is **not supported**.
  Install with `winget install --id Microsoft.PowerShell` or from
  <https://aka.ms/PowerShell-Release>.
* **Tenant admin credentials** with the appropriate role(s) for the product
  being deployed (see each product's README for the exact role mapping).
* **Required PowerShell modules**: follow the selected product's README.
  Use `-AutoInstallModules` only where the product documents support for it.

For the full prerequisite list (licensing, admin roles, modules) for the
Purview toolkit, see [`Products/Purview/README.md`](Products/Purview/README.md#prerequisites).

## Quick start

```powershell
# Clone the repo, then run the toolkit for the product you want to configure.
# Example: Purview baseline against a Business Premium tenant.
cd Products/Purview
.\Deploy-PurviewBestPractice.ps1 -TenantAdminUpn admin@contoso.onmicrosoft.com -WhatIf
```

> ⚠️ **Always pilot in a test tenant before applying to production.** Many
> changes are tenant-wide and can take up to 24 hours to fully propagate.

## License

See [`LICENSE`](LICENSE).

## Disclaimer

This sample script is not supported under any Microsoft standard support
program or service. The sample script is provided AS IS without warranty of
any kind. Microsoft further disclaims all implied warranties including,
without limitation, any implied warranties of merchantability or of fitness
for a particular purpose. The entire risk arising out of the use or
performance of the sample scripts and documentation remains with you. In no
event shall Microsoft, its authors, or anyone else involved in the creation,
production, or delivery of the scripts be liable for any damages whatsoever
(including, without limitation, damages for loss of business profits,
business interruption, loss of business information, or other pecuniary loss)
arising out of the use of or inability to use the sample scripts or
documentation, even if Microsoft has been advised of the possibility of such
damages.

Please do not contact Microsoft support with any issues or concerns regarding
this script.
