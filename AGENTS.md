# AGENTS.md — BestPractice_Deploy-Scripts

**PowerShell deployment scripts** implementing Microsoft best-practice configurations
(currently Microsoft Purview) as repeatable, idempotent automation. This file is the entry
point for humans and coding agents. Copilot-specific guidance already lives in
[`.github/copilot-instructions.md`](.github/copilot-instructions.md).

## Repository map
| Path | What lives here |
| --- | --- |
| `Products/Purview/Deploy-PurviewBestPractice.ps1` | Top-level orchestrator. |
| `Products/Purview/Modules/` | Task modules: `Setup-DLP.ps1`, `Setup-Retention.ps1`, `Setup-SensitivityLabels.ps1`, `Setup-AIGovernance.ps1`, `Setup-TenantSettings.ps1`, `Connect-PurviewServices.ps1`, `Invoke-WithTransientRetry.ps1`, `PurviewRunLog.ps1`, `Write-PurviewHtmlReport.ps1`. |
| `Products/Purview/Config/PurviewConfig.psd1` | Deployment configuration (data file). |
| `Products/Purview/AdHoc/` | Standalone helper scripts. |
| `Products/Purview/docs/`, `Products/Purview/Examples/` | Playbooks, references, examples. |
| `.github/copilot-instructions.md` | Copilot guardrails. |

## Conventions
See [`docs/conventions.md`](docs/conventions.md).

## Verification / Definition of Done
```powershell
pwsh scripts/verify.ps1
```
`verify.ps1` syntax-checks every `*.ps1` under `Products/` and validates that the
`*.psd1` configuration files parse as PowerShell data files. A change is done when
`verify.ps1` passes and the affected deployment path has been dry-run/validated against a
non-production tenant.

## PR & work-item telemetry — required
Every PR must follow [`.github/instructions/telemetry.instructions.md`](.github/instructions/telemetry.instructions.md).
