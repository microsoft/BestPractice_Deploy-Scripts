# Conventions — BestPractice_Deploy-Scripts

Observed conventions. Derived from the current structure; update as it evolves.

## Layout
- **`Products/<Product>/Deploy-*.ps1`** — top-level orchestrator per product.
- **`Products/<Product>/Modules/`** — one task per file (`Setup-*.ps1`), plus shared helpers
  (`Connect-*`, `Invoke-WithTransientRetry`, `PurviewRunLog`, `Write-*HtmlReport`).
- **`Products/<Product>/Config/*.psd1`** — configuration as PowerShell data files.
- **`Products/<Product>/AdHoc/`** — standalone one-off scripts.
- **`Products/<Product>/docs/` & `Examples/`** — playbooks, references, examples.

## Authoring conventions
- Keep tasks idempotent and safe to re-run; funnel transient failures through
  `Invoke-WithTransientRetry`.
- One logical task per `Setup-*.ps1`; put shared logic in `Modules/`.
- Keep tenant-specific values in `Config/*.psd1`, never hard-coded in scripts.
- No secrets, tokens, tenant identifiers, or customer data in scripts, config, or logs.

## Validation
`pwsh scripts/verify.ps1` — syntax-parses all `Products/**/*.ps1` and validates
`Products/**/*.psd1` config files.
