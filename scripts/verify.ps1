#!/usr/bin/env pwsh
# verify.ps1 - Readiness verify loop for BestPractice_Deploy-Scripts.
# Non-fragile checks: syntax-parse all PowerShell under Products/ and validate *.psd1 config.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
$failures = 0

Write-Host "== Syntax check: Products/**/*.ps1 =="
$targets = @()
$prod = Join-Path $root 'Products'
if (Test-Path $prod) { $targets = Get-ChildItem -Path $prod -Recurse -File -Filter *.ps1 -ErrorAction SilentlyContinue }
if (-not $targets) { Write-Host "  WARN: no .ps1 found under Products/." }
foreach ($f in $targets) {
    $tk=$null; $er=$null
    [System.Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$tk,[ref]$er) | Out-Null
    if ($er -and $er.Count -gt 0) {
        Write-Host "  SYNTAX: $($f.FullName)"; $er | ForEach-Object { Write-Host "    $($_.Message)" }; $failures++
    }
}
if ($failures -eq 0 -and $targets) { Write-Host "  OK: $($targets.Count) file(s) parse cleanly." }

Write-Host "== Config check: Products/**/*.psd1 =="
$psd1 = Get-ChildItem -Path $prod -Recurse -File -Filter *.psd1 -ErrorAction SilentlyContinue
foreach ($c in $psd1) {
    try { Import-PowerShellDataFile -Path $c.FullName -ErrorAction Stop | Out-Null; Write-Host "  OK: $($c.Name)" }
    catch { Write-Host "  INVALID: $($c.FullName) -> $($_.Exception.Message)"; $failures++ }
}

Pop-Location
if ($failures -gt 0) { Write-Host "verify.ps1 FAILED with $failures error(s)." -ForegroundColor Red; exit 1 }
Write-Host "verify.ps1 PASSED." -ForegroundColor Green
exit 0
