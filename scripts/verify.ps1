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

Write-Host "== Defender scaffold contract =="
$defenderRoot = Join-Path $prod 'Defender'
if (Test-Path -LiteralPath $defenderRoot) {
    $requiredDefenderFiles = @(
        'Deploy-DefenderBestPractice.ps1',
        'Config\DefenderConfig.psd1',
        'Modules\Connect-DefenderServices.ps1',
        'Modules\DefenderRunLog.ps1',
        'Modules\Invoke-WithTransientRetry.ps1',
        'Modules\Write-DefenderHtmlReport.ps1',
        'Modules\Setup-DefenderPreflight.ps1',
        'Modules\Setup-MdoEopBaseline.ps1',
        'Modules\Setup-DefenderForBusiness.ps1',
        'Modules\Setup-MdeAdvanced.ps1',
        'Modules\Setup-DefenderForCloudApps.ps1'
    )
    foreach ($relativePath in $requiredDefenderFiles) {
        $requiredPath = Join-Path $defenderRoot $relativePath
        if (Test-Path -LiteralPath $requiredPath) {
            Write-Host "  OK: Products/Defender/$relativePath"
        }
        else {
            Write-Host "  MISSING: Products/Defender/$relativePath"
            $failures++
        }
    }
    try {
        $defenderConfig = Import-PowerShellDataFile -LiteralPath (Join-Path $defenderRoot 'Config\DefenderConfig.psd1')
        $keys = @($defenderConfig.BestPracticeItems | ForEach-Object { $_.Key })
        if ($keys.Count -eq 0 -or @($keys | Where-Object { $_ -notmatch '^[a-z0-9]+(?:-[a-z0-9]+)+$' }).Count -gt 0) {
            Write-Host "  INVALID: Defender BestPracticeItems keys must use lowercase kebab-case."
            $failures++
        }
        elseif (@($keys | Sort-Object -Unique).Count -ne $keys.Count) {
            Write-Host "  INVALID: Defender BestPracticeItems keys must be unique."
            $failures++
        }
        else {
            Write-Host "  OK: Defender BestPracticeItems key contract"
        }
        $capabilityKeys = @($defenderConfig.LicenseCapabilities.Keys)
        $missingMappings = @($defenderConfig.BestPracticeItems | Where-Object {
            [string]::IsNullOrWhiteSpace([string] $_.LicenseCapability) -or
            $_.LicenseCapability -notin $capabilityKeys
        })
        if ($missingMappings.Count -gt 0) {
            Write-Host "  INVALID: Defender license capability mappings are incomplete."
            $failures++
        }
        else {
            Write-Host "  OK: Defender license capability mappings"
        }
        if (@($defenderConfig.Api.RequiredCommands).Count -eq 0) {
            Write-Host "  INVALID: Defender API command readiness contract is empty."
            $failures++
        }
        else {
            Write-Host "  OK: Defender API command readiness contract"
        }

        $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("defender-verify-" + [guid]::NewGuid().ToString('N'))
        try {
            New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
            . (Join-Path $defenderRoot 'Modules\DefenderRunLog.ps1')
            . (Join-Path $defenderRoot 'Modules\Write-DefenderHtmlReport.ps1')
            $fixtureJson = Join-Path $fixtureRoot 'fixture.json'
            $fixtureHtml = Join-Path $fixtureRoot 'fixture.html'
            Initialize-DefenderRunLog -JsonPath $fixtureJson -ScriptVersion $defenderConfig.ProductVersion
            Add-DefenderRunLogEntry -Module 'verify' -Action 'Fixture' -Status 'Info' `
                -BestPracticeKey 'mdo-safe-attachments' -Disposition 'Applicable' `
                -Detail 'access_token=fixture-secret'
            Add-DefenderRunLogEntry -Module 'verify' -Action 'Fixture' -Status 'Skipped' `
                -Disposition 'GuidedOnly' -Detail 'guided-only fixture'
            Save-DefenderRunLogJson
            Write-DefenderHtmlReport -Path $fixtureHtml -Entries (Get-DefenderRunLog)
            $fixturePayload = Get-Content -LiteralPath $fixtureJson -Raw | ConvertFrom-Json
            $fixtureMarkup = Get-Content -LiteralPath $fixtureHtml -Raw
            if ($fixturePayload.entryCount -ne 2 -or
                $fixturePayload.entries[0].detail -match 'fixture-secret' -or
                $fixtureMarkup -notmatch 'Disposition' -or
                $fixtureMarkup -notmatch 'GuidedOnly') {
                throw 'Defender logger/report fixture assertions failed.'
            }
            Write-Host "  OK: Defender logger/report fixture"
        }
        catch {
            Write-Host "  INVALID: Defender logger/report fixture -> $($_.Exception.Message)"
            $failures++
        }
        finally {
            Clear-DefenderRunLog
            if (Test-Path -LiteralPath $fixtureRoot) {
                Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
            }
        }
    }
    catch {
        Write-Host "  INVALID: Defender configuration contract -> $($_.Exception.Message)"
        $failures++
    }
}

Pop-Location
if ($failures -gt 0) { Write-Host "verify.ps1 FAILED with $failures error(s)." -ForegroundColor Red; exit 1 }
Write-Host "verify.ps1 PASSED." -ForegroundColor Green
exit 0
