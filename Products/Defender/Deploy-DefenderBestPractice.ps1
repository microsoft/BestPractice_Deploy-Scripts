#requires -Version 7.0
<#
.SYNOPSIS
    Scaffolding entry point for the Microsoft Defender Best Practice Toolkit.

.DESCRIPTION
    Applies verified Defender recommendations using Purview-compatible
    orchestration semantics. The scaffold is intentionally read-only until
    each BP item has a verified supported API, permission model, license gate,
    readback projection, and rollback decision.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')] [string] $TenantAdminUpn,
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')] [string] $TenantId,
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')] [string] $ClientId,
    [ValidatePattern('^[0-9a-fA-F]{40}$')] [string] $CertificateThumbprint,
    [ValidatePattern('^[^@\s]+\.[^@\s]+$')] [string] $DelegatedOrganization,
    [string] $ConfigPath,
    [switch] $NonInteractive,
    [switch] $AutoInstallModules,
    [switch] $NoLicenseAutoDetect,
    [switch] $AdoptExisting,
    [switch] $SkipPreflight,
    [switch] $SkipMdoEop,
    [switch] $SkipDefenderForBusiness,
    [switch] $SkipMdeAdvanced,
    [switch] $SkipDefenderForCloudApps,
    [switch] $IncludeHighRisk,
    [string] $CustomerApprovalId,
    [string] $ApprovalArtifactPath,
    [switch] $RollbackAcknowledged,
    [switch] $EnableMailFlowImpactingChanges,
    [switch] $EnableAutomatedRemediation,
    [switch] $EnableAsrBlockMode,
    [switch] $EnableMdcaEnforcement,
    [switch] $CloudDiscoveryReviewed,
    [string] $PilotGroupId
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleRoot = Join-Path $scriptRoot 'Modules'
$runId = [guid]::NewGuid()
$startTime = [datetime]::UtcNow
$jsonPath = $null
$htmlPath = $null

. (Join-Path $moduleRoot 'DefenderRunLog.ps1')
. (Join-Path $moduleRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $moduleRoot 'Write-DefenderHtmlReport.ps1')

function Test-DefenderConfigContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Config)

    if (-not $Config.BestPracticeItems) {
        throw 'Defender configuration must define at least one BestPracticeItems entry.'
    }
    $keys = @()
    foreach ($item in @($Config.BestPracticeItems)) {
        foreach ($property in @('Key', 'Name', 'Module', 'Risk')) {
            if ([string]::IsNullOrWhiteSpace([string] $item[$property])) {
                throw "BestPracticeItems entries must define '$property'."
            }
        }
        if ([string]::IsNullOrWhiteSpace([string] $item.LicenseCapability) -or
            -not $Config.LicenseCapabilities.ContainsKey([string] $item.LicenseCapability)) {
            throw "BestPracticeItems entry '$($item.Key)' must reference a configured LicenseCapability."
        }
        if ($item.Key -notmatch '^[a-z0-9]+(?:-[a-z0-9]+)+$') {
            throw "BestPracticeItems key '$($item.Key)' must be lowercase kebab-case."
        }
        if ($keys -contains $item.Key) {
            throw "Duplicate BestPracticeItems key '$($item.Key)'."
        }
        $keys += $item.Key
    }
}

try {
    $certificateArguments = @($TenantId, $ClientId, $CertificateThumbprint) |
        ForEach-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if (($certificateArguments | Where-Object { $_ }).Count -gt 0 -and
        ($certificateArguments | Where-Object { -not $_ }).Count -gt 0) {
        throw 'TenantId, ClientId, and CertificateThumbprint must be supplied together for certificate authentication.'
    }

    if ($IncludeHighRisk -and [string]::IsNullOrWhiteSpace($CustomerApprovalId)) {
        throw 'IncludeHighRisk requires CustomerApprovalId.'
    }
    if ($ApprovalArtifactPath) {
        if (-not (Test-Path -LiteralPath $ApprovalArtifactPath -PathType Leaf)) {
            throw "Approval artifact not found: $ApprovalArtifactPath"
        }
        if ((Get-Item -LiteralPath $ApprovalArtifactPath).Length -eq 0) {
            throw "Approval artifact is empty: $ApprovalArtifactPath"
        }
    }
    $categoryGates = @(
        @{ Enabled = $EnableMailFlowImpactingChanges; Name = 'EnableMailFlowImpactingChanges' }
        @{ Enabled = $EnableAutomatedRemediation; Name = 'EnableAutomatedRemediation' }
        @{ Enabled = $EnableAsrBlockMode; Name = 'EnableAsrBlockMode' }
        @{ Enabled = $EnableMdcaEnforcement; Name = 'EnableMdcaEnforcement' }
    )
    foreach ($gate in $categoryGates) {
        if ($gate.Enabled -and -not $IncludeHighRisk) {
            throw "$($gate.Name) requires IncludeHighRisk."
        }
    }
    if ($EnableMailFlowImpactingChanges -and -not $RollbackAcknowledged) {
        throw 'EnableMailFlowImpactingChanges requires RollbackAcknowledged.'
    }

    if (-not $ConfigPath) {
        $ConfigPath = Join-Path $scriptRoot 'Config\DefenderConfig.psd1'
    }
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Config file not found: $ConfigPath"
    }

    $config = Import-PowerShellDataFile -Path $ConfigPath
    Test-DefenderConfigContract -Config $config
    $reportDirectory = Join-Path $scriptRoot $config.Report.OutputDirectory
    $jsonPath = Join-Path $reportDirectory $config.Report.JsonLogFileName
    $htmlPath = Join-Path $reportDirectory $config.Report.HtmlReportFileName
    Initialize-DefenderRunLog -JsonPath $jsonPath -RunId $runId `
        -StartTime $startTime -ScriptVersion $config.ProductVersion `
        -TenantId $TenantId -TenantAdminUpn $TenantAdminUpn

    Add-DefenderRunLogEntry -Module 'Deploy-DefenderBestPractice' `
        -Action 'Run' -Status 'Started' -Detail 'Defender scaffold run started.'
    if ($WhatIfPreference) {
        Add-DefenderRunLogEntry -Module 'Deploy-DefenderBestPractice' `
            -Action 'WhatIf' -Status 'Info' `
            -Detail 'WhatIf preview enabled; child modules may not change tenant state.'
    }
    foreach ($item in @($config.BestPracticeItems)) {
        Add-DefenderRunLogEntry -Module $item.Module -Action 'ConfiguredItem' `
            -BestPracticeKey $item.Key -Status 'Info' `
            -Detail "Configured recommendation: $($item.Name)."
    }

    if ($IncludeHighRisk -and (-not $CustomerApprovalId -or -not $RollbackAcknowledged)) {
        throw 'High-risk operations require CustomerApprovalId and RollbackAcknowledged.'
    }

    $connectScript = Join-Path $moduleRoot 'Connect-DefenderServices.ps1'
    $connectArgs = @{
        TenantAdminUpn = $TenantAdminUpn
        TenantId = $TenantId
        ClientId = $ClientId
        CertificateThumbprint = $CertificateThumbprint
        DelegatedOrganization = $DelegatedOrganization
        AutoInstallModules = $AutoInstallModules
        NonInteractive = $NonInteractive
        ConnectGraph = $true
    }
    $connection = & $connectScript @connectArgs

    $commonContext = @{
        TenantAdminUpn = $TenantAdminUpn
        TenantId = $TenantId
        ClientId = $ClientId
        CertificateThumbprint = $CertificateThumbprint
        DelegatedOrganization = $DelegatedOrganization
        CustomerApprovalId = $CustomerApprovalId
        ApprovalArtifactPath = $ApprovalArtifactPath
        IncludeHighRisk = [bool] $IncludeHighRisk
        RollbackAcknowledged = [bool] $RollbackAcknowledged
        WhatIf = [bool] $WhatIfPreference
        NonInteractive = [bool] $NonInteractive
    }
    $tasks = @(
        @{ Name = 'Setup-DefenderPreflight'; Script = 'Setup-DefenderPreflight.ps1'; Skip = $SkipPreflight; Args = @{ Config = $config; Context = $commonContext; TenantAdminUpn = $TenantAdminUpn; TenantId = $TenantId; NoLicenseAutoDetect = $NoLicenseAutoDetect } }
        @{ Name = 'Setup-MdoEopBaseline'; Script = 'Setup-MdoEopBaseline.ps1'; Skip = $SkipMdoEop; Args = @{ Config = $config; Context = $commonContext; AdoptExisting = $AdoptExisting; IncludeHighRisk = $IncludeHighRisk; EnableMailFlowImpactingChanges = $EnableMailFlowImpactingChanges; RollbackAcknowledged = $RollbackAcknowledged } }
        @{ Name = 'Setup-DefenderForBusiness'; Script = 'Setup-DefenderForBusiness.ps1'; Skip = $SkipDefenderForBusiness; Args = @{ Config = $config; Context = $commonContext; AdoptExisting = $AdoptExisting; PilotGroupId = $PilotGroupId; EnableAsrBlockMode = $EnableAsrBlockMode } }
        @{ Name = 'Setup-MdeAdvanced'; Script = 'Setup-MdeAdvanced.ps1'; Skip = $SkipMdeAdvanced; Args = @{ Config = $config; Context = $commonContext; IncludeHighRisk = $IncludeHighRisk; EnableAutomatedRemediation = $EnableAutomatedRemediation } }
        @{ Name = 'Setup-DefenderForCloudApps'; Script = 'Setup-DefenderForCloudApps.ps1'; Skip = $SkipDefenderForCloudApps; Args = @{ Config = $config; Context = $commonContext; IncludeHighRisk = $IncludeHighRisk; EnableMdcaEnforcement = $EnableMdcaEnforcement; CloudDiscoveryReviewed = $CloudDiscoveryReviewed } }
    )

    foreach ($task in $tasks) {
        if ($task.Skip) {
            Add-DefenderRunLogEntry -Module $task.Name -Action 'Module' `
                -Status 'Skipped' -Detail 'Skip switch was supplied.'
            continue
        }

        $taskPath = Join-Path $moduleRoot $task.Script
        if (-not (Test-Path -LiteralPath $taskPath -PathType Leaf)) {
            Add-DefenderRunLogEntry -Module $task.Name -Action 'Module' `
                -Status 'Failed' -Detail "Module script not found: $taskPath"
            throw "Module script not found: $taskPath"
        }
        Add-DefenderRunLogEntry -Module $task.Name -Action 'Module' `
            -Status 'Started' -Detail 'Module process started.'
        $taskArgs = $task.Args
        if ($WhatIfPreference) {
            $taskArgs['WhatIf'] = $true
        }
        try {
            & $taskPath @taskArgs
            Add-DefenderRunLogEntry -Module $task.Name -Action 'Module' `
                -Status 'Succeeded' -Detail 'Module process completed.'
        }
        catch {
            $status = Get-DefenderHttpStatusCode -ErrorRecord $_
            Add-DefenderRunLogEntry -Module $task.Name -Action 'Module' `
                -Status 'Failed' -HttpStatusCode $status `
                -Detail $_.Exception.Message
            throw
        }
    }

    Add-DefenderRunLogEntry -Module 'Deploy-DefenderBestPractice' `
        -Action 'Run' -Status 'Succeeded' -Detail 'Defender scaffold run completed.'
}
catch {
    $status = Get-DefenderHttpStatusCode -ErrorRecord $_
    if ($global:DefenderRunLogPath) {
        Add-DefenderRunLogEntry -Module 'Deploy-DefenderBestPractice' `
            -Action 'Run' -Status 'Failed' -HttpStatusCode $status `
            -Detail $_.Exception.Message
    }
    throw
}
finally {
    if ($global:DefenderRunLog) {
        $endTime = [datetime]::UtcNow
        Save-DefenderRunLogJson -EndTime $endTime
        Write-DefenderHtmlReport -Path $htmlPath -Entries (Get-DefenderRunLog) `
            -RunId $runId -StartTime $startTime -EndTime $endTime `
            -TenantId $TenantId -TenantAdminUpn $TenantAdminUpn `
            -ScriptVersion $config.ProductVersion
        Clear-DefenderRunLog
    }
}
