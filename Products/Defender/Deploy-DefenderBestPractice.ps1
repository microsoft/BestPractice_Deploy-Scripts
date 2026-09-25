#requires -Version 7.0
<#
.SYNOPSIS
    Scaffolding entry point for the Microsoft Defender Best Practice Toolkit.

.DESCRIPTION
    Applies verified Defender recommendations using Purview-compatible
    orchestration semantics. The scaffold is intentionally read-only until
    each BP item has a verified supported API, permission model, license gate,
    readback projection, and rollback decision.

.PARAMETER EnableAsrAuditPolicy
    Explicitly creates or reuses the toolkit-owned Intune endpoint security
    ASR policy in Audit mode and assigns it only to PilotGroupId. The default
    path is read-only.

.PARAMETER RecoverAsrAuditPolicy
    Permanently deletes the captured toolkit-owned ASR Audit policy after
    exact ownership and isolated-assignment readback. Requires
    RecoveryPolicyId, PilotGroupId, and RollbackAcknowledged. This operation
    cannot be undone; recreate the policy with EnableAsrAuditPolicy if needed.
    API authority: https://learn.microsoft.com/graph/api/intune-deviceconfigv2-devicemanagementconfigurationpolicy-delete?view=graph-rest-beta

.PARAMETER RecoveryPolicyId
    Captured Intune configuration policy GUID to delete during separately
    approved ASR recovery. The identifier must resolve to the exact
    toolkit-owned policy and approved pilot-group assignment.

.PARAMETER RollbackAcknowledged
    Acknowledges that a selected recovery operation is irreversible. ASR
    recovery permanently deletes the verified toolkit-owned policy and also
    requires RecoverAsrAuditPolicy, RecoveryPolicyId, PilotGroupId, exact
    ownership readback, and assignment-isolation readback. This switch alone
    does not authorize deletion.

.PARAMETER EnableAsrBlockMode
    Reserved safety gate that also requires IncludeHighRisk. ASR Block mode
    is not implemented, so satisfying the high-risk gate still stops the run
    without changing tenant state.
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
    [switch] $UseDeviceAuthentication,
    [switch] $AutoInstallModules,
    [switch] $AdoptExisting,
    [switch] $SkipPreflight,
    [switch] $SkipMdoEop,
    [switch] $SkipDefenderForBusiness,
    [switch] $SkipMdeAdvanced,
    [switch] $SkipDefenderForCloudApps,
    [switch] $IncludeHighRisk,
    [switch] $RollbackAcknowledged,
    [switch] $EnableMailFlowImpactingChanges,
    [switch] $EnableAutomatedRemediation,
    [switch] $EnableAsrAuditPolicy,
    [switch] $RecoverAsrAuditPolicy,
    [switch] $EnableAsrBlockMode,
    [switch] $EnableMdcaEnforcement,
    [switch] $CloudDiscoveryReviewed,
    [string] $PilotGroupId,
    [string] $RecoveryPolicyId
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
. (Join-Path $moduleRoot 'Get-DefenderPermissionPlan.ps1')
. (Join-Path $moduleRoot 'DefenderSafetyGates.ps1')
. (Join-Path $moduleRoot 'DefenderOrchestrationHelpers.ps1')
. (Join-Path $moduleRoot 'Write-DefenderHtmlReport.ps1')

function Test-DefenderConfigContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Config)

    Assert-DefenderPermissionManifest -Config $Config
    if (-not $Config.BestPracticeItems) {
        throw 'Defender configuration must define at least one BestPracticeItems entry.'
    }
    $keys = @()
    foreach ($item in @($Config.BestPracticeItems)) {
        foreach ($property in @('Key', 'Name', 'Module', 'Risk', 'CapabilityKey')) {
            if ([string]::IsNullOrWhiteSpace([string] $item[$property])) {
                throw "BestPracticeItems entries must define '$property'."
            }
        }
        if (@($Config.WorkloadCapabilities | Where-Object {
                    $_.Key -eq $item.CapabilityKey
                }).Count -eq 0) {
            throw "BestPracticeItems entry '$($item.Key)' must reference a configured WorkloadCapability."
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
        if ($null -eq $item.PermissionOperations) {
            throw "BestPracticeItems entry '$($item.Key)' must declare PermissionOperations."
        }
        $keys += $item.Key
    }
    if (-not $Config.WorkloadCapabilities -or @($Config.WorkloadCapabilities).Count -eq 0) {
        throw 'Defender configuration must declare workload capability records.'
    }
    foreach ($capability in @($Config.WorkloadCapabilities)) {
        foreach ($property in @('Key', 'Workload', 'Status', 'Mode', 'Detail')) {
            if ([string]::IsNullOrWhiteSpace([string] $capability[$property])) {
                throw "Workload capability entries must define '$property'."
            }
        }
    }
    $quarantinePolicy = $Config.DefenderForOffice365.QuarantinePolicy
    if ($null -ne $quarantinePolicy) {
        foreach ($property in @('Key', 'Name')) {
            if ([string]::IsNullOrWhiteSpace([string] $quarantinePolicy[$property])) {
                throw "DefenderForOffice365.QuarantinePolicy must define '$property'."
            }
        }
        foreach ($property in @(
                'EndUserQuarantinePermissionsValue'
                'ESNEnabled'
                'IncludeMessagesFromBlockedSenderAddress'
                'ProtectionPolicyAssignments')) {
            if (-not $quarantinePolicy.ContainsKey($property)) {
                throw "DefenderForOffice365.QuarantinePolicy must define '$property'."
            }
        }
        if (@($quarantinePolicy.ProtectionPolicyAssignments).Count -ne 0) {
            throw 'DefenderForOffice365.QuarantinePolicy.ProtectionPolicyAssignments must remain empty; protection-policy assignment is out of scope.'
        }
        if ($null -eq $Config.StateManagement.ObjectDefinitions.QuarantinePolicy) {
            throw 'DefenderForOffice365.QuarantinePolicy requires StateManagement.ObjectDefinitions.QuarantinePolicy.'
        }
    }
}

try {
    # TenantId alone is valid for delegated sign-in; certificate mode requires
    # the client ID and thumbprint in addition to the tenant.
    $certificateArguments = @($ClientId, $CertificateThumbprint) |
        ForEach-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if (($certificateArguments | Where-Object { $_ }).Count -gt 0 -and
        ($certificateArguments | Where-Object { -not $_ }).Count -gt 0) {
        throw 'TenantId, ClientId, and CertificateThumbprint must be supplied together for certificate authentication.'
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

    # Safety gates run after run-log initialization so a gate-blocked invocation
    # still produces structured evidence (a 'Failed' entry via the outer catch)
    # instead of exiting with no report at all.
    try {
        Assert-DefenderSafetyGates -IncludeHighRisk:$IncludeHighRisk `
            -RollbackAcknowledged:$RollbackAcknowledged `
            -EnableMailFlowImpactingChanges:$EnableMailFlowImpactingChanges `
            -EnableAutomatedRemediation:$EnableAutomatedRemediation `
            -EnableAsrBlockMode:$EnableAsrBlockMode `
            -EnableMdcaEnforcement:$EnableMdcaEnforcement | Out-Null
    }
    catch {
        Add-DefenderRunLogEntry -Module 'Deploy-DefenderBestPractice' `
            -Action 'SafetyGate' -Status 'Failed' -Disposition 'Blocked' `
            -Detail $_.Exception.Message
        throw
    }

    # Validate complete ASR write intent before permission planning or service
    # connection. This prevents an invalid invocation from requesting consent.
    try {
        if ($EnableAsrAuditPolicy -and $RecoverAsrAuditPolicy) {
            throw 'EnableAsrAuditPolicy and RecoverAsrAuditPolicy cannot be used together.'
        }
        if ($EnableAsrAuditPolicy -or $RecoverAsrAuditPolicy) {
            $pilotGroupGuid = [guid]::Empty
            if ([string]::IsNullOrWhiteSpace($PilotGroupId) -or
                -not [guid]::TryParse($PilotGroupId, [ref] $pilotGroupGuid)) {
                throw 'ASR apply and recovery operations require PilotGroupId as a valid group GUID.'
            }
        }
        if ($RecoverAsrAuditPolicy) {
            if (-not $RollbackAcknowledged) {
                throw 'RecoverAsrAuditPolicy requires RollbackAcknowledged.'
            }
            $recoveryPolicyGuid = [guid]::Empty
            if ([string]::IsNullOrWhiteSpace($RecoveryPolicyId) -or
                -not [guid]::TryParse($RecoveryPolicyId, [ref] $recoveryPolicyGuid)) {
                throw 'RecoverAsrAuditPolicy requires RecoveryPolicyId as the captured policy GUID.'
            }
        }
    }
    catch {
        Add-DefenderRunLogEntry -Module 'Deploy-DefenderBestPractice' `
            -Action 'AsrIntentGuard' -Status 'Failed' -Disposition 'Blocked' `
            -Detail $_.Exception.Message
        throw
    }

    $moduleSkipped = @{
        'Setup-DefenderPreflight' = $SkipPreflight
        'Setup-MdoEopBaseline' = $SkipMdoEop
        'Setup-DefenderForBusiness' = $SkipDefenderForBusiness
        'Setup-MdeAdvanced' = $SkipMdeAdvanced
        'Setup-DefenderForCloudApps' = $SkipDefenderForCloudApps
    }
    $permissionOperations = @('tenant-identity')
    foreach ($item in @($config.BestPracticeItems)) {
        if ($moduleSkipped.ContainsKey($item.Module) -and -not $moduleSkipped[$item.Module]) {
            $permissionOperations += @($item.PermissionOperations)
        }
    }
    if ($EnableAsrAuditPolicy -and -not $SkipDefenderForBusiness) {
        $permissionOperations += 'mde-asr-audit-apply'
    }
    if ($RecoverAsrAuditPolicy -and -not $SkipDefenderForBusiness) {
        $permissionOperations += 'mde-asr-audit-recovery'
    }
    $permissionOperations = @($permissionOperations | Sort-Object -Unique)
    $permissionPlan = Get-DefenderPermissionPlan -Config $config `
        -OperationKeys $permissionOperations
    if ($permissionPlan.Status -ne 'Ready') {
        throw "Defender permission plan is not ready for dispatch: $($permissionPlan.Status)."
    }
    Add-DefenderRunLogEntry -Module 'Deploy-DefenderBestPractice' `
        -Action 'PermissionPlan' -Status 'Info' `
        -Detail "Permission plan ready. Operations=$($permissionPlan.Operations.Key -join ','); GraphScopes=$($permissionPlan.GraphDelegatedScopes -join ','); GraphApplicationPermissions=$($permissionPlan.GraphApplicationPermissions -join ',')."

    $connectScript = Join-Path $moduleRoot 'Connect-DefenderServices.ps1'
    $connectArgs = @{
        TenantAdminUpn = $TenantAdminUpn
        TenantId = $TenantId
        ClientId = $ClientId
        CertificateThumbprint = $CertificateThumbprint
        DelegatedOrganization = $DelegatedOrganization
        AutoInstallModules = $AutoInstallModules
        NonInteractive = $NonInteractive
        UseDeviceAuthentication = $UseDeviceAuthentication
        ConnectGraph = $permissionPlan.GraphDelegatedScopes.Count -gt 0
        GraphScopes = $permissionPlan.GraphDelegatedScopes
    }
    $connectionInfo = & $connectScript @connectArgs

    $commonContext = @{
        TenantAdminUpn = $TenantAdminUpn
        TenantId = $TenantId
        ConnectionInfo = $connectionInfo
        ClientId = $ClientId
        CertificateThumbprint = $CertificateThumbprint
        DelegatedOrganization = $DelegatedOrganization
        IncludeHighRisk = [bool] $IncludeHighRisk
        RollbackAcknowledged = [bool] $RollbackAcknowledged
        WhatIf = [bool] $WhatIfPreference
        NonInteractive = [bool] $NonInteractive
        UseDeviceAuthentication = [bool] $UseDeviceAuthentication
        PermissionPlan = $permissionPlan
    }
    $tasks = @(
        @{ Name = 'Setup-DefenderPreflight'; SkipSwitch = '-SkipPreflight'; Script = 'Setup-DefenderPreflight.ps1'; Skip = $SkipPreflight; Args = @{ Config = $config; Context = $commonContext; TenantAdminUpn = $TenantAdminUpn } }
        @{ Name = 'Setup-MdoEopBaseline'; SkipSwitch = '-SkipMdoEop'; Script = 'Setup-MdoEopBaseline.ps1'; Skip = $SkipMdoEop; Args = @{ Config = $config; Context = $commonContext; AdoptExisting = $AdoptExisting; IncludeHighRisk = $IncludeHighRisk; EnableMailFlowImpactingChanges = $EnableMailFlowImpactingChanges; RollbackAcknowledged = $RollbackAcknowledged } }
        @{ Name = 'Setup-DefenderForBusiness'; SkipSwitch = '-SkipDefenderForBusiness'; Script = 'Setup-DefenderForBusiness.ps1'; Skip = $SkipDefenderForBusiness; Args = @{ Config = $config; Context = $commonContext; PilotGroupId = $PilotGroupId; RecoveryPolicyId = $RecoveryPolicyId; EnableAsrAuditPolicy = $EnableAsrAuditPolicy; RecoverAsrAuditPolicy = $RecoverAsrAuditPolicy; RollbackAcknowledged = $RollbackAcknowledged; EnableAsrBlockMode = $EnableAsrBlockMode } }
        @{ Name = 'Setup-MdeAdvanced'; SkipSwitch = '-SkipMdeAdvanced'; Script = 'Setup-MdeAdvanced.ps1'; Skip = $SkipMdeAdvanced; Args = @{ Config = $config; Context = $commonContext; IncludeHighRisk = $IncludeHighRisk; EnableAutomatedRemediation = $EnableAutomatedRemediation } }
        @{ Name = 'Setup-DefenderForCloudApps'; SkipSwitch = '-SkipDefenderForCloudApps'; Script = 'Setup-DefenderForCloudApps.ps1'; Skip = $SkipDefenderForCloudApps; Args = @{ Config = $config; Context = $commonContext; IncludeHighRisk = $IncludeHighRisk; EnableMdcaEnforcement = $EnableMdcaEnforcement; CloudDiscoveryReviewed = $CloudDiscoveryReviewed } }
    )

    foreach ($task in $tasks) {
        if ($task.Skip) {
            Add-DefenderRunLogEntry -Module $task.Name -Action 'Module' `
                -Status 'Skipped' -Disposition 'Skipped' `
                -Detail (Get-DefenderContinuationCommand `
                    -Reason 'the module was intentionally skipped' `
                    -SwitchToRemove $task.SkipSwitch)
            continue
        }

        $taskPath = Join-Path $moduleRoot $task.Script
        Add-DefenderRunLogEntry -Module $task.Name -Action 'Module' `
            -Status 'Started' -Detail 'Module process started.'
        $taskArgs = $task.Args
        if ($WhatIfPreference) {
            $taskArgs['WhatIf'] = $true
        }
        try {
            Invoke-DefenderModuleProcess -ScriptPath $taskPath -Arguments $taskArgs
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

    $terminalOutcomeStatuses = @('Succeeded', 'Created', 'Updated', 'Adopted', 'Skipped', 'Failed')
    foreach ($item in @($config.BestPracticeItems)) {
        $itemEntries = @(Get-DefenderRunLog | Where-Object {
            $_.BestPracticeKey -eq $item.Key -and
            $_.Action -ne 'ConfiguredItem' -and
            $_.Status -in $terminalOutcomeStatuses
        })
        if ($itemEntries.Count -gt 0) {
            $outcome = $itemEntries[-1]
            $status = [string] $outcome.Status
            $disposition = [string] $outcome.Disposition
            $detail = "Recommendation=$($item.Name); ActualOutcome=$status/$disposition."
        }
        else {
            $status = 'Skipped'
            $disposition = if ($moduleSkipped[$item.Module]) { 'Skipped' } else { 'GuidedOnly' }
            $detail = "Recommendation=$($item.Name); no operation-specific outcome was recorded."
        }
        Add-DefenderRunLogEntry -Module $item.Module -Action 'ConfiguredItem' `
            -BestPracticeKey $item.Key -FriendlyName $item.Name `
            -Status $status -Disposition $disposition -Detail $detail
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
