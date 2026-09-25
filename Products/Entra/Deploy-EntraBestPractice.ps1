#requires -Version 7.0
<#
.SYNOPSIS
    Entry point for the Microsoft Entra Best Practice Toolkit.

.DESCRIPTION
    Deploys the Conditional Access baseline from the Identity Protection Best
    Practice Deployment guide (Business Premium / Microsoft Entra ID P1), after
    ensuring an emergency-access (break-glass) exclusion exists.

    Every Conditional Access policy is created report-only by default and
    excludes the configured break-glass principals. These controls do not prove
    recovery or replacement protection. Enforcing a policy (state 'enabled') is a deliberate, separately gated
    promotion. All writes are gated by ShouldProcess, wrapped in the shared
    transient-retry boundary, read back, and recorded as structured evidence.

.PARAMETER TenantAdminUpn
    Operator UPN; also used to derive and verify the expected tenant domain.

.PARAMETER DelegatedOrganization
    Customer tenant domain for a GDAP delegated run.

.PARAMETER AutoInstallModules
    Install missing Microsoft Graph modules to CurrentUser without prompting.

.PARAMETER PilotGroupId
    Entra group the all-users-style policies are scoped to. High-risk items
    require this unless -AssignTenantWide is supplied.

.PARAMETER IncludeHighRisk
    Required before the Conditional Access baseline is created. Requires
    CustomerApprovalId so the authorization is recorded in evidence.

.PARAMETER BreakGlassExclusionsConfirmed
    Operator confirmation that an emergency-access account is excluded from every
    policy. Required alongside IncludeHighRisk for the Conditional Access write.

.PARAMETER AssignTenantWide
    Scope the all-users policies to every user instead of the pilot group. This
    is the highest blast-radius option and requires RollbackAcknowledged.

.PARAMETER CustomerApprovalId
    Approved change reference required with IncludeHighRisk. Only its hash is
    recorded in evidence.

.PARAMETER RollbackAcknowledged
    Confirms that recovery has been reviewed. Required for Conditional Access
    writes as well as tenant-wide assignment.

.PARAMETER ConfigPath
    Complete private configuration containing verified break-glass IDs, policy
    selection and optional naming prefix. Defaults to Config\EntraConfig.psd1.

.LINK
    https://learn.microsoft.com/entra/identity/conditional-access/
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')] [string] $TenantAdminUpn,
    [ValidatePattern('^[^@\s]+\.[^@\s]+$')] [string] $DelegatedOrganization,
    [string] $ConfigPath,
    [switch] $AutoInstallModules,
    [switch] $NonInteractive,
    [switch] $AdoptExisting,
    [switch] $SkipEmergencyAccess,
    [switch] $SkipConditionalAccessBaseline,
    [switch] $SkipTenantSecuritySettings,
    [switch] $SkipDeploymentHealth,
    [switch] $IncludeHighRisk,
    [string] $CustomerApprovalId,
    [switch] $RollbackAcknowledged,
    [switch] $BreakGlassExclusionsConfirmed,
    [switch] $AssignTenantWide,
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')] [string] $PilotGroupId
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleRoot = Join-Path $scriptRoot 'Modules'
$runId = [guid]::NewGuid()
$startTime = [datetime]::UtcNow
$jsonPath = $null
$htmlPath = $null
$resolvedTenantId = $null

. (Join-Path $moduleRoot 'EntraRunLog.ps1')
. (Join-Path $moduleRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $moduleRoot 'Write-EntraHtmlReport.ps1')
. (Join-Path $moduleRoot 'EntraSecurityDefaults.ps1')

function Test-EntraConfigContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Config)

    foreach ($section in @('BestPracticeItems', 'LicenseCapabilities', 'Api',
                           'Assignment', 'ConditionalAccess', 'Report')) {
        if (-not $Config.ContainsKey($section)) {
            throw "Entra configuration must define a '$section' section."
        }
    }
    if (-not $Config.BestPracticeItems) {
        throw 'Entra configuration must define at least one BestPracticeItems entry.'
    }

    $validRisk = @('Standard', 'High')
    $keys = @()
    foreach ($item in @($Config.BestPracticeItems)) {
        foreach ($property in @('Key', 'Name', 'Module', 'Risk')) {
            if ([string]::IsNullOrWhiteSpace([string] $item[$property])) {
                throw "BestPracticeItems entries must define '$property'."
            }
        }
        if ($item.Key -notmatch '^[a-z0-9]+(?:-[a-z0-9]+)+$') {
            throw "BestPracticeItems key '$($item.Key)' must be lowercase kebab-case."
        }
        if ($keys -contains $item.Key) { throw "Duplicate BestPracticeItems key '$($item.Key)'." }
        if ($item.Risk -notin $validRisk) {
            throw "BestPracticeItems entry '$($item.Key)' declares Risk '$($item.Risk)'; valid values are $($validRisk -join ', ')."
        }
        if ($item.RequiresHighRiskGate -isnot [bool]) {
            throw "BestPracticeItems entry '$($item.Key)' must declare RequiresHighRiskGate as a boolean."
        }
        if ($item.Risk -eq 'High' -and -not $item.RequiresHighRiskGate) {
            throw "BestPracticeItems entry '$($item.Key)' is Risk High but does not set RequiresHighRiskGate."
        }
        $keys += $item.Key
    }

    $ca = $Config.ConditionalAccess
    $validState = @('enabledForReportingButNotEnforced', 'disabled', 'enabled')
    if ($ca.DefaultState -notin $validState) {
        throw "ConditionalAccess.DefaultState is '$($ca.DefaultState)'; valid values: $($validState -join ', ')."
    }
    if ($ca.RequireBreakGlassExclusion -isnot [bool]) {
        throw 'ConditionalAccess.RequireBreakGlassExclusion must be a boolean.'
    }
    if ([string]::IsNullOrWhiteSpace([string] $ca.PolicyTemplateDirectory)) {
        throw 'ConditionalAccess.PolicyTemplateDirectory must identify the policy template folder.'
    }
    if (-not $ca.Policies) {
        throw 'ConditionalAccess must define at least one policy.'
    }
    Assert-EntraPolicyMigrationConfig -ConditionalAccess $ca
    foreach ($key in @('OutputDirectory', 'JsonLogFileName', 'HtmlReportFileName')) {
        if ([string]::IsNullOrWhiteSpace([string] $Config.Report[$key])) {
            throw "Report section must define '$key'."
        }
    }
}

function Deny-EntraRun {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Gate, [Parameter(Mandatory)] [string] $Reason)
    if (Test-EntraRunLogInitialized) {
        Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' `
            -Action $Gate -Status 'Skipped' -Disposition 'Blocked' -Detail $Reason
    }
    throw $Reason
}

function Write-EntraWriteReadiness {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Config)

    if ($SkipConditionalAccessBaseline) {
        Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' -Action 'WriteReadiness' -Status 'Skipped' `
            -Detail 'Conditional Access was not selected. Other selected modules retain their own write gates.'
        return
    }
    $missing = @(
        if (-not $IncludeHighRisk) { '-IncludeHighRisk' }
        if ([string]::IsNullOrWhiteSpace($CustomerApprovalId)) { '-CustomerApprovalId <approved-change-reference>' }
        if (-not $BreakGlassExclusionsConfirmed) { '-BreakGlassExclusionsConfirmed' }
        if (-not $RollbackAcknowledged) { '-RollbackAcknowledged' }
        if (-not $AssignTenantWide -and [string]::IsNullOrWhiteSpace($PilotGroupId)) { '-PilotGroupId <group-object-id>' }
    )
    $parameterState = if ($missing.Count) { 'Missing apply parameters: ' + ($missing -join ', ') + '.' }
        else { 'Apply parameters supplied; tenant readiness, recovery, permissions and selected policy prerequisites still require verification.' }
    Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' -Action 'WriteReadiness' -Status 'Info' `
        -Disposition 'GuidedOnly' -Detail (
            "$parameterState Configure ConditionalAccess.BreakGlass.ExcludeUserIds or ExcludeGroupIds with verified emergency-access principals in your private ConfigPath. " +
            'Security Defaults must be verified disabled after an approved transition with active replacement protection; this toolkit never disables it automatically. ' +
            'First rerun the same approved configuration and scope with -WhatIf and all required parameters. Review the report before a separately approved run without -WhatIf. ' +
            'New policies remain report-only by default; enforcement is a separate change. AssignTenantWide additionally requires Assignment.AllowTenantWideAssignmentForHighRisk=true; it is not the default.'
        )
}

$tasks = @()
try {
    if (-not $ConfigPath) { $ConfigPath = Join-Path $scriptRoot 'Config\EntraConfig.psd1' }
    if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Config file not found: $ConfigPath" }

    $config = Import-PowerShellDataFile -Path $ConfigPath
    Test-EntraConfigContract -Config $config

    $reportDirectory = Join-Path $scriptRoot $config.Report.OutputDirectory
    $jsonPath = Join-Path $reportDirectory $config.Report.JsonLogFileName
    $htmlPath = Join-Path $reportDirectory $config.Report.HtmlReportFileName
    Initialize-EntraRunLog -JsonPath $jsonPath -RunId $runId `
        -StartTime $startTime -ScriptVersion $config.ProductVersion `
        -TenantAdminUpn $TenantAdminUpn

    $tasks = @(
        @{ Name = 'Setup-EmergencyAccess'; Stage = '[3/7] Emergency-access verification'; Script = 'Setup-EmergencyAccess.ps1'; Skip = $SkipEmergencyAccess; Args = @{ Config = $config } }
        @{ Name = 'Setup-ConditionalAccessBaseline'; Stage = '[4/7] Conditional Access assessment and gated deployment'; Script = 'Setup-ConditionalAccessBaseline.ps1'; Skip = $SkipConditionalAccessBaseline; Args = @{ Config = $config; AdoptExisting = $AdoptExisting } }
        @{ Name = 'Setup-TenantSecuritySettings'; Stage = '[5/7] Optional tenant security settings'; Script = 'Setup-TenantSecuritySettings.ps1'; Skip = $SkipTenantSecuritySettings; Args = @{ Config = $config; AdoptExisting = $AdoptExisting } }
        @{ Name = 'Get-EntraDeploymentHealth'; Stage = '[6/7] Read-only deployment validation'; Script = 'Get-EntraDeploymentHealth.ps1'; Skip = $SkipDeploymentHealth; Args = @{ Config = $config } }
    )

    Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' `
        -Action 'Run' -Status 'Started' -Detail 'Entra baseline run started.'
    Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' -Action 'Stage' -Status 'Info' `
        -Detail '[1/7] Prerequisites and write readiness'
    Write-EntraWriteReadiness -Config $config
    $baselineCount = @($config.ConditionalAccess.Policies | Where-Object {
        (Get-EntraPolicyTier $_) -eq 'P1Baseline' -and (Test-EntraPolicySelected $_)
    }).Count
    $hardenedCount = @($config.ConditionalAccess.Policies | Where-Object {
        (Get-EntraPolicyTier $_) -eq 'P1Hardened' -and (Test-EntraPolicySelected $_)
    }).Count
    Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' -Action 'PolicyTier' -Status 'Info' `
        -Detail "Business Premium / P1 baseline selected=$baselineCount; P1 optional/hardened selected=$hardenedCount. Configuration selection is not proof of license entitlement."
    Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' -Action 'PolicyTier' -Status 'Info' -Disposition 'GuidedOnly' `
        -Detail 'P2 / Identity Protection: sign-in risk, user risk and risk-triggered stronger authentication are not deployed. These require separate entitlement, design and approval; authentication strength alone is a P1 capability.'

    if ($IncludeHighRisk -and [string]::IsNullOrWhiteSpace($CustomerApprovalId)) {
        Deny-EntraRun -Gate 'IncludeHighRisk' -Reason 'IncludeHighRisk requires CustomerApprovalId.'
    }
    if ($AssignTenantWide -and -not $RollbackAcknowledged) {
        Deny-EntraRun -Gate 'AssignTenantWide' -Reason 'AssignTenantWide requires RollbackAcknowledged.'
    }
    if ($AssignTenantWide -and -not $config.Assignment.AllowTenantWideAssignmentForHighRisk) {
        Deny-EntraRun -Gate 'AssignTenantWide' `
            -Reason 'AssignTenantWide is disabled by Assignment.AllowTenantWideAssignmentForHighRisk in configuration.'
    }

    if ($IncludeHighRisk) {
        $approvalHash = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($CustomerApprovalId)))
        Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' `
            -Action 'HighRiskApproval' -Status 'Info' -Disposition 'Applicable' `
            -Detail "High-risk operations authorised. CustomerApprovalReferenceSha256=$approvalHash."
    }

    if ($WhatIfPreference) {
        Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' `
            -Action 'WhatIf' -Status 'Info' `
            -Detail 'WhatIf preview enabled; child modules will not change tenant state.'
    }

    $assignmentScope = if ($AssignTenantWide) { 'TenantWide' } else { 'PilotGroup' }

    # The Conditional Access baseline is High risk. Withhold its write unless the
    # operator supplied every gate; the item is still assessed and reported.
    $writeBlockedItemKeys = @()
    $caAuthorized = $IncludeHighRisk -and $BreakGlassExclusionsConfirmed -and $RollbackAcknowledged
    if (-not $caAuthorized) {
        $writeBlockedItemKeys += 'conditional-access-baseline'
        $reason = 'Write authorization withheld: the Conditional Access baseline requires IncludeHighRisk with CustomerApprovalId, BreakGlassExclusionsConfirmed, and RollbackAcknowledged.'
        Add-EntraRunLogEntry -Module 'Setup-ConditionalAccessBaseline' -Action 'WriteRiskGate' `
            -BestPracticeKey 'conditional-access-baseline' -Status 'Info' -Detail $reason
    }
    if ($caAuthorized -and $config.Assignment.RequirePilotGroupForHighRisk -and
        -not $AssignTenantWide -and [string]::IsNullOrWhiteSpace($PilotGroupId)) {
        Deny-EntraRun -Gate 'PilotGroup' `
            -Reason 'The Conditional Access baseline requires PilotGroupId, or AssignTenantWide with RollbackAcknowledged.'
    }

    Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' -Action 'Stage' -Status 'Info' `
        -Detail '[2/7] Tenant discovery and Security Defaults readiness'
    $connectScript = Join-Path $moduleRoot 'Connect-EntraServices.ps1'
    $connectArgs = @{
        TenantAdminUpn = $TenantAdminUpn
        DelegatedOrganization = $DelegatedOrganization
        Scopes = $config.Api.GraphScopes
        GraphBaseUri = $config.Api.GraphBaseUri
        NonInteractive = $NonInteractive
        ConnectGraph = $true
    }
    if ($AutoInstallModules) { $connectArgs.AutoInstallModules = $true }
    $connectionInfo = & $connectScript @connectArgs
    $resolvedTenantId = [string]$connectionInfo.TenantIdentity.TenantId
    if ([string]::IsNullOrWhiteSpace($resolvedTenantId)) {
        throw 'The verified Microsoft Graph connection did not return a tenant ID.'
    }
    Set-EntraRunTenantId -TenantId $resolvedTenantId
    $securityDefaultsState = Get-EntraSecurityDefaultsState `
        -BaseUri $config.Api.GraphBaseUri -Module 'Deploy-EntraBestPractice'

    $commonContext = @{
        TenantAdminUpn = $TenantAdminUpn
        TenantId = $resolvedTenantId
        ConnectionInfo = $connectionInfo
        DelegatedOrganization = $DelegatedOrganization
        IncludeHighRisk = [bool] $IncludeHighRisk
        RollbackAcknowledged = [bool] $RollbackAcknowledged
        BreakGlassExclusionsConfirmed = [bool] $BreakGlassExclusionsConfirmed
        PilotGroupId = $PilotGroupId
        AssignmentScope = $assignmentScope
        WriteBlockedItemKeys = $writeBlockedItemKeys
        BlockedItemKeys = @()
        BreakGlassOutputPath = (Join-Path $reportDirectory 'entra-breakglass.json')
        BreakGlassUserIds = @($config.ConditionalAccess.BreakGlass.ExcludeUserIds)
        BreakGlassGroupIds = @($config.ConditionalAccess.BreakGlass.ExcludeGroupIds)
        WhatIf = [bool] $WhatIfPreference
        NonInteractive = [bool] $NonInteractive
        SecurityDefaultsState = $securityDefaultsState
    }

    foreach ($task in $tasks) {
        Add-EntraRunLogEntry -Module $task.Name -Action 'Stage' -Status 'Info' -Detail $task.Stage
        if ($task.Skip) {
            Add-EntraRunLogEntry -Module $task.Name -Action 'Module' -Status 'Skipped' -Detail 'Skip switch was supplied.'
            continue
        }
        $taskPath = Join-Path $moduleRoot $task.Script
        if (-not (Test-Path -LiteralPath $taskPath -PathType Leaf)) {
            Add-EntraRunLogEntry -Module $task.Name -Action 'Module' -Status 'Failed' -Detail "Module script not found: $taskPath"
            throw "Module script not found: $taskPath"
        }
        Add-EntraRunLogEntry -Module $task.Name -Action 'Module' -Status 'Started' -Detail 'Module process started.'
        $taskArgs = $task.Args
        $taskArgs.Context = $commonContext
        if ($WhatIfPreference) { $taskArgs['WhatIf'] = $true }
        try {
            & $taskPath @taskArgs
            Add-EntraRunLogEntry -Module $task.Name -Action 'Module' -Status 'Succeeded' -Detail 'Module process completed.'

            # Fold the emergency-access module's resolved break-glass principals
            # into the shared context so the Conditional Access baseline can
            # exclude them. Later tasks receive this updated context at dispatch.
            if ($task.Name -eq 'Setup-EmergencyAccess' -and
                (Test-Path -LiteralPath $commonContext.BreakGlassOutputPath -PathType Leaf)) {
                $bg = Get-Content -LiteralPath $commonContext.BreakGlassOutputPath -Raw | ConvertFrom-Json
                $commonContext.BreakGlassUserIds = @(@($commonContext.BreakGlassUserIds) + @($bg.userIds) | Where-Object { $_ } | Select-Object -Unique)
                $commonContext.BreakGlassGroupIds = @(@($commonContext.BreakGlassGroupIds) + @($bg.groupIds) | Where-Object { $_ } | Select-Object -Unique)
                Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' -Action 'BreakGlass' -Status 'Info' `
                    -Detail "Break-glass exclusions available: $((@($commonContext.BreakGlassUserIds)+@($commonContext.BreakGlassGroupIds)).Count)."
            }
        }
        catch {
            $status = Get-EntraHttpStatusCode -ErrorRecord $_
            Add-EntraRunLogEntry -Module $task.Name -Action 'Module' -Status 'Failed' -HttpStatusCode $status -Detail $_.Exception.Message
            throw
        }
    }

    Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' -Action 'Run' -Status 'Info' `
        -Detail 'Execution completed. Read the module summary for failed, blocked or skipped work; completion does not prove deployment or protection.'
}
catch {
    if (Test-EntraRunLogInitialized) {
        Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' -Action 'Run' -Status 'Failed' -Detail $_.Exception.Message
        $entries = Get-EntraRunLog
        $recordedModules = @($entries | Where-Object Action -eq 'Module' | Select-Object -ExpandProperty Module -Unique)
        foreach ($task in $tasks) {
            if ($task.Name -in $recordedModules) { continue }
            $disposition = if ($task.Skip) { 'Skipped' } else { 'Blocked' }
            $detail = if ($task.Skip) { 'Skip switch was supplied.' } else {
                'Not started because an earlier prerequisite or module failed. No assessment or deployment was performed by this module.'
            }
            Add-EntraRunLogEntry -Module $task.Name -Action 'Module' -Status 'Skipped' `
                -Disposition $disposition -Detail $detail
        }
    }
    throw
}
finally {
    if (Test-EntraRunLogInitialized) {
        Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' -Action 'Stage' -Status 'Info' `
            -Detail '[7/7] Summary and local evidence'
        $moduleGroups = @((Get-EntraRunLog) | Group-Object Module | Sort-Object Name)
        foreach ($group in $moduleGroups) {
            $verdict = Get-EntraModuleVerdict -Entries @($group.Group)
            $summaryDisposition = switch ($verdict) { 'BLOCKED' { 'Blocked' } 'FAILED' { 'Blocked' } 'SKIPPED' { 'Skipped' } default { 'Applicable' } }
            $summaryStatus = if ($verdict -eq 'FAILED') { 'Failed' } else { 'Info' }
            Add-EntraRunLogEntry -Module 'Deploy-EntraBestPractice' -Action 'ModuleSummary' -Status $summaryStatus `
                -Disposition $summaryDisposition -Detail "$($group.Name): $verdict"
        }
        $endTime = [datetime]::UtcNow
        try {
            $writtenJsonPath = Save-EntraRunLogJson -EndTime $endTime -PassThru
            if ($writtenJsonPath) {
                Write-Host ("`nJSON run log written: {0}" -f $writtenJsonPath) -ForegroundColor Cyan
            }
            try {
                Write-EntraHtmlReport -Path $htmlPath -Entries (Get-EntraRunLog) `
                    -RunId $runId -StartTime $startTime -EndTime $endTime `
                    -TenantId $resolvedTenantId -TenantAdminUpn $TenantAdminUpn `
                    -ScriptVersion $config.ProductVersion `
                    -WhatIfRun:([bool] $WhatIfPreference)
                $writtenHtmlPath = (Resolve-Path -LiteralPath $htmlPath -ErrorAction Stop).ProviderPath
                Write-Host ("HTML report written: {0}" -f $writtenHtmlPath) -ForegroundColor Cyan
                Write-Host ("Open report: Invoke-Item -LiteralPath '{0}'" -f $writtenHtmlPath.Replace("'", "''")) -ForegroundColor Cyan
            }
            catch {
                Write-Warning ("HTML report could not be written: {0}" -f $_.Exception.Message) -WarningAction Continue
            }
        }
        finally {
            Clear-EntraRunLog
        }
    }
}
