#requires -Version 7.0
# smb-quality-gate: read-only
<#
.SYNOPSIS
    Standalone, read-only Purview configuration validation against a
    Deployment Plan.

.DESCRIPTION
    Reads current Microsoft Purview tenant configuration. With -PlanPath, it
    compares observable state with a schema 1.2 Deployment Plan intended-state
    snapshot. Without -PlanPath, it assesses the pinned Good, Better, and Best
    guide controls without assuming the repository's default configuration.

    This tool never changes tenant state. It has no apply path or repair switch.
    It declares SupportsShouldProcess for repository contract parity, but GET
    operations are not gated and local evidence is written with
    -WhatIf:$false. Any future repair capability is a separate, explicitly
    approved design.

    What the report is:

      * a comparison of observable tenant settings with one plan;
      * scoped to fields the toolkit owns, so customer-managed settings are
        reported as unscored context rather than as failures.

    What the report is not:

      * a compliance assessment;
      * a measure of data-protection effectiveness or user adoption;
      * a substitute for the deployment run report.

    Results use exactly five values: Matched, Drift, Not evaluated,
    Informational, and Collection failed. There is no "pending propagation"
    result: a mismatch that survives the shared transient-retry boundary is
    reported as drift.

    Exit codes:

        0  no drift and no collection failures
        2  drift present
        4  collection failure present
        6  both drift and collection failure
        1  fatal input, schema, tenant-identity, or connection failure

.PARAMETER PlanPath
    Optional path to a schema 1.2 Deployment Plan JSON sidecar.

.PARAMETER TenantAdminUpn
    UPN used to sign in to the tenant being validated.

.PARAMETER OutputPath
    HTML report path. The JSON sidecar uses the same basename. Defaults to a
    timestamped file in the current directory.

.PARAMETER DelegatedOrganization
    Customer tenant primary domain when a partner signs in through GDAP.

.PARAMETER SharePointAdminUrl
    Explicit SharePoint admin URL for tenants where it cannot be derived.

.PARAMETER ClientId
    Optional approved tenant-local public-client application ID. The effective
    Graph context must contain only the validator's two resource scopes plus
    standard OpenID identity scopes.

.PARAMETER UseDeviceAuthentication
    Use Microsoft Graph device authentication when the host cannot display the
    default WAM or browser flow.

.PARAMETER AutoInstallModules
    Install missing read-only modules for the current user without prompting.

.PARAMETER NonInteractive
    Fail instead of prompting. A tenant identity mismatch is always fatal.

.EXAMPLE
    .\Test-PurviewTenantConfiguration.ps1 `
        -PlanPath .\Deploy-PurviewBestPractice-Plan-20260814.json `
        -TenantAdminUpn admin@contoso.onmicrosoft.com

.EXAMPLE
    # Partner GDAP scenario with an explicit report location
    .\Test-PurviewTenantConfiguration.ps1 `
        -PlanPath .\plan.json `
        -TenantAdminUpn partneradmin@fabrikam.onmicrosoft.com `
        -DelegatedOrganization contoso.onmicrosoft.com `
        -OutputPath .\evidence\contoso-validation.html
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
param(
    [Parameter()]
    [string] $PlanPath,

    [Parameter(Mandatory)]
    [string] $TenantAdminUpn,

    [Parameter()]
    [string] $OutputPath,

    [Parameter()]
    [string] $DelegatedOrganization,

    [Parameter()]
    [string] $SharePointAdminUrl,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $ClientId,

    [Parameter()]
    [switch] $UseDeviceAuthentication,

    [Parameter()]
    [switch] $AutoInstallModules,

    [Parameter()]
    [switch] $NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ValidationVersion = '1.1.0'

$modulesPath = Join-Path $PSScriptRoot 'Modules'
. (Join-Path $modulesPath 'PurviewRunLog.ps1')
. (Join-Path $modulesPath 'PurviewValidationModel.ps1')
. (Join-Path $modulesPath 'PurviewValidationCollectors.ps1')
. (Join-Path $modulesPath 'Write-PurviewValidationReport.ps1')
. (Join-Path $modulesPath 'PurviewTenantIdentity.ps1')

Initialize-PurviewRunLog

function Resolve-ValidationOutputPath {
    [CmdletBinding()]
    param([Parameter()] [string] $Requested)

    if ($Requested) {
        if (Test-Path -LiteralPath $Requested -PathType Container) {
            throw 'The -OutputPath value is a directory. Supply a file path ending in .html.'
        }
        return $Requested
    }

    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    return Join-Path (Get-Location).Path "Test-PurviewTenantConfiguration-$stamp.html"
}

$exitCode = 1
$startedAt = [datetime]::UtcNow

try {
    Write-Host ''
    Write-Host '=== Purview configuration validation (read-only) ===' -ForegroundColor White
    Write-Host 'This tool reads tenant settings and makes no tenant changes.' -ForegroundColor DarkGray

    $adapterPath = Join-Path $PSScriptRoot 'References\ValidationAdapters.psd1'
    if (-not (Test-Path -LiteralPath $adapterPath -PathType Leaf)) {
        throw "Validation adapter allowlist not found: $adapterPath"
    }
    $allowlist = Import-PowerShellDataFile -LiteralPath $adapterPath
    Assert-PurviewValidationAdapterCoverage -Allowlist $allowlist

    Write-Host ''
    if ($PlanPath) {
        Write-Host '--- Deployment Plan ---' -ForegroundColor White
        $plan = Test-PurviewValidationPlan -Path $PlanPath -Allowlist $allowlist
        Write-Host ("  Plan {0}, schema {1}, {2} actions." -f `
            $plan.PlanReference, $plan.SchemaVersion, @($plan.Actions).Count) -ForegroundColor Green
        Add-RunLogEntry -Module 'Test-PurviewTenantConfiguration' -Action 'Validate plan' `
            -Status 'Succeeded' -Detail ("schema={0}; actions={1}" -f $plan.SchemaVersion, @($plan.Actions).Count)
    } else {
        Write-Host '--- Guide-only assessment ---' -ForegroundColor White
        $guidePath = Join-Path $PSScriptRoot 'References\DataSecuritySmbGuideMapping.psd1'
        $guide = Import-PowerShellDataFile -LiteralPath $guidePath
        $plan = New-PurviewGuideAssessmentPlan -GuideMapping $guide
        Write-Host '  No plan supplied. Assessing pinned Good, Better, and Best controls.' -ForegroundColor Green
        Add-RunLogEntry -Module 'Test-PurviewTenantConfiguration' -Action 'Select assessment mode' `
            -Status 'Succeeded' -Detail 'Guide-only assessment; no configuration intent loaded.'
    }

    $reportPath = Resolve-ValidationOutputPath -Requested $OutputPath

    # Only connect the services the plan actually needs, and only for actions
    # that will be scored. An excluded action must not cause an operator to
    # authenticate a session, let alone trigger a tenant read.
    $scoredAdapterIds = @(
        $plan.Actions |
            Where-Object { [bool]$_.Validation.Scored } |
            ForEach-Object { [string]$_.Validation.AdapterId } |
            Select-Object -Unique
    )
    $needsSharePoint = @($scoredAdapterIds | Where-Object {
        $_ -in @('purview.tenant.spo-labels', 'purview.tenant.pdf-labels')
    }).Count -gt 0
    $needsGraph = $true

    Write-Host ''
    Write-Host '--- Read-only service connections ---' -ForegroundColor White
    $connectArgs = @{
        TenantAdminUpn = $TenantAdminUpn
        NeedsGraph = $needsGraph
    }
    if ($needsSharePoint) { $connectArgs['NeedsSharePoint'] = $true }
    if ($DelegatedOrganization) { $connectArgs['DelegatedOrganization'] = $DelegatedOrganization }
    if ($SharePointAdminUrl) { $connectArgs['SharePointAdminUrl'] = $SharePointAdminUrl }
    if ($ClientId) { $connectArgs['ClientId'] = $ClientId }
    if ($UseDeviceAuthentication) { $connectArgs['UseDeviceAuthentication'] = $true }
    if ($AutoInstallModules) { $connectArgs['AutoInstallModules'] = $true }
    if ($NonInteractive) { $connectArgs['NonInteractive'] = $true }

    $connectScript = Join-Path $modulesPath 'Connect-PurviewValidationServices.ps1'
    $connection = & $connectScript @connectArgs

    Write-Host ''
    Write-Host '--- Tenant identity confirmation ---' -ForegroundColor White
    $identity = Get-PurviewTenantIdentity
    $identityMatch = Test-PurviewExpectedTenantMatch -Identity $identity `
        -TenantAdminUpn $TenantAdminUpn -DelegatedOrganization $DelegatedOrganization

    $tenantLabel = if ($identity.DisplayName) { $identity.DisplayName } else { '(not resolved)' }
    Write-Host ("  Connected tenant: {0} (source: {1})" -f $tenantLabel, $identity.Source) -ForegroundColor DarkGray

    if (-not $identityMatch.Matched) {
        Add-RunLogEntry -Module 'Test-PurviewTenantConfiguration' -Action 'Tenant identity' `
            -Status 'Failed' -Detail $identityMatch.Reason
        throw (
            "Tenant identity mismatch. $($identityMatch.Reason) " +
            "Expected source: $($identityMatch.Source). " +
            'Validation stopped so the report cannot describe the wrong tenant.')
    }
    Write-Host '  Identity check passed.' -ForegroundColor Green
    Add-RunLogEntry -Module 'Test-PurviewTenantConfiguration' -Action 'Tenant identity' `
        -Status 'Succeeded' -Detail 'Connected tenant matches the expected domain.'

    # Custom verified domains cannot be recognized by shape, so they are
    # registered as literal redaction terms before any service text is
    # captured into the model.
    Set-PurviewValidationRedactionTerm -Term @(
        @($identity.AllDomains)
        $identity.DefaultDomain
        $DelegatedOrganization
    )

    $entitlement = [pscustomobject]@{
        State = 'Unknown'
        Tier = 'Unknown'
        Available = $false
        Reason = 'The validator does not request license-assignment scope. License-gated controls remain provisional unless the workload read proves support.'
    }

    $managedTag = if ($plan.PSObject.Properties['ManagedByTag']) { [string]$plan.ManagedByTag } else { '' }
    $capabilities = @{
        SharePointOnlineSession = ($needsSharePoint -and [bool]$connection.SharePointConnected)
        GraphDirectorySettings = ([bool]$connection.GraphConnected -and
            $null -ne (Get-Command -Name 'Get-MgBetaDirectorySetting' -ErrorAction SilentlyContinue))
    }
    $context = New-PurviewValidationContext -ManagedByTag $managedTag `
        -Entitlement $entitlement -Capabilities $capabilities

    Write-Host ''
    Write-Host '--- Collecting tenant configuration ---' -ForegroundColor White
    $results = Invoke-PurviewValidationCollection -Plan $plan -Context $context -Progress {
        param($action)
        Write-Host ("  {0}" -f $action.ActionId) -ForegroundColor DarkGray
    }

    $model = New-PurviewValidationModel -Plan $plan -Results $results `
        -ToolkitVersion $script:ValidationVersion `
        -ObservedAt $startedAt `
        -DurationSeconds ([int]([datetime]::UtcNow - $startedAt).TotalSeconds) `
        -TenantDisplayName $identity.DisplayName `
        -TenantIdentityCheck 'Connected tenant verified' `
        -ServiceStatus $connection `
        -Diagnostics @(Get-PurviewRunLog | ForEach-Object {
            [pscustomobject]@{
                Module = $_.Module
                Action = $_.Action
                Status = $_.Status
                Detail = ConvertTo-PurviewValidationRedactedText -Text ([string]$_.Detail)
            }
        })

    $exitCode = Get-PurviewValidationExitCode -Model $model

    # Print the outcome before writing, so an artifact-write failure does not
    # leave the operator with no result at all.
    Write-Host ''
    Write-Host '--- Summary ---' -ForegroundColor White
    Write-Host ("  Matched: {0}   Drift: {1}   Not evaluated: {2}   Informational: {3}   Collection failed: {4}" -f `
        $model.Summary.Matched, $model.Summary.Drift, $model.Summary.NotEvaluated, `
        $model.Summary.Informational, $model.Summary.CollectionFailed) -ForegroundColor White
    Write-Host ("  Not evaluated breakdown: prerequisite unmet {0}, prerequisite unreadable {1}" -f `
        $model.Summary.PrerequisiteUnmet, $model.Summary.PrerequisiteUnknown) -ForegroundColor DarkGray

    $written = Write-PurviewValidationReport -Model $model -OutputPath $reportPath

    Write-Host ("  Report: {0}" -f (Split-Path -Leaf $written.HtmlPath)) -ForegroundColor Green
    Write-Host ("  Sidecar: {0}" -f (Split-Path -Leaf $written.JsonPath)) -ForegroundColor Green
    Write-Host ("  Exit code: {0}" -f $exitCode) -ForegroundColor DarkGray
    Write-Host ("  Proven level: {0}   Provisional level: {1}" -f `
        $model.Summary.ProvenLevel, $model.Summary.ProvisionalLevel) -ForegroundColor DarkGray
}
catch {
    $exitCode = 1
    Write-Host ''
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    Write-Host '  Validation did not complete. No tenant state was read or changed after this point.' -ForegroundColor DarkGray
}
finally {
    Clear-PurviewRunLog
}

exit $exitCode
