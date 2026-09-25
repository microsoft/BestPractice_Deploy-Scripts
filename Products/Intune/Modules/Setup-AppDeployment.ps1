#requires -Version 7.0
<#
.SYNOPSIS
    Microsoft 365 Apps deployment to managed Windows devices (guide task 8).

.DESCRIPTION
    Creates a single officeSuiteApp (Monthly Enterprise Channel, Open Document
    Format default) from the AppDeployment section of IntuneConfig.psd1 and
    assigns it to the pilot group, or to all licensed users when the operator
    opted into tenant-wide assignment.

    Idempotent: an existing officeSuiteApp with the toolkit name or management
    tag is left untouched. The current writer is create-only and does not
    perform in-place adoption or refresh. This is a Standard-risk write (app
    delivery only; it denies no access), so it does not require the high-risk
    gate. All state changes are gated by ShouldProcess, wrapped in the shared
    transient-retry boundary, and read back after write.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [switch] $AdoptExisting
)

$ErrorActionPreference = 'Stop'
# Auto-confirm: this toolkit runs unattended. -WhatIf still previews; the
# orchestrator supplies the high-risk gates.
$ConfirmPreference = 'None'

. (Join-Path $PSScriptRoot 'IntuneRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

$module = 'Setup-AppDeployment'
$bestPracticeKey = 'm365-apps-deployment'

function Get-IntuneAppDeploymentProperty {
    param([AllowNull()] $InputObject, [Parameter(Mandatory)] [string] $Name)

    $exists = $false
    $value = $null
    if ($null -eq $InputObject) {
        return [pscustomobject] @{ Exists = $exists; Value = $value }
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $exists = $InputObject.Contains($Name)
        if ($exists) { $value = $InputObject[$Name] }
        return [pscustomobject] @{ Exists = $exists; Value = $value }
    }
    $property = $InputObject.PSObject.Properties[$Name]
    $exists = $null -ne $property
    if ($exists) { $value = $property.Value }
    return [pscustomobject] @{ Exists = $exists; Value = $value }
}

function Get-IntuneOfficeSuiteApps {
    param(
        [Parameter(Mandatory)] [string] $InitialUri,
        [Parameter(Mandatory)] [string] $GraphBaseUri
    )

    $base = [uri] $GraphBaseUri
    $expectedPathPrefix = $base.AbsolutePath.TrimEnd('/') + '/'
    $visited = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $apps = [System.Collections.Generic.List[object]]::new()
    $nextUri = $InitialUri

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        if (-not $visited.Add($nextUri)) {
            throw 'Microsoft Graph returned a pagination cycle for Microsoft 365 Apps deployments.'
        }
        $parsedNext = $null
        if (-not [uri]::TryCreate($nextUri, [UriKind]::Absolute, [ref] $parsedNext) -or
            $parsedNext.Scheme -ne 'https' -or
            -not [string]::Equals(
                $parsedNext.Host,
                $base.Host,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not $parsedNext.AbsolutePath.StartsWith(
                $expectedPathPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'Microsoft Graph returned a Microsoft 365 Apps next link outside the configured Graph API path.'
        }

        $response = Invoke-WithTransientRetry -Description 'Read existing officeSuiteApp' -Action {
            Invoke-MgGraphRequest -Method GET -Uri $nextUri
        }
        $value = Get-IntuneAppDeploymentProperty -InputObject $response -Name 'value'
        if (-not $value.Exists -or $null -eq $value.Value) {
            throw 'Microsoft Graph returned no Microsoft 365 Apps collection.'
        }
        foreach ($item in @($value.Value)) {
            if ($null -eq $item) {
                throw 'Microsoft Graph returned a null Microsoft 365 Apps deployment.'
            }
            $apps.Add($item)
        }

        $nextLink = Get-IntuneAppDeploymentProperty `
            -InputObject $response -Name '@odata.nextLink'
        $nextUri = if ($nextLink.Exists) { [string] $nextLink.Value } else { $null }
    }

    return @($apps)
}

# Preflight or a gate may have withheld this item; a withheld item must not be
# written even though the module itself was not skipped.
if ($Context -and @($Context.BlockedItemKeys) -contains $bestPracticeKey) {
    Add-IntuneRunLogEntry -Module $module -Action 'Deploy' -BestPracticeKey $bestPracticeKey `
        -Status 'Skipped' -Disposition 'Blocked' `
        -Detail 'Microsoft 365 Apps deployment was withheld by preflight or a gate.'
    return
}

# Standalone modules no longer connect Graph themselves; require the caller
# (the orchestrator, or an operator running this module directly) to have
# already established an authenticated Graph context in this session.
if (-not $Context -or [string]::IsNullOrWhiteSpace([string] $Context.TenantAdminUpn)) {
    throw 'Setup-AppDeployment.ps1 requires Context.TenantAdminUpn from a pre-authenticated Graph connection. Run it through Deploy-IntuneBestPractice.ps1 or connect to Microsoft Graph yourself and supply -Context.'
}

$app = $Config.AppDeployment
$tag = $Config.ManagedByTag
$appsUri = "$($Config.Api.GraphBetaBaseUri)/deviceAppManagement/mobileApps"

# Read before write. A toolkit-owned officeSuiteApp is treated as already
# compliant so re-runs do not create duplicates.
$managedExisting = @()
$unmanagedSameName = @()
try {
    $existingApps = @(Get-IntuneOfficeSuiteApps `
            -InitialUri ("{0}?`$filter=isof('microsoft.graph.officeSuiteApp')" -f $appsUri) `
            -GraphBaseUri $Config.Api.GraphBetaBaseUri)
    foreach ($existingApp in $existingApps) {
        $displayNameProperty = Get-IntuneAppDeploymentProperty `
            -InputObject $existingApp -Name 'displayName'
        if (-not $displayNameProperty.Exists -or
            $displayNameProperty.Value -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string] $displayNameProperty.Value)) {
            throw 'Microsoft Graph returned a malformed Microsoft 365 Apps display name.'
        }
        $descriptionProperty = Get-IntuneAppDeploymentProperty `
            -InputObject $existingApp -Name 'description'
        if ($descriptionProperty.Exists -and
            $null -ne $descriptionProperty.Value -and
            $descriptionProperty.Value -isnot [string]) {
            throw 'Microsoft Graph returned a malformed Microsoft 365 Apps description.'
        }

        $isManaged = $descriptionProperty.Exists -and
            $descriptionProperty.Value -is [string] -and
            ([string] $descriptionProperty.Value).Contains(
                $tag,
                [StringComparison]::Ordinal
            )
        $isSameName = [string]::Equals(
            [string] $displayNameProperty.Value,
            [string] $app.DisplayName,
            [StringComparison]::OrdinalIgnoreCase
        )
        if ($isManaged) {
            $managedExisting += $existingApp
        }
        elseif ($isSameName) {
            $unmanagedSameName += $existingApp
        }
    }
}
catch {
    $reason = "Could not enumerate existing Microsoft 365 Apps deployments before create: $($_.Exception.Message)"
    Add-IntuneRunLogEntry -Module $module -Action 'ReadExisting' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
        -Detail $reason
    throw $reason
}

if ($unmanagedSameName.Count -gt 0) {
    $reason = "A Microsoft 365 Apps deployment named '$($app.DisplayName)' already exists but is not managed by the toolkit. Rename it or choose a different configured name; the create-only writer will not adopt or overwrite it."
    Add-IntuneRunLogEntry -Module $module -Action 'Deploy' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -Disposition 'Blocked' -Target $app.DisplayName `
        -Readback 'NotAttempted' -Detail $reason
    throw $reason
}

if ($managedExisting.Count -gt 1) {
    $reason = 'Multiple toolkit-managed Microsoft 365 Apps deployments exist. Resolve the duplicate ownership collision before rerunning.'
    Add-IntuneRunLogEntry -Module $module -Action 'Deploy' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -Disposition 'Blocked' -Target $app.DisplayName `
        -Readback 'NotAttempted' -Detail $reason
    throw $reason
}

if ($managedExisting.Count -gt 0) {
    Add-IntuneRunLogEntry -Module $module -Action 'Deploy' -BestPracticeKey $bestPracticeKey `
        -Status 'Skipped' -Disposition 'AlreadyCompliant' -Target $app.DisplayName `
        -Readback 'Verified' `
        -Detail 'A toolkit-managed Microsoft 365 Apps deployment already exists; leaving it unchanged. The current writer is create-only and does not refresh or rename existing applications.'
    return
}

if ([string] $Context.AssignmentScope -eq 'TenantWide' -and
    $Context.RollbackAcknowledged -ne $true) {
    $reason = 'Tenant-wide Microsoft 365 Apps assignment requires Context.RollbackAcknowledged from the verified run context.'
    Add-IntuneRunLogEntry -Module $module -Action 'Deploy' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -Disposition 'Blocked' -Target $app.DisplayName `
        -Readback 'NotAttempted' -Detail $reason
    throw $reason
}

# Resolve the assignment target from the orchestrator's assignment decision.
$assignmentTarget = $null
$assignmentDetail = $null
if ($Context.AssignmentScope -eq 'TenantWide') {
    $assignmentTarget = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' }
    $assignmentDetail = 'all licensed users'
}
elseif (-not [string]::IsNullOrWhiteSpace([string] $Context.PilotGroupId)) {
    $assignmentTarget = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $Context.PilotGroupId }
    $assignmentDetail = "pilot group $($Context.PilotGroupId)"
}

$displayName = $app.DisplayName
if (-not $PSCmdlet.ShouldProcess($displayName, 'Create Microsoft 365 Apps (Windows) and assign')) {
    Add-IntuneRunLogEntry -Module $module -Action 'Deploy' -BestPracticeKey $bestPracticeKey `
        -Status 'Info' -Disposition 'WillChange' -Target $displayName -Readback 'NotAttempted' `
        -Detail "WhatIf: would create officeSuiteApp '$displayName' ($($app.UpdateChannel), $($app.DefaultFileFormat)) and assign to $([string]::IsNullOrWhiteSpace($assignmentDetail) ? 'no target (none provided)' : $assignmentDetail)."
    return
}

$excludedApps = @{ '@odata.type' = '#microsoft.graph.excludedApps' }
foreach ($excluded in @($app.ExcludedApps)) { $excludedApps[$excluded] = $true }

$body = @{
    '@odata.type'                   = '#microsoft.graph.officeSuiteApp'
    displayName                     = $displayName
    description                     = $tag
    publisher                       = $app.Publisher
    autoAcceptEula                  = $true
    officePlatformArchitecture      = $app.Architecture
    updateChannel                   = $app.UpdateChannel
    officeSuiteAppDefaultFileFormat = $app.DefaultFileFormat
    useSharedComputerActivation     = [bool] $app.UseSharedComputerActivation
    localesToInstall                = @($app.Locales)
    productIds                      = @($app.ProductIds)
    excludedApps                    = $excludedApps
} | ConvertTo-Json -Depth 10

$created = $null
try {
    $created = Invoke-WithTransientRetry -Description "Create officeSuiteApp '$displayName'" -Action {
        Invoke-MgGraphRequest -Method POST -Uri $appsUri -Body $body -ContentType 'application/json'
    }
    Add-IntuneRunLogEntry -Module $module -Action 'Create' -BestPracticeKey $bestPracticeKey `
        -Status 'Created' -Disposition 'Applicable' -Target $displayName `
        -Detail "Created Microsoft 365 Apps deployment ($($app.UpdateChannel), $($app.DefaultFileFormat))."
}
catch {
    Add-IntuneRunLogEntry -Module $module -Action 'Create' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -Disposition 'Applicable' -Target $displayName `
        -HttpStatusCode (Get-IntuneHttpStatusCode -ErrorRecord $_) `
        -Detail "Failed to create Microsoft 365 Apps deployment: $($_.Exception.Message)"
    throw
}

$createdId = [string] $created.id
if ([string]::IsNullOrWhiteSpace($createdId)) {
    throw "Microsoft Graph returned no ID for the created Microsoft 365 Apps deployment '$displayName'."
}
$encodedCreatedId = [uri]::EscapeDataString($createdId)

if ($assignmentTarget) {
    $assignBody = @{
        mobileAppAssignments = @(@{
            '@odata.type' = '#microsoft.graph.mobileAppAssignment'
            intent        = $app.AssignmentIntent
            target        = $assignmentTarget
        })
    } | ConvertTo-Json -Depth 10
    try {
        Invoke-WithTransientRetry -Description "Assign officeSuiteApp '$displayName'" -Action {
            Invoke-MgGraphRequest -Method POST -Uri "$appsUri/$encodedCreatedId/assign" -Body $assignBody -ContentType 'application/json' | Out-Null
        }
        Add-IntuneRunLogEntry -Module $module -Action 'Assign' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'Applicable' -Target $displayName `
            -Detail "Assigned to $assignmentDetail."
    }
    catch {
        Add-IntuneRunLogEntry -Module $module -Action 'Assign' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Applicable' -Target $displayName `
            -HttpStatusCode (Get-IntuneHttpStatusCode -ErrorRecord $_) `
            -Detail "Created the app but failed to assign it: $($_.Exception.Message)"
        throw
    }
}
else {
    Add-IntuneRunLogEntry -Module $module -Action 'Assign' -BestPracticeKey $bestPracticeKey `
        -Status 'Info' -Disposition 'GuidedOnly' -Target $displayName `
        -Detail 'No assignment target was available (no PilotGroupId and not tenant-wide); the app was created but not assigned. Supply -PilotGroupId or -AssignTenantWide to assign it.'
}

# Read back so evidence records the tenant's committed state, not just the
# create response.
try {
    $verify = Invoke-WithTransientRetry -Description "Read back officeSuiteApp '$displayName'" -Action {
        Invoke-MgGraphRequest -Method GET -Uri "$appsUri/$encodedCreatedId"
    }
    $readback = if ($verify -and $verify.displayName -eq $displayName -and $verify.updateChannel -eq $app.UpdateChannel) { 'Verified' } else { 'Mismatch' }
    if ($readback -ne 'Verified') {
        $reason = "Microsoft 365 Apps readback did not match the configured display name and update channel."
        Add-IntuneRunLogEntry -Module $module -Action 'Readback' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Target $displayName -Readback $readback `
            -Detail $reason
        throw $reason
    }
    Add-IntuneRunLogEntry -Module $module -Action 'Readback' -BestPracticeKey $bestPracticeKey `
        -Status 'Info' -Disposition 'Applicable' -Target $displayName -Readback $readback `
        -Detail "Read-back of the deployed app returned displayName='$($verify.displayName)', updateChannel='$($verify.updateChannel)'."
}
catch {
    if ([string] $_.Exception.Message -eq 'Microsoft 365 Apps readback did not match the configured display name and update channel.') {
        throw
    }
    Add-IntuneRunLogEntry -Module $module -Action 'Readback' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -Disposition 'Blocked' -Target $displayName -Readback 'NotAttempted' `
        -Detail "Read-back could not be completed: $($_.Exception.Message)"
    throw
}
