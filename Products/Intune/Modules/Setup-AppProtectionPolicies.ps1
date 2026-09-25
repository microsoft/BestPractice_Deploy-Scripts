#requires -Version 7.0
<#
.SYNOPSIS
    App protection policies for mobile application management (guide task 6).

.DESCRIPTION
    Reads Android and iOS/iPadOS managed app protection inventory, then creates
    the Level 1 basic data-protection policy for core Microsoft apps from the
    AppProtection section of IntuneConfig.psd1 (create policy, target the core
    apps, assign to the pilot group or all licensed users).

    Standard risk: MAM protects app data and denies no device access. Idempotent
    on the managed-by tag; an existing toolkit-managed policy is left
    unchanged because the current writer is create-only. All writes are gated
    by ShouldProcess and wrapped in the shared transient-retry boundary.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [switch] $AdoptExisting,
    [string] $PilotGroupId
)

$ErrorActionPreference = 'Stop'
$ConfirmPreference = 'None'

. (Join-Path $PSScriptRoot 'IntuneRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'IntuneAssignmentScope.ps1')
. (Join-Path $PSScriptRoot 'IntuneGraphClient.ps1')

function Get-IntuneObjectProperty {
    [CmdletBinding()]
    param(
        [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [string] $Name
    )

    # Assign through a variable rather than an inline `if`. A hashtable member
    # assigned from an `if` block that yields an empty collection collapses to
    # $null, which would make an empty but valid Graph collection look like a
    # missing property and fail closed on a legitimately empty tenant.
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

function New-IntuneSafeGraphException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $EvidenceTarget,
        [Parameter(Mandatory)] $ErrorRecord
    )

    $status = Get-IntuneHttpStatusCode -ErrorRecord $ErrorRecord
    $exception = [Exception]::new("Microsoft Graph request failed for $EvidenceTarget.")
    if ($status) {
        $exception | Add-Member -NotePropertyName Response `
            -NotePropertyValue ([pscustomobject] @{ StatusCode = $status })
    }
    return $exception
}

function Get-IntuneGraphCollection {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string] $InitialUri,
        [Parameter(Mandatory)] [string] $GraphBaseUri,
        [Parameter(Mandatory)] [string] $EvidenceTarget,
        [int[]] $ExpectedStatusCodes = @()
    )

    $base = [uri] $GraphBaseUri
    $expectedPathPrefix = $base.AbsolutePath.TrimEnd('/') + '/'
    $visited = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $results = [System.Collections.Generic.List[object]]::new()
    $nextUri = $InitialUri

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        if (-not $visited.Add($nextUri)) {
            throw "Microsoft Graph returned a pagination cycle for $EvidenceTarget."
        }

        $parsedNext = $null
        if (-not [uri]::TryCreate($nextUri, [UriKind]::Absolute, [ref] $parsedNext) -or
            $parsedNext.Scheme -ne 'https' -or
            -not [string]::Equals($parsedNext.Host, $base.Host, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Microsoft Graph returned a next link outside the approved Microsoft Graph host for $EvidenceTarget."
        }
        if (-not $parsedNext.AbsolutePath.StartsWith(
                $expectedPathPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Microsoft Graph returned a next link outside the configured Graph API path for $EvidenceTarget."
        }

        $response = Invoke-WithTransientRetry `
            -Description "Get $EvidenceTarget" `
            -ExpectedStatusCodes $ExpectedStatusCodes `
            -Action {
                try {
                    Invoke-IntuneGraphRequest -Method 'GET' -Uri $nextUri `
                        -EvidenceTarget $EvidenceTarget `
                        -ExpectedStatusCodes $ExpectedStatusCodes `
                        -DeferFailureEvidence
                }
                catch {
                    throw (New-IntuneSafeGraphException `
                            -EvidenceTarget $EvidenceTarget -ErrorRecord $_)
                }
            }

        $valueProperty = Get-IntuneObjectProperty -InputObject $response -Name 'value'
        if (-not $valueProperty.Exists -or $null -eq $valueProperty.Value) {
            throw "Microsoft Graph returned no value collection for $EvidenceTarget."
        }
        foreach ($item in @($valueProperty.Value)) {
            if ($null -eq $item) {
                throw "Microsoft Graph returned a null collection item for $EvidenceTarget."
            }
            $results.Add($item)
        }

        $nextLinkProperty = Get-IntuneObjectProperty `
            -InputObject $response -Name '@odata.nextLink'
        $nextUri = if ($nextLinkProperty.Exists) {
            [string] $nextLinkProperty.Value
        }
        else {
            $null
        }
    }

    return @($results)
}

function Get-IntuneAssignmentScope {
    <#
        Thin wrapper over the shared classifier in IntuneAssignmentScope.ps1.
        This module does not model exclusions, so an exclusion target makes the
        whole collection Unknown rather than being counted. That keeps the
        assessment from understating how broadly a policy is targeted.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyCollection()] [object[]] $Assignments,
        [string] $PilotGroupId
    )

    return (Get-IntuneAssignmentScopeResult `
            -Assignments $Assignments `
            -PilotGroupId $PilotGroupId `
            -ExclusionBehavior 'Unknown' `
            -MissingTargetMessage 'Microsoft Graph returned an assignment without a target.').Scope
}

function Assert-IntuneManagedAppCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('Android', 'iOS')] [string] $Platform,
        [AllowEmptyCollection()] [object[]] $Apps
    )

    $identifierField = if ($Platform -eq 'Android') { 'packageId' } else { 'bundleId' }
    foreach ($app in @($Apps)) {
        $identifierProperty = Get-IntuneObjectProperty `
            -InputObject $app -Name 'mobileAppIdentifier'
        if (-not $identifierProperty.Exists -or $null -eq $identifierProperty.Value) {
            throw "Microsoft Graph returned a malformed $Platform managed app identifier."
        }
        $valueProperty = Get-IntuneObjectProperty `
            -InputObject $identifierProperty.Value -Name $identifierField
        if (-not $valueProperty.Exists -or
            [string]::IsNullOrWhiteSpace([string] $valueProperty.Value)) {
            throw "Microsoft Graph returned a malformed $Platform managed app identifier."
        }
    }
}

function Get-IntuneAppProtectionAssessmentState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [ValidateSet('Android', 'iOS')] [string] $Platform,
        [Parameter(Mandatory)] [string] $GraphBaseUri,
        [string] $PilotGroupId,
        [Parameter(Mandatory)] [string] $ManagedByTag,
        [Parameter(Mandatory)] [string] $ExpectedDisplayName
    )

    $resourceName = if ($Platform -eq 'Android') {
        'androidManagedAppProtections'
    }
    else {
        'iosManagedAppProtections'
    }
    $collectionUri = Resolve-IntuneGraphUri -BaseUri $GraphBaseUri `
        -RelativePath "deviceAppManagement/$resourceName"
    $policies = @(Get-IntuneGraphCollection -InitialUri $collectionUri `
            -GraphBaseUri $GraphBaseUri -EvidenceTarget "$Platform app protection policies")

    $assignments = [System.Collections.Generic.List[object]]::new()
    $toolkitManagedPolicyCount = 0
    $managedSameNamePolicyCount = 0
    $unmanagedSameNamePolicyCount = 0
    $targetAppReadback = if ($policies.Count -eq 0) { 'NotApplicable' } else { 'Available' }

    foreach ($policy in $policies) {
        $idProperty = Get-IntuneObjectProperty -InputObject $policy -Name 'id'
        $descriptionProperty = Get-IntuneObjectProperty `
            -InputObject $policy -Name 'description'
        $displayNameProperty = Get-IntuneObjectProperty `
            -InputObject $policy -Name 'displayName'
        $policyId = [string] $idProperty.Value
        if (-not $idProperty.Exists -or
            [string]::IsNullOrWhiteSpace($policyId)) {
            throw "Microsoft Graph returned a malformed $Platform app protection policy ID."
        }
        $encodedPolicyId = [uri]::EscapeDataString($policyId)
        if (-not $descriptionProperty.Exists -or
            ($null -ne $descriptionProperty.Value -and
             $descriptionProperty.Value -isnot [string])) {
            throw "Microsoft Graph returned a malformed $Platform app protection policy description."
        }
        $description = [string] $descriptionProperty.Value
        if ($displayNameProperty.Exists -and
            $null -ne $displayNameProperty.Value -and
            $displayNameProperty.Value -isnot [string]) {
            throw "Microsoft Graph returned a malformed $Platform app protection policy display name."
        }
        $displayName = [string] $displayNameProperty.Value
        $isManaged = -not [string]::IsNullOrWhiteSpace($description) -and
            $description.Contains($ManagedByTag, [StringComparison]::Ordinal)
        if ($isManaged) {
            $toolkitManagedPolicyCount++
        }
        if ([string]::Equals(
                $displayName,
                $ExpectedDisplayName,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            if ($isManaged) {
                $managedSameNamePolicyCount++
            }
            else {
                $unmanagedSameNamePolicyCount++
            }
        }

        $assignmentUri = Resolve-IntuneGraphUri -BaseUri $GraphBaseUri `
            -RelativePath "deviceAppManagement/$resourceName/$encodedPolicyId/assignments"
        foreach ($assignment in @(Get-IntuneGraphCollection `
                    -InitialUri $assignmentUri -GraphBaseUri $GraphBaseUri `
                    -EvidenceTarget "$Platform app protection assignments")) {
            $assignments.Add($assignment)
        }

        $appsUri = Resolve-IntuneGraphUri -BaseUri $GraphBaseUri `
            -RelativePath "deviceAppManagement/$resourceName/$encodedPolicyId/apps"
        try {
            $apps = @(Get-IntuneGraphCollection -InitialUri $appsUri `
                    -GraphBaseUri $GraphBaseUri `
                    -EvidenceTarget "$Platform app protection targeted apps" `
                    -ExpectedStatusCodes @(404, 405, 501))
            Assert-IntuneManagedAppCollection -Platform $Platform -Apps $apps
        }
        catch {
            $status = Get-IntuneHttpStatusCode -ErrorRecord $_
            if ($status -in @(404, 405, 501)) {
                $targetAppReadback = 'Unavailable'
            }
            else {
                throw
            }
        }
    }

    return [pscustomobject] @{
        Platform = $Platform
        PolicyCount = $policies.Count
        ToolkitManagedPolicyCount = $toolkitManagedPolicyCount
        ManagedSameNamePolicyCount = $managedSameNamePolicyCount
        UnmanagedSameNamePolicyCount = $unmanagedSameNamePolicyCount
        AssignmentScope = Get-IntuneAssignmentScope `
            -Assignments @($assignments) -PilotGroupId $PilotGroupId
        TargetAppReadback = $targetAppReadback
    }
}

function Add-IntuneAppProtectionFailure {
    param(
        [Parameter(Mandatory)] [ValidateSet('Android', 'iOS')] [string] $Platform,
        [Parameter(Mandatory)] $ErrorRecord
    )

    $status = Get-IntuneHttpStatusCode -ErrorRecord $ErrorRecord
    # The reason is constructed by this module and names only the platform and
    # the evidence target, never a policy, group, app, or tenant identifier, so
    # it is safe to record and keeps a failed run diagnosable.
    $detail = "Platform=$Platform; app protection assessment failed. Reason=$($ErrorRecord.Exception.Message)"
    if ($status) { $detail += " HttpStatusCode=$status." }
    Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
        -Action 'Assessment' -BestPracticeKey 'app-protection-policies' `
        -Status 'Failed' -HttpStatusCode $status -Detail $detail
}

$bestPracticeKey = 'app-protection-policies'
$platforms = @('Android', 'iOS')

if ($Context -and @($Context.BlockedItemKeys) -contains $bestPracticeKey) {
    foreach ($platform in $platforms) {
        Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
            -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
            -Status 'Skipped' -Disposition 'Skipped' `
            -Detail "Platform=$platform; skipped because preflight or operator gating blocked app-protection-policies."
    }
    return
}

try {
    if (-not $Context) {
        throw 'Setup-AppProtectionPolicies.ps1 requires -Context from a pre-authenticated Graph connection. Run it through Deploy-IntuneBestPractice.ps1 or connect to Microsoft Graph yourself and supply -Context.'
    }
    if ([string]::IsNullOrWhiteSpace([string] $Context.TenantAdminUpn)) {
        throw 'Setup-AppProtectionPolicies.ps1 requires Context.TenantAdminUpn for Graph authentication.'
    }
}
catch {
    foreach ($platform in $platforms) {
        Add-IntuneAppProtectionFailure -Platform $platform -ErrorRecord $_
    }
    throw
}

$failures = [System.Collections.Generic.List[string]]::new()
$states = @{}
foreach ($platform in $platforms) {
    try {
        $expectedDisplayName = if ($platform -eq 'iOS') {
            [string] $Config.AppProtection.Ios.DisplayName
        }
        else {
            [string] $Config.AppProtection.Android.DisplayName
        }
        $state = Get-IntuneAppProtectionAssessmentState `
            -Platform $platform `
            -GraphBaseUri $Config.Api.GraphBaseUri `
            -PilotGroupId $PilotGroupId `
            -ManagedByTag $Config.ManagedByTag `
            -ExpectedDisplayName $expectedDisplayName
        $states[$platform] = $state
        $detail = 'Platform={0}; PolicyCount={1}; ToolkitManagedPolicyCount={2}; AssignmentScope={3}; TargetAppReadback={4}.' -f `
            $state.Platform,
            $state.PolicyCount,
            $state.ToolkitManagedPolicyCount,
            $state.AssignmentScope,
            $state.TargetAppReadback
        Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
            -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'GuidedOnly' -Detail $detail
    }
    catch {
        Add-IntuneAppProtectionFailure -Platform $platform -ErrorRecord $_
        $failures.Add($platform)
    }
}

if ($failures.Count -gt 0) {
    throw "App protection assessment failed for: $($failures -join ', ')."
}

if ([string] $Context.AssignmentScope -eq 'TenantWide' -and
    $Context.RollbackAcknowledged -ne $true) {
    $reason = 'Tenant-wide app protection assignment requires Context.RollbackAcknowledged from the verified run context.'
    Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
        -Action 'Deploy' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
        -Detail $reason
    throw $reason
}

# ---------------------------------------------------------------------------
# Write phase: create the Level 1 policy per platform, target the core apps,
# and assign. Idempotent on the managed-by tag.
# ---------------------------------------------------------------------------
$beta = $Config.Api.GraphBetaBaseUri
$pilotGroup = if (-not [string]::IsNullOrWhiteSpace([string] $Context.PilotGroupId)) { $Context.PilotGroupId } else { $PilotGroupId }
$assignmentTarget = $null
$assignmentDetail = $null
if ($Context.AssignmentScope -eq 'TenantWide') {
    $assignmentTarget = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' }
    $assignmentDetail = 'all licensed users'
}
elseif (-not [string]::IsNullOrWhiteSpace([string] $pilotGroup)) {
    $assignmentTarget = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $pilotGroup }
    $assignmentDetail = "pilot group $pilotGroup"
}

foreach ($platform in $platforms) {
    $def = if ($platform -eq 'iOS') { $Config.AppProtection.Ios } else { $Config.AppProtection.Android }
    $resourceName = if ($platform -eq 'iOS') { 'iosManagedAppProtections' } else { 'androidManagedAppProtections' }
    $state = $states[$platform]
    $displayName = $def.DisplayName

    if ($state -and $state.UnmanagedSameNamePolicyCount -gt 0) {
        $reason = "A $platform app protection policy named '$displayName' already exists but is not managed by the toolkit. Rename it or choose a different configured name; the create-only writer will not adopt or overwrite it."
        Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
            -Action 'Deploy' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Target $displayName `
            -Readback 'NotAttempted' -Detail $reason
        throw $reason
    }

    if ($state -and $state.ToolkitManagedPolicyCount -gt 1) {
        $reason = "Multiple toolkit-managed $platform app protection policies exist. Resolve the duplicate ownership collision before rerunning."
        Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
            -Action 'Deploy' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Target $displayName `
            -Readback 'NotAttempted' -Detail $reason
        throw $reason
    }

    if ($state -and $state.ToolkitManagedPolicyCount -eq 1) {
        Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
            -Action 'Deploy' -BestPracticeKey $bestPracticeKey `
            -Status 'Skipped' -Disposition 'AlreadyCompliant' -Target $displayName -Readback 'Verified' `
            -Detail "Platform=$platform; a toolkit-owned app protection policy already exists; leaving it unchanged. The current writer is create-only and does not refresh or rename existing policies."
        continue
    }

    if (-not $PSCmdlet.ShouldProcess("$platform app protection ($displayName)", 'Create policy, target core apps, and assign')) {
        Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
            -Action 'Deploy' -BestPracticeKey $bestPracticeKey `
            -Status 'Info' -Disposition 'WillChange' -Target $displayName -Readback 'NotAttempted' `
            -Detail "WhatIf: would create the $platform baseline app protection policy, target $(@($def.Apps).Count) core apps, and assign to $([string]::IsNullOrWhiteSpace($assignmentDetail) ? 'no target (none provided)' : $assignmentDetail)."
        continue
    }

    $body = [ordered]@{
        '@odata.type' = $def.OdataType
        displayName   = $displayName
        description   = $Config.ManagedByTag
    }
    foreach ($key in $def.Settings.Keys) { $body[$key] = $def.Settings[$key] }
    $bodyJson = $body | ConvertTo-Json -Depth 20

    $created = $null
    try {
        $created = Invoke-WithTransientRetry -Description "Create $platform app protection policy" -Action {
            Invoke-MgGraphRequest -Method POST -Uri "$beta/deviceAppManagement/$resourceName" -Body $bodyJson -ContentType 'application/json'
        }
        Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
            -Action 'Create' -BestPracticeKey $bestPracticeKey `
            -Status 'Created' -Disposition 'Applicable' -Target $displayName `
            -Detail "Created $platform baseline app protection policy."
    }
    catch {
        Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
            -Action 'Create' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Applicable' -Target $displayName `
            -HttpStatusCode (Get-IntuneHttpStatusCode -ErrorRecord $_) `
            -Detail "Failed to create $platform app protection policy: $($_.Exception.Message)"
        throw
    }

    $createdId = [string] $created.id
    if ([string]::IsNullOrWhiteSpace($createdId)) {
        throw "Microsoft Graph returned no ID for the created $platform app protection policy."
    }
    $encodedCreatedId = [uri]::EscapeDataString($createdId)

    $apps = @($def.Apps | ForEach-Object {
        @{ mobileAppIdentifier = @{ '@odata.type' = $def.AppIdentifierType; $def.AppIdentifierKey = $_ } }
    })
    $targetJson = @{ apps = $apps } | ConvertTo-Json -Depth 10
    try {
        Invoke-WithTransientRetry -Description "Target apps for $platform app protection policy" -Action {
            Invoke-MgGraphRequest -Method POST -Uri "$beta/deviceAppManagement/$resourceName('$encodedCreatedId')/targetApps" -Body $targetJson -ContentType 'application/json' | Out-Null
        }
        Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
            -Action 'TargetApps' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'Applicable' -Target $displayName `
            -Detail "Targeted $(@($def.Apps).Count) core Microsoft apps."
    }
    catch {
        Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
            -Action 'TargetApps' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Applicable' -Target $displayName `
            -HttpStatusCode (Get-IntuneHttpStatusCode -ErrorRecord $_) `
            -Detail "Created the policy but failed to target apps: $($_.Exception.Message)"
        throw
    }

    if ($assignmentTarget) {
        $assignJson = @{ assignments = @(@{ target = $assignmentTarget }) } | ConvertTo-Json -Depth 10
        try {
            Invoke-WithTransientRetry -Description "Assign $platform app protection policy" -Action {
                Invoke-MgGraphRequest -Method POST -Uri "$beta/deviceAppManagement/$resourceName('$encodedCreatedId')/assign" -Body $assignJson -ContentType 'application/json' | Out-Null
            }
            Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
                -Action 'Assign' -BestPracticeKey $bestPracticeKey `
                -Status 'Succeeded' -Disposition 'Applicable' -Target $displayName `
                -Detail "Assigned to $assignmentDetail."
        }
        catch {
            Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
                -Action 'Assign' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Applicable' -Target $displayName `
                -HttpStatusCode (Get-IntuneHttpStatusCode -ErrorRecord $_) `
                -Detail "Created and targeted the policy but failed to assign it: $($_.Exception.Message)"
            throw
        }
    }
    else {
        Add-IntuneRunLogEntry -Module 'Setup-AppProtectionPolicies' `
            -Action 'Assign' -BestPracticeKey $bestPracticeKey `
            -Status 'Info' -Disposition 'GuidedOnly' -Target $displayName `
            -Detail "No assignment target was available; the $platform policy was created and targeted but not assigned. Supply -PilotGroupId or -AssignTenantWide to assign it."
    }
}
