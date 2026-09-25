#requires -Version 7.0
<#
.SYNOPSIS
    Device platform enrollment restrictions (guide task 5).

.DESCRIPTION
    Inventories existing device enrollment platform restrictions, then creates
    the restrictions defined in EnrollmentRestrictions.Restrictions and assigns
    them. Safe by default: the shipped payload blocks only personally owned
    enrollment on used platforms, so corporate enrollment continues to work.

    A misconfigured restriction can block the enrollment the rest of the
    baseline depends on, so this is High risk: the write only runs when the
    orchestrator has cleared the item (IncludeHighRisk + EnableEnrollmentRestrictions);
    otherwise the module assesses and reports. Idempotent on display name; every
    change is gated by ShouldProcess, wrapped in the shared transient-retry
    boundary, and read back.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [switch] $AdoptExisting,
    # High-risk authorization; the orchestrator also records the item in
    # Context.WriteBlockedItemKeys when these are absent.
    [switch] $IncludeHighRisk,
    [switch] $EnableEnrollmentRestrictions
)

$ErrorActionPreference = 'Stop'
$ConfirmPreference = 'None'

. (Join-Path $PSScriptRoot 'IntuneRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'IntuneAssignmentScope.ps1')
. (Join-Path $PSScriptRoot 'IntuneGraphClient.ps1')

function Get-IntuneEnrollmentProperty {
    [CmdletBinding()]
    param(
        [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [string] $Name
    )

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

function New-IntuneEnrollmentSafeException {
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

function Get-IntuneEnrollmentCollection {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string] $InitialUri,
        [Parameter(Mandatory)] [string] $GraphBaseUri,
        [Parameter(Mandatory)] [string] $EvidenceTarget
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
            -not [string]::Equals($parsedNext.Host, $base.Host, [StringComparison]::OrdinalIgnoreCase) -or
            -not $parsedNext.AbsolutePath.StartsWith(
                $expectedPathPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Microsoft Graph returned a next link outside the configured Graph API path for $EvidenceTarget."
        }

        $response = Invoke-WithTransientRetry -Description "Get $EvidenceTarget" -Action {
            try {
                Invoke-IntuneGraphRequest -Method 'GET' -Uri $nextUri `
                    -EvidenceTarget $EvidenceTarget -DeferFailureEvidence
            }
            catch {
                throw (New-IntuneEnrollmentSafeException `
                        -EvidenceTarget $EvidenceTarget -ErrorRecord $_)
            }
        }
        $value = Get-IntuneEnrollmentProperty -InputObject $response -Name 'value'
        if (-not $value.Exists -or $null -eq $value.Value) {
            throw "Microsoft Graph returned no value collection for $EvidenceTarget."
        }
        foreach ($item in @($value.Value)) {
            if ($null -eq $item) {
                throw "Microsoft Graph returned a null collection item for $EvidenceTarget."
            }
            $results.Add($item)
        }
        $nextLink = Get-IntuneEnrollmentProperty `
            -InputObject $response -Name '@odata.nextLink'
        $nextUri = if ($nextLink.Exists) { [string] $nextLink.Value } else { $null }
    }
    return @($results)
}

function Get-IntuneEnrollmentAssignmentScope {
    <#
        Thin wrapper over the shared classifier in IntuneAssignmentScope.ps1.
        Enrollment restrictions report exclusions to the operator, so exclusion
        targets are counted rather than treated as Unknown.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyCollection()] [object[]] $Assignments,
        [string] $PilotGroupId
    )

    return Get-IntuneAssignmentScopeResult `
        -Assignments $Assignments `
        -PilotGroupId $PilotGroupId `
        -ExclusionBehavior 'Count' `
        -MissingTargetMessage 'Microsoft Graph returned an enrollment restriction assignment without a target.'
}

$bestPracticeKey = 'enrollment-restrictions'

if ($Context -and @($Context.BlockedItemKeys) -contains $bestPracticeKey) {
    Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
        -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
        -Status 'Skipped' -Disposition 'Skipped' `
        -Detail 'Skipped because preflight or operator gating blocked enrollment-restrictions.'
    return
}

try {
    if (-not $Context) {
        throw 'Setup-EnrollmentRestrictions.ps1 requires -Context from a pre-authenticated Graph connection. Run it through Deploy-IntuneBestPractice.ps1 or connect to Microsoft Graph yourself and supply -Context.'
    }
    if ([string]::IsNullOrWhiteSpace([string] $Context.TenantAdminUpn)) {
        throw 'Setup-EnrollmentRestrictions.ps1 requires Context.TenantAdminUpn for Graph authentication.'
    }

    $collectionUri = Resolve-IntuneGraphUri -BaseUri $Config.Api.GraphBaseUri `
        -RelativePath 'deviceManagement/deviceEnrollmentConfigurations'
    $allConfigurations = @(Get-IntuneEnrollmentCollection `
            -InitialUri $collectionUri -GraphBaseUri $Config.Api.GraphBaseUri `
            -EvidenceTarget 'device enrollment configurations')
    $configurations = @($allConfigurations | Where-Object {
            $type = Get-IntuneEnrollmentProperty -InputObject $_ -Name '@odata.type'
            [string] $type.Value -match '(?i)deviceEnrollmentPlatformRestrictionsConfiguration$'
        })

    $assignments = [System.Collections.Generic.List[object]]::new()
    $assignedPlatformBlockedSignals = 0
    $assignedPersonalBlockedSignals = 0
    $unassignedPlatformBlockedSignals = 0
    $unassignedPersonalBlockedSignals = 0
    $assignedConfigurationCount = 0
    $unassignedConfigurationCount = 0
    $restrictionProperties = @(
        'iosRestriction',
        'windowsRestriction',
        'windowsMobileRestriction',
        'androidRestriction',
        'macOSRestriction'
    )
    foreach ($configuration in $configurations) {
        $id = Get-IntuneEnrollmentProperty -InputObject $configuration -Name 'id'
        if (-not $id.Exists -or
            [string]::IsNullOrWhiteSpace([string] $id.Value)) {
            throw 'Microsoft Graph returned a malformed enrollment restriction configuration ID.'
        }
        $encodedConfigurationId = [uri]::EscapeDataString([string] $id.Value)
        foreach ($propertyName in $restrictionProperties) {
            $restriction = Get-IntuneEnrollmentProperty `
                -InputObject $configuration -Name $propertyName
            if (-not $restriction.Exists -or $null -eq $restriction.Value) {
                throw "Microsoft Graph returned no $propertyName value for an enrollment restriction configuration."
            }
            foreach ($flagName in @('platformBlocked', 'personalDeviceEnrollmentBlocked')) {
                $flag = Get-IntuneEnrollmentProperty `
                    -InputObject $restriction.Value -Name $flagName
                if (-not $flag.Exists -or $flag.Value -isnot [bool]) {
                    throw "Microsoft Graph returned a malformed $propertyName.$flagName value."
                }
            }
        }

        $assignmentUri = Resolve-IntuneGraphUri -BaseUri $Config.Api.GraphBaseUri `
            -RelativePath "deviceManagement/deviceEnrollmentConfigurations/$encodedConfigurationId/assignments"
        $configurationAssignments = @(Get-IntuneEnrollmentCollection `
                    -InitialUri $assignmentUri `
                    -GraphBaseUri $Config.Api.GraphBaseUri `
                    -EvidenceTarget 'enrollment restriction assignments')
        foreach ($assignment in $configurationAssignments) {
            $assignments.Add($assignment)
        }
        $isAssigned = $configurationAssignments.Count -gt 0
        if ($isAssigned) { $assignedConfigurationCount++ } else { $unassignedConfigurationCount++ }
        foreach ($propertyName in $restrictionProperties) {
            $restriction = (Get-IntuneEnrollmentProperty `
                -InputObject $configuration -Name $propertyName).Value
            if ((Get-IntuneEnrollmentProperty -InputObject $restriction -Name 'platformBlocked').Value) {
                if ($isAssigned) { $assignedPlatformBlockedSignals++ } else { $unassignedPlatformBlockedSignals++ }
            }
            if ((Get-IntuneEnrollmentProperty -InputObject $restriction -Name 'personalDeviceEnrollmentBlocked').Value) {
                if ($isAssigned) { $assignedPersonalBlockedSignals++ } else { $unassignedPersonalBlockedSignals++ }
            }
        }
    }

    $scopeResult = Get-IntuneEnrollmentAssignmentScope `
        -Assignments @($assignments) -PilotGroupId $Context.PilotGroupId
    $scope = $scopeResult.Scope
    $exclusionCount = $scopeResult.ExclusionCount
    $detail = 'ConfigurationCount={0}; AssignedConfigurationCount={1}; UnassignedConfigurationCount={2}; AssignedScope={3}; ExclusionCount={4}; AssignedPlatformBlockedSignals={5}; AssignedPersonalBlockedSignals={6}; UnassignedPlatformBlockedSignals={7}; UnassignedPersonalBlockedSignals={8}; Assessment=InventoryOnly.' -f `
        $configurations.Count,
        $assignedConfigurationCount,
        $unassignedConfigurationCount,
        $scope,
        $exclusionCount,
        $assignedPlatformBlockedSignals,
        $assignedPersonalBlockedSignals,
        $unassignedPlatformBlockedSignals,
        $unassignedPersonalBlockedSignals
    Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
        -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
        -Status 'Succeeded' -Disposition 'GuidedOnly' -Detail $detail

    # ---- Write phase ----
    if (@($Context.WriteBlockedItemKeys) -contains $bestPracticeKey -or
        -not $IncludeHighRisk -or
        -not $EnableEnrollmentRestrictions -or
        -not [bool] $Context.IncludeHighRisk) {
        Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
            -Action 'EnrollmentRestrictions' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'GuidedOnly' `
            -Detail 'Assessment only: creating enrollment restrictions is withheld until IncludeHighRisk and EnableEnrollmentRestrictions are supplied. A misconfigured restriction can block the enrollment the rest of the baseline depends on.'
        return
    }

    if ([string] $Context.AssignmentScope -eq 'TenantWide') {
        if ($Context.RollbackAcknowledged -ne $true) {
            $reason = 'Tenant-wide enrollment restriction assignment requires Context.RollbackAcknowledged from the verified run context.'
            Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
                -Action 'EnrollmentRestrictions' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
                -Detail $reason
            throw $reason
        }
        if ($Config.Assignment.AllowTenantWideAssignmentForHighRisk -isnot [bool] -or
            -not $Config.Assignment.AllowTenantWideAssignmentForHighRisk) {
            $reason = 'Tenant-wide enrollment restriction assignment is disabled by Assignment.AllowTenantWideAssignmentForHighRisk in configuration.'
            Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
                -Action 'EnrollmentRestrictions' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
                -Detail $reason
            throw $reason
        }
    }
    elseif ([string] $Context.AssignmentScope -ne 'PilotGroup' -or
        [string]::IsNullOrWhiteSpace([string] $Context.PilotGroupId)) {
        $reason = 'Enrollment restriction creation requires a verified PilotGroup assignment scope and Context.PilotGroupId unless tenant-wide assignment was explicitly authorized.'
        Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
            -Action 'EnrollmentRestrictions' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
            -Detail $reason
        throw $reason
    }

    $tag = $Config.ManagedByTag
    $expectedNames = @($Config.EnrollmentRestrictions.Restrictions | ForEach-Object DisplayName)
    $existingNames = @{}
    foreach ($c in $allConfigurations) {
        $dn = Get-IntuneEnrollmentProperty -InputObject $c -Name 'displayName'
        if ($dn.Exists -and $dn.Value) {
            $description = Get-IntuneEnrollmentProperty -InputObject $c -Name 'description'
            $isManaged = $description.Exists -and
                $description.Value -is [string] -and
                ([string] $description.Value).Contains($tag, [StringComparison]::Ordinal)
            $name = [string] $dn.Value
            if ($isManaged -and $name -notin $expectedNames) {
                $reason = 'A toolkit-managed enrollment configuration has an unexpected name. Reconcile its recorded object ID and configured name before creating more restrictions; renamed managed objects are not duplicated.'
                Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
                    -Action 'Collision' -BestPracticeKey $bestPracticeKey `
                    -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
                    -Detail $reason
                throw $reason
            }
            if (-not $existingNames.ContainsKey($name)) {
                $existingNames[$name] = [pscustomobject] @{
                    ManagedCount = 0
                    UnmanagedCount = 0
                }
            }
            if ($isManaged) {
                $existingNames[$name].ManagedCount++
            }
            else {
                $existingNames[$name].UnmanagedCount++
            }
        }
    }

    $createUri = "$($Config.Api.GraphBetaBaseUri)/deviceManagement/deviceEnrollmentConfigurations"
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

    foreach ($restriction in @($Config.EnrollmentRestrictions.Restrictions)) {
        $dn = [string] $restriction.DisplayName

        if ($existingNames.ContainsKey($dn) -and
            $existingNames[$dn].UnmanagedCount -gt 0) {
            $reason = "An enrollment restriction named '$dn' already exists but is not managed by the toolkit. Rename it or choose a different configured name; the create-only writer will not adopt or overwrite it."
            Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
                -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Target $dn `
                -Readback 'NotAttempted' -Detail $reason
            throw $reason
        }

        if ($existingNames.ContainsKey($dn) -and
            $existingNames[$dn].ManagedCount -gt 0) {
            Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
                -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Skipped' -Disposition 'AlreadyCompliant' -Target $dn -Readback 'Verified' `
                -Detail "An enrollment restriction named '$dn' already exists; leaving it unchanged. The current writer is create-only and does not refresh existing restrictions."
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($dn, 'Create enrollment platform restriction and assign')) {
            Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
                -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Info' -Disposition 'WillChange' -Target $dn -Readback 'NotAttempted' `
                -Detail "WhatIf: would create enrollment restriction '$dn' (platform=$($restriction.PlatformType), platformBlocked=$([bool] $restriction.PlatformBlocked), personalBlocked=$([bool] $restriction.PersonalDeviceEnrollmentBlocked)) and assign to $([string]::IsNullOrWhiteSpace($assignmentDetail) ? 'no target (none provided)' : $assignmentDetail)."
            continue
        }

        $body = @{
            '@odata.type'       = '#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration'
            displayName         = $dn
            description         = $tag
            platformType        = $restriction.PlatformType
            platformRestriction = @{
                '@odata.type'                    = 'microsoft.graph.deviceEnrollmentPlatformRestriction'
                platformBlocked                 = [bool] $restriction.PlatformBlocked
                personalDeviceEnrollmentBlocked = [bool] $restriction.PersonalDeviceEnrollmentBlocked
                osMinimumVersion                = ''
                osMaximumVersion                = ''
                blockedManufacturers            = @()
                blockedSkus                     = @()
            }
        } | ConvertTo-Json -Depth 10

        $created = $null
        try {
            $created = Invoke-WithTransientRetry -Description "Create enrollment restriction '$dn'" -Action {
                Invoke-MgGraphRequest -Method POST -Uri $createUri -Body $body -ContentType 'application/json'
            }
            Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
                -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Created' -Disposition 'Applicable' -Target $dn `
                -Detail "Created enrollment restriction '$dn'."
        }
        catch {
            Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
                -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Applicable' -Target $dn `
                -HttpStatusCode (Get-IntuneHttpStatusCode -ErrorRecord $_) `
                -Detail "Failed to create enrollment restriction '$dn': $($_.Exception.Message)"
            throw
        }

        $createdIdProperty = Get-IntuneEnrollmentProperty -InputObject $created -Name 'id'
        if (-not $createdIdProperty.Exists -or
            [string]::IsNullOrWhiteSpace([string] $createdIdProperty.Value)) {
            throw "Microsoft Graph returned no ID for the created enrollment restriction '$dn'."
        }
        $encodedCreatedId = [uri]::EscapeDataString([string] $createdIdProperty.Value)

        if ($assignmentTarget) {
            $assignBody = @{ enrollmentConfigurationAssignments = @(@{ target = $assignmentTarget }) } | ConvertTo-Json -Depth 10
            try {
                Invoke-WithTransientRetry -Description "Assign enrollment restriction '$dn'" -Action {
                    Invoke-MgGraphRequest -Method POST -Uri "$createUri/$encodedCreatedId/assign" -Body $assignBody -ContentType 'application/json' | Out-Null
                }
                Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
                    -Action 'Assign' -BestPracticeKey $bestPracticeKey `
                    -Status 'Succeeded' -Disposition 'Applicable' -Target $dn `
                    -Detail "Assigned '$dn' to $assignmentDetail."
            }
            catch {
                Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
                    -Action 'Assign' -BestPracticeKey $bestPracticeKey `
                    -Status 'Failed' -Disposition 'Applicable' -Target $dn `
                    -HttpStatusCode (Get-IntuneHttpStatusCode -ErrorRecord $_) `
                    -Detail "Created '$dn' but failed to assign it: $($_.Exception.Message)"
                throw
            }
        }

        try {
            $verify = Invoke-WithTransientRetry -Description "Read back enrollment restriction '$dn'" -Action {
                Invoke-MgGraphRequest -Method GET -Uri "$createUri/$encodedCreatedId"
            }
            $readback = if ($verify -and $verify.displayName -eq $dn) { 'Verified' } else { 'Mismatch' }
            if ($readback -ne 'Verified') {
                $reason = "Enrollment restriction readback did not confirm the configured display name '$dn'."
                Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
                    -Action 'Readback' -BestPracticeKey $bestPracticeKey `
                    -Status 'Failed' -Disposition 'Blocked' -Target $dn -Readback $readback `
                    -Detail $reason
                throw $reason
            }
            Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
                -Action 'Readback' -BestPracticeKey $bestPracticeKey `
                -Status 'Info' -Disposition 'Applicable' -Target $dn -Readback $readback `
                -Detail "Read-back returned displayName='$($verify.displayName)'."
        }
        catch {
            if ([string] $_.Exception.Message -eq "Enrollment restriction readback did not confirm the configured display name '$dn'.") {
                throw
            }
            Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
                -Action 'Readback' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Target $dn -Readback 'NotAttempted' `
                -Detail "Read-back could not be completed: $($_.Exception.Message)"
            throw
        }
    }
}
catch {
    $status = Get-IntuneHttpStatusCode -ErrorRecord $_
    Add-IntuneRunLogEntry -Module 'Setup-EnrollmentRestrictions' `
        -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -HttpStatusCode $status `
        -Detail "Enrollment restriction assessment failed. Reason=$($_.Exception.Message)"
    throw
}
