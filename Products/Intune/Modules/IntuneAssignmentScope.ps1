#requires -Version 7.0
<#
.SYNOPSIS
    Shared assignment-target scope classification for Intune modules.

.DESCRIPTION
    One traversal of a Microsoft Graph assignment collection, used by every
    Intune module that has to describe how broadly a policy or configuration is
    targeted.

    Modules previously carried their own copy of this logic and the copies
    drifted. The app protection copy classified an exclusion target as Unknown
    while the enrollment copy counted it, and the enrollment copy returned as
    soon as it saw a broad target, so any exclusion later in the collection was
    never counted. Microsoft Graph does not guarantee assignment order, so that
    made the reported exclusion count depend on response ordering.

    Exclusion handling is the one genuine domain difference between callers, so
    it is an explicit parameter here rather than an accident of two separate
    implementations. Everything else is shared.

    This function classifies data the caller already fetched. It issues no Graph
    requests and changes no tenant state.
#>

function Get-IntuneAssignmentTargetProperty {
    <#
        Property reader that tolerates both hashtable and PSObject shapes,
        because Invoke-MgGraphRequest returns either depending on the call.
        Assign through a variable rather than an inline `if`, since a value
        assigned from an `if` block that yields an empty collection collapses to
        $null and would make an empty but valid Graph collection look like a
        missing property.
    #>
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

function Get-IntuneAssignmentScopeResult {
    <#
    .SYNOPSIS
        Classify an assignment collection as None, PilotOnly, Broad, or Unknown.

    .PARAMETER ExclusionBehavior
        How to treat an exclusionGroupAssignmentTarget. 'Unknown' marks the
        whole collection Unknown, which is what a caller that does not model
        exclusions should do so it never overstates how narrow the targeting is.
        'Count' records the exclusions in ExclusionCount and lets the rest of the
        collection decide the scope.

    .PARAMETER MissingTargetMessage
        Message thrown when an assignment carries no target. Callers supply
        their own so the failure names the resource the operator was reading.

    .OUTPUTS
        PSCustomObject with Scope and ExclusionCount. ExclusionCount is always 0
        when ExclusionBehavior is 'Unknown'.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyCollection()] [object[]] $Assignments,
        [string] $PilotGroupId,
        [ValidateSet('Unknown', 'Count')] [string] $ExclusionBehavior = 'Unknown',
        [string] $MissingTargetMessage = 'Microsoft Graph returned an assignment without a target.'
    )

    if (@($Assignments).Count -eq 0) {
        return [pscustomobject] @{ Scope = 'None'; ExclusionCount = 0 }
    }

    $hasBroad = $false
    $hasUnknown = $false
    $exclusionCount = 0
    $groupIds = [System.Collections.Generic.List[string]]::new()

    foreach ($assignment in @($Assignments)) {
        # Every assignment is validated, including any that follow a broad
        # target. The enrollment classifier used to return at the first broad
        # target, so whether a malformed assignment was caught at all depended
        # on the order Microsoft Graph returned assignments in. Walking the
        # whole collection makes that deterministic and fails closed, which is
        # what the app protection caller already did.
        $target = Get-IntuneAssignmentTargetProperty -InputObject $assignment -Name 'target'
        if (-not $target.Exists -or $null -eq $target.Value) {
            throw $MissingTargetMessage
        }

        $targetType = [string] (Get-IntuneAssignmentTargetProperty `
                -InputObject $target.Value -Name '@odata.type').Value

        # Exclusion is tested first on purpose. The group pattern below is a
        # substring of exclusionGroupAssignmentTarget, so testing group first
        # would swallow every exclusion target and read its group as an include.
        if ($targetType -match '(?i)exclusionGroupAssignmentTarget$') {
            if ($ExclusionBehavior -eq 'Count') { $exclusionCount++ } else { $hasUnknown = $true }
            continue
        }

        # Flag rather than return. Returning here would stop the walk and lose
        # any exclusion that sorts after the broad target, which is the ordering
        # defect this shared helper exists to prevent.
        if ($targetType -match '(?i)(?:allLicensedUsersAssignmentTarget|allDevicesAssignmentTarget)$') {
            $hasBroad = $true
            continue
        }

        # Covers a blank or absent @odata.type as well, which must never be
        # read as a narrow assignment.
        if ($targetType -notmatch '(?i)(?:groupAssignmentTarget|scopeTagGroupAssignmentTarget)$') {
            $hasUnknown = $true
            continue
        }

        # groupAssignmentTarget carries groupId and scopeTagGroupAssignmentTarget
        # carries entraObjectId, so exactly one is normally present. Both
        # original classifiers keyed their fallback on whether the property
        # EXISTED, not on whether it held a value, so a present-but-empty
        # identifier meant Unknown rather than silently falling through to the
        # other name. Preserve that, and when both properties exist with
        # different values there is no safe way to pick a winner, so report
        # Unknown rather than risk reporting targeting narrower than it is.
        $group = Get-IntuneAssignmentTargetProperty -InputObject $target.Value -Name 'groupId'
        $altGroup = Get-IntuneAssignmentTargetProperty `
            -InputObject $target.Value -Name 'entraObjectId'

        $groupId = ''
        if ($group.Exists -and $altGroup.Exists) {
            if (-not [string]::Equals(
                    [string] $group.Value,
                    [string] $altGroup.Value,
                    [StringComparison]::OrdinalIgnoreCase)) {
                $hasUnknown = $true
                continue
            }
            $groupId = [string] $group.Value
        }
        elseif ($group.Exists) { $groupId = [string] $group.Value }
        elseif ($altGroup.Exists) { $groupId = [string] $altGroup.Value }

        if ([string]::IsNullOrWhiteSpace($groupId)) {
            $hasUnknown = $true
            continue
        }
        $groupIds.Add($groupId)
    }

    # Broad outranks Unknown. A collection that reaches everyone is reported as
    # Broad even when another target could not be read, because that is the
    # wider and therefore safer thing to tell the operator.
    $scope =
        if ($hasBroad) { 'Broad' }
        elseif ($hasUnknown) { 'Unknown' }
        elseif ([string]::IsNullOrWhiteSpace($PilotGroupId)) { 'Broad' }
        elseif (@($groupIds | Where-Object {
                    -not [string]::Equals(
                        $_,
                        $PilotGroupId,
                        [StringComparison]::OrdinalIgnoreCase
                    )
                }).Count -gt 0) { 'Broad' }
        else { 'PilotOnly' }

    return [pscustomobject] @{ Scope = $scope; ExclusionCount = $exclusionCount }
}
