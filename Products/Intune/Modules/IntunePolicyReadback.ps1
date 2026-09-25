#requires -Version 7.0
<#
.SYNOPSIS
    Compare managed JSON fields and exact assignment intent without coercion.
#>

function Get-IntuneReadbackProperty {
    param([AllowNull()] $InputObject, [Parameter(Mandatory)] [string] $Name)

    $exists = $false
    $value = $null
    if ($InputObject -is [System.Collections.IDictionary]) {
        $exists = $InputObject.Contains($Name)
        if ($exists) { $value = $InputObject[$Name] }
    }
    elseif ($null -ne $InputObject) {
        $property = $InputObject.PSObject.Properties[$Name]
        $exists = $null -ne $property
        if ($exists) { $value = $property.Value }
    }
    return [pscustomobject] @{ Exists = $exists; Value = $value }
}

function Test-IntuneManagedValue {
    param([AllowNull()] $Expected, [AllowNull()] $Actual, [string] $PropertyName = '')

    if ($null -eq $Expected) { return $null -eq $Actual }
    if ($null -eq $Actual) { return $false }
    if ($Expected -is [System.Collections.IDictionary] -or $Expected -is [pscustomobject]) {
        if ($Actual -isnot [System.Collections.IDictionary] -and $Actual -isnot [pscustomobject]) {
            return $false
        }
        $names = if ($Expected -is [System.Collections.IDictionary]) {
            @($Expected.Keys)
        } else { @($Expected.PSObject.Properties.Name) }
        foreach ($name in $names) {
            $wanted = Get-IntuneReadbackProperty $Expected $name
            $found = Get-IntuneReadbackProperty $Actual $name
            # This non-derived complex type is known from the property schema;
            # Graph can omit its OData annotation. Root resource types must match.
            if ($name -eq '@odata.type' -and $PropertyName -eq 'platformRestriction' -and
                $wanted.Value -in @('microsoft.graph.deviceEnrollmentPlatformRestriction',
                    '#microsoft.graph.deviceEnrollmentPlatformRestriction') -and -not $found.Exists) {
                continue
            }
            if (-not $found.Exists -or -not (Test-IntuneManagedValue $wanted.Value $found.Value $name)) {
                return $false
            }
        }
        # Properties not managed by the payload, including server metadata, are preserved.
        return $true
    }
    if ($Expected -is [System.Collections.IList]) {
        if ($Actual -isnot [System.Collections.IList] -or $Expected.Count -ne $Actual.Count) { return $false }
        $unordered = $PropertyName -in @(
            'scheduledActionsForRule', 'scheduledActionConfigurations', 'roleScopeTagIds',
            'notificationMessageCCList', 'restrictedApps', 'blockedManufacturers', 'blockedSkus'
        )
        $used = [System.Collections.Generic.HashSet[int]]::new()
        for ($i = 0; $i -lt $Expected.Count; $i++) {
            if (-not $unordered) {
                if (-not (Test-IntuneManagedValue $Expected[$i] $Actual[$i])) { return $false }
                continue
            }
            $matched = $false
            for ($j = 0; $j -lt $Actual.Count; $j++) {
                if (-not $used.Contains($j) -and (Test-IntuneManagedValue $Expected[$i] $Actual[$j])) {
                    $null = $used.Add($j)
                    $matched = $true
                    break
                }
            }
            if (-not $matched) { return $false }
        }
        return $true
    }
    if ($Expected -is [bool]) { return $Actual -is [bool] -and $Expected -eq $Actual }
    if ($Expected -is [string]) {
        if ($Actual -isnot [string]) { return $false }
        if ($PropertyName -eq '@odata.type') {
            return [string]::Equals($Expected.TrimStart('#'), $Actual.TrimStart('#'), [StringComparison]::Ordinal)
        }
        return [string]::Equals($Expected, $Actual, [StringComparison]::Ordinal)
    }
    # JSON numbers can deserialize to different CLR numeric types, but never strings or Booleans.
    $numericTypes = @([byte], [sbyte], [short], [ushort], [int], [uint], [long], [ulong], [float], [double], [decimal])
    if ($Expected.GetType() -in $numericTypes -and $Actual.GetType() -in $numericTypes) {
        return $Expected -eq $Actual
    }
    return $false
}

function Test-IntuneExactAssignment {
    param([AllowNull()] $ExpectedTarget, [AllowEmptyCollection()] [object[]] $Assignments)

    if ($null -eq $ExpectedTarget) { return @($Assignments).Count -eq 0 }
    if (@($Assignments).Count -ne 1) { return $false }
    $target = (Get-IntuneReadbackProperty $Assignments[0] 'target').Value
    if (-not (Test-IntuneManagedValue $ExpectedTarget $target)) { return $false }
    $names = if ($target -is [System.Collections.IDictionary]) {
        @($target.Keys)
    } else { @($target.PSObject.Properties.Name) }
    foreach ($name in $names) {
        if ((Get-IntuneReadbackProperty $ExpectedTarget $name).Exists) { continue }
        $value = (Get-IntuneReadbackProperty $target $name).Value
        switch -Exact ($name) {
            'deviceAndAppManagementAssignmentFilterType' {
                if ($null -ne $value -and ($value -isnot [string] -or $value -cne 'none')) { return $false }
            }
            'deviceAndAppManagementAssignmentFilterId' {
                if ($null -ne $value -and ($value -isnot [string] -or $value -cne '')) { return $false }
            }
            default { return $false }
        }
    }
    return $true
}
