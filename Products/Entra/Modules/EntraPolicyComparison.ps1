#requires -Version 7.0
<#
.SYNOPSIS
    Shared Conditional Access policy comparison helpers.

.DESCRIPTION
    Used by both the Conditional Access baseline, which decides whether an
    existing policy already carries the required protections, and the deployment
    health check, which reports drift after a deployment.

    These live in one place on purpose. The same comparison written twice drifts,
    and for a break-glass exclusion check a drifted copy could report a tenant as
    safe when it is one policy promotion away from locking every administrator
    out.

    Read-only. Nothing here issues a Graph request or changes tenant state.
#>

function Get-EntraPolicyProperty {
    <#
        Safe traversal for Graph responses, which arrive as hashtables from
        Invoke-MgGraphRequest but as PSCustomObject from a deserialized fixture.
        Returns $null for a missing node instead of throwing under StrictMode,
        so a policy that omits an optional branch is treated as "not present"
        rather than failing the whole health check.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [string] $Name
    )

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-EntraManagedPropertiesMatch {
    param([AllowNull()] $Expected, [AllowNull()] $Actual)

    if ($null -eq $Expected) { return $null -eq $Actual }
    if ($null -eq $Actual) { return $false }
    if ($Expected -is [System.Collections.IDictionary]) {
        foreach ($key in $Expected.Keys) {
            if (-not (Test-EntraManagedPropertiesMatch -Expected $Expected[$key] `
                    -Actual (Get-EntraPolicyProperty $Actual $key))) { return $false }
        }
        return $true
    }
    if ($Expected -is [bool]) {
        return $Actual -is [bool] -and $Expected -eq $Actual
    }
    if ($Expected -is [string]) {
        return $Actual -is [string] -and $Expected -ceq $Actual
    }
    return ($Expected | ConvertTo-Json -Compress) -ceq ($Actual | ConvertTo-Json -Compress)
}

function Get-EntraNormalizedSet {
    <#
        Order-independent, duplicate-free, string-typed view of a Graph
        collection so two lists can be compared for equality.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()] $Value)
    return @(@($Value) | Where-Object { $_ } | ForEach-Object { [string] $_ } | Sort-Object -Unique)
}

function Get-EntraPolicyDisplayNames {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $DisplayName,
        [Parameter(Mandatory)] [hashtable] $PolicyReference,
        [hashtable] $ConditionalAccess = @{}
    )
    $names = @(
        Get-EntraPolicyDisplayName -DisplayName $DisplayName -PolicyReference $PolicyReference -ConditionalAccess $ConditionalAccess
        $DisplayName
        foreach ($prefix in @(Get-EntraPolicyProperty $ConditionalAccess 'PreviousDisplayNamePrefixes')) {
            if (-not [string]::IsNullOrWhiteSpace([string] $prefix)) {
                Get-EntraPolicyDisplayName -DisplayName $DisplayName -PolicyReference $PolicyReference `
                    -ConditionalAccess @{ DisplayNamePrefix = $prefix }
            }
        }
        Get-EntraPolicyProperty -InputObject $PolicyReference -Name 'LegacyDisplayNames'
    )
    $uniqueNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    return @($names | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and $uniqueNames.Add([string] $_)
    })
}

function Get-EntraPolicyDisplayName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $DisplayName,
        [Parameter(Mandatory)] [hashtable] $PolicyReference,
        [hashtable] $ConditionalAccess = @{}
    )
    $prefix = [string] (Get-EntraPolicyProperty $ConditionalAccess 'DisplayNamePrefix')
    if ([string]::IsNullOrWhiteSpace($prefix)) { return $DisplayName }
    $code = [string] (Get-EntraPolicyProperty $PolicyReference 'NameCode')
    if ([string]::IsNullOrWhiteSpace($code)) {
        throw "Policy '$($PolicyReference.Key)' requires NameCode when DisplayNamePrefix is configured."
    }
    return "$prefix$code-$DisplayName"
}

function Test-EntraPolicySelected {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [hashtable] $PolicyReference)
    if (-not $PolicyReference.ContainsKey('Enabled')) { return $true }
    if ($PolicyReference.Enabled -isnot [bool]) {
        throw "Policy '$($PolicyReference.Key)' Enabled must be a Boolean."
    }
    return $PolicyReference.Enabled
}

function Get-EntraPolicyTier {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [hashtable] $PolicyReference)
    $tier = Get-EntraPolicyProperty $PolicyReference 'Tier'
    if ($null -eq $tier) { return 'P1Baseline' }
    if ($tier -notin @('P1Baseline', 'P1Hardened')) {
        throw "Policy '$($PolicyReference.Key)' has an unsupported tier. P2 risk policies are not deployed by this toolkit."
    }
    return $tier
}

function Assert-EntraPolicyMigrationConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $ConditionalAccess)
    foreach ($reference in @($ConditionalAccess.Policies)) {
        $null = Test-EntraPolicySelected -PolicyReference $reference
        $null = Get-EntraPolicyTier -PolicyReference $reference
        if ($reference.Key -eq 'require-phishing-resistant-mfa-admins' -and
            -not $reference.ContainsKey('Enabled')) {
            throw 'The hardened admin policy requires an explicit Boolean Enabled opt-in.'
        }
        if ($reference.Key -in @(
                'block-device-code-flow', 'protect-security-info-registration', 'require-phishing-resistant-mfa-admins',
                'no-persistent-browser-session', 'require-mfa-admins', 'require-mfa-admin-portals',
                'require-mfa-azure-management', 'require-compliant-device-or-mfa')) {
            $reviewOnly = Get-EntraPolicyProperty $reference 'ReviewExistingOnly'
            if ($reviewOnly -isnot [bool] -or -not $reviewOnly) {
                throw "Policy '$($reference.Key)' requires ReviewExistingOnly=true. Existing targeting, grant, session, authentication-flow, registration and strength changes must be reviewed rather than automatically migrated."
            }
        }
        if ($reference.Key -ne 'require-approved-client-apps') { continue }
        $reviewOnly = Get-EntraPolicyProperty $reference 'ReviewExistingOnly'
        $legacy = @(Get-EntraPolicyProperty $reference 'LegacyDisplayNames')
        if ($reviewOnly -isnot [bool] -or -not $reviewOnly -or
            $legacy.Count -eq 0 -or @($legacy | Where-Object {
                $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_)
            }).Count -gt 0) {
            throw 'The app-protection policy reference requires ReviewExistingOnly=true and nonempty LegacyDisplayNames. Update the supplied configuration using the current EntraConfig.psd1 before running.'
        }
    }
}

function Get-EntraBreakGlassExclusionState {
    <#
    .SYNOPSIS
        Report whether a policy excludes every configured break-glass principal.

    .DESCRIPTION
        This is the lockout control. A Conditional Access policy that enforces
        without excluding the emergency-access principals can lock every
        administrator out of the tenant, and the only safe reading of a policy
        whose exclusions cannot be read is that the exclusion is missing.

        Returns counts rather than identifiers so a caller can log the finding
        without writing directory object IDs into evidence.

    .OUTPUTS
        PSCustomObject with Excluded, MissingUserCount, and MissingGroupCount.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowNull()] $Policy,
        [string[]] $BreakGlassUsers = @(),
        [string[]] $BreakGlassGroups = @()
    )

    $conditions = Get-EntraPolicyProperty -InputObject $Policy -Name 'conditions'
    $users = Get-EntraPolicyProperty -InputObject $conditions -Name 'users'

    $excludedUsers = Get-EntraNormalizedSet (Get-EntraPolicyProperty -InputObject $users -Name 'excludeUsers')
    $excludedGroups = Get-EntraNormalizedSet (Get-EntraPolicyProperty -InputObject $users -Name 'excludeGroups')

    $missingUsers = @(@($BreakGlassUsers) | Where-Object { $_ -and ($_ -notin $excludedUsers) })
    $missingGroups = @(@($BreakGlassGroups) | Where-Object { $_ -and ($_ -notin $excludedGroups) })

    return [pscustomobject] @{
        Excluded = (($missingUsers.Count -eq 0) -and ($missingGroups.Count -eq 0))
        MissingUserCount = $missingUsers.Count
        MissingGroupCount = $missingGroups.Count
    }
}

function Test-EntraBreakGlassExcluded {
    <#
        Boolean form of Get-EntraBreakGlassExclusionState, for callers that only
        need a pass or fail.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()] $Policy,
        [string[]] $BreakGlassUsers = @(),
        [string[]] $BreakGlassGroups = @()
    )

    return (Get-EntraBreakGlassExclusionState -Policy $Policy `
            -BreakGlassUsers $BreakGlassUsers -BreakGlassGroups $BreakGlassGroups).Excluded
}
