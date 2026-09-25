#requires -Version 7.0
<#
.SYNOPSIS
    Shared read-only directory reads used by more than one Entra module.

.DESCRIPTION
    Holds Graph GET helpers that both the emergency-access setup and the
    deployment health check need. They live here so the two cannot disagree
    about whether an emergency-access principal can actually recover the tenant.

    Read-only. Every function here issues GET requests only.
#>

. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'EntraPolicyComparison.ps1')

# The Global Administrator role definition id. Microsoft's emergency-access
# guidance requires this role assigned PERMANENTLY, not PIM-eligible, so a PIM
# outage cannot lock the tenant out.
$script:EntraGlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'

function Get-EntraGlobalAdminRoleId {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return $script:EntraGlobalAdminRoleId
}

function Test-EntraDirectoryPropertyPresent {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [string] $Name
    )

    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject.Contains($Name)
    }
    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function Get-EntraGlobalAdminPrincipalId {
    <#
        Principals (users, or role-assignable groups) holding a permanently
        assigned Global Administrator role. Read once and reused, because every
        break-glass principal is checked against the same list.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $BaseUri,
        [string] $RoleId = $script:EntraGlobalAdminRoleId
    )

    $assignments = Get-EntraGraphCollection -BaseUri $BaseUri `
        -Uri "$BaseUri/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=roleDefinitionId eq '$RoleId'&`$select=principalId,assignmentType,endDateTime,directoryScopeId" `
        -Description 'Read Global Administrator assignments'
    return @(@($assignments) | ForEach-Object {
            $principalId = [string] (Get-EntraPolicyProperty -InputObject $_ -Name 'principalId')
            $assignmentType = [string] (Get-EntraPolicyProperty -InputObject $_ -Name 'assignmentType')
            $endDateTime = Get-EntraPolicyProperty -InputObject $_ -Name 'endDateTime'
            $directoryScopeId = [string] (Get-EntraPolicyProperty -InputObject $_ -Name 'directoryScopeId')
            if ($assignmentType -ceq 'Assigned' -and
                (Test-EntraDirectoryPropertyPresent -InputObject $_ -Name 'endDateTime') -and
                $null -eq $endDateTime -and
                $directoryScopeId -eq '/' -and
                -not [string]::IsNullOrWhiteSpace($principalId)) {
                $principalId
            }
        })
}

function Test-EntraGraphContinuationUri {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $BaseUri,
        [Parameter(Mandatory)] [string] $ContinuationUri
    )

    [uri] $parsedBaseUri = $null
    [uri] $parsedContinuationUri = $null
    if (-not [uri]::TryCreate($BaseUri, [UriKind]::Absolute, [ref] $parsedBaseUri) -or
        -not [uri]::TryCreate($ContinuationUri, [UriKind]::Absolute, [ref] $parsedContinuationUri)) {
        return $false
    }
    if ($parsedBaseUri.Scheme -ne [uri]::UriSchemeHttps -or
        $parsedContinuationUri.Scheme -ne [uri]::UriSchemeHttps) {
        return $false
    }
    if (-not [string]::IsNullOrEmpty($parsedBaseUri.UserInfo) -or
        -not [string]::IsNullOrEmpty($parsedContinuationUri.UserInfo)) {
        return $false
    }
    if ($parsedBaseUri.Port -ne $parsedContinuationUri.Port) {
        return $false
    }
    if ($parsedBaseUri.Port -ne 443) {
        return $false
    }
    if (-not $parsedBaseUri.IdnHost.Equals(
            $parsedContinuationUri.IdnHost,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        return $false
    }

    $basePath = $parsedBaseUri.AbsolutePath.TrimEnd('/')
    if ([string]::IsNullOrEmpty($basePath)) { $basePath = '/' }
    $continuationPath = $parsedContinuationUri.AbsolutePath.TrimEnd('/')
    if ([string]::IsNullOrEmpty($continuationPath)) { $continuationPath = '/' }
    if ($continuationPath.Equals($basePath, [StringComparison]::Ordinal)) {
        return $true
    }
    if ($basePath -eq '/') {
        # Every absolute URI path is at or below root. The authority checks
        # above are therefore sufficient when the configured base path is root.
        return $true
    }
    return $continuationPath.StartsWith("$basePath/", [StringComparison]::Ordinal)
}

function Get-EntraGraphCollection {
    <#
        Follow every @odata.nextLink page of a Graph collection.

        Pagination matters for any safety check: a single unread page can hide
        the one policy or the one enabled member that changes the verdict. A
        continuation link is service-supplied input, so a link that leaves the
        configured Graph host is refused rather than followed.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $BaseUri,
        [Parameter(Mandatory)] [string] $Description,
        [int] $PageLimit = 200
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    $pageGuard = 0

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        if (++$pageGuard -gt $PageLimit) {
            throw "$Description exceeded $PageLimit pages; refusing to continue rather than loop indefinitely."
        }
        $requestUri = $nextUri
        $response = Invoke-WithTransientRetry -Description $Description -Action {
            Invoke-MgGraphRequest -Method GET -Uri $requestUri
        }
        foreach ($item in @(Get-EntraPolicyProperty -InputObject $response -Name 'value')) {
            if ($null -ne $item) { $items.Add($item) }
        }

        $link = [string] (Get-EntraPolicyProperty -InputObject $response -Name '@odata.nextLink')
        if ([string]::IsNullOrWhiteSpace($link)) { break }
        if (-not (Test-EntraGraphContinuationUri -BaseUri $BaseUri -ContinuationUri $link)) {
            throw "$Description returned an unsafe pagination link. Continuation links must use absolute HTTPS without user information, default port 443, the configured host, and the configured base path."
        }
        $nextUri = $link
    }

    return , @($items)
}

function Get-EntraGlobalAdminRecoveryState {
    <#
    .SYNOPSIS
        Determines whether an emergency principal can recover the tenant.

    .DESCRIPTION
        Uses one implementation for setup-time verification and post-deployment
        health. A user is valid when Global Administrator is assigned directly
        or through a role-assignable group. A group is valid when the role is
        assigned to the group or to one of its enabled transitive user members.

        GlobalAdminPrincipalIds must come from
        Get-EntraGlobalAdminPrincipalId, which reads permanent active role
        assignments rather than PIM eligibility.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $BaseUri,
        [Parameter(Mandatory)] [string] $PrincipalId,
        [Parameter(Mandatory)] [ValidateSet('User', 'Group')] [string] $PrincipalType,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $GlobalAdminPrincipalIds,
        [AllowEmptyCollection()] [string[]] $EnabledMemberIds = @()
    )

    if ($PrincipalId -in $GlobalAdminPrincipalIds) {
        $roleVia = if ($PrincipalType -eq 'User') {
            'directly'
        }
        else {
            'assigned to the group'
        }
        return [pscustomobject] @{
            HasGlobalAdmin = $true
            RoleVia = $roleVia
        }
    }

    if ($PrincipalType -eq 'User' -and $GlobalAdminPrincipalIds.Count -gt 0) {
        $encodedPrincipalId = [uri]::EscapeDataString($PrincipalId)
        $memberships = Get-EntraGraphCollection -BaseUri $BaseUri `
            -Uri "$BaseUri/users/$encodedPrincipalId/transitiveMemberOf/microsoft.graph.group?`$select=id" `
            -Description 'Read break-glass group memberships'
        $membershipIds = @(@($memberships) | ForEach-Object {
                [string] (Get-EntraPolicyProperty -InputObject $_ -Name 'id')
            } | Where-Object { $_ })
        if (@($membershipIds | Where-Object {
                    $_ -in $GlobalAdminPrincipalIds
                }).Count -gt 0) {
            return [pscustomobject] @{
                HasGlobalAdmin = $true
                RoleVia = 'through a role-assignable group'
            }
        }
    }

    if ($PrincipalType -eq 'Group' -and
        @($EnabledMemberIds | Where-Object {
                $_ -in $GlobalAdminPrincipalIds
            }).Count -gt 0) {
        return [pscustomobject] @{
            HasGlobalAdmin = $true
            RoleVia = 'held by an enabled group member'
        }
    }

    return [pscustomobject] @{
        HasGlobalAdmin = $false
        RoleVia = 'none'
    }
}
