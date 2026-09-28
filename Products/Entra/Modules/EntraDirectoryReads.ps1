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

function Assert-EntraWriteIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $BaseUri,
        [AllowNull()] [string] $TenantAdminUpn,
        [AllowNull()] [string] $TenantId
    )

    $intendedTenant = [guid]::Empty
    if ([string]::IsNullOrWhiteSpace($TenantAdminUpn) -or
        -not [guid]::TryParse($TenantId, [ref] $intendedTenant) -or $intendedTenant -eq [guid]::Empty) {
        throw 'Conditional Access writes require Context.TenantAdminUpn and the intended Context.TenantId GUID.'
    }
    $actual = Get-MgContext -ErrorAction Stop
    $actualTenant = [guid]::Empty
    if ($null -eq $actual -or $actual.Account -isnot [string] -or
        [string]::IsNullOrWhiteSpace($actual.Account) -or $actual.TenantId -isnot [string] -or
        $actual.Account -ine $TenantAdminUpn -or
        -not [guid]::TryParse([string] $actual.TenantId, [ref] $actualTenant) -or
        $actualTenant -ne $intendedTenant) {
        throw 'Microsoft Graph context does not match the intended operator account and tenant. Reconnect to the approved tenant before applying Conditional Access.'
    }
    $organizations = Get-EntraGraphCollection -BaseUri $BaseUri `
        -Uri "$BaseUri/organization?`$select=id" -Description 'Verify Conditional Access write tenant'
    $organizationTenant = [guid]::Empty
    if ($organizations.Count -ne 1 -or $organizations[0].id -isnot [string] -or
        -not [guid]::TryParse([string] $organizations[0].id, [ref] $organizationTenant) -or
        $organizationTenant -ne $intendedTenant) {
        throw 'Microsoft Graph organization identity does not match the intended Conditional Access tenant.'
    }
}

function Get-EntraVerifiedEmergencyAccess {
    <#
        Read-only verification shared by setup and each CA write boundary.
        Caller markers and diagnostic files are not proof of directory state.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $BaseUri,
        [AllowEmptyCollection()] [string[]] $UserIds = @(),
        [AllowEmptyCollection()] [string[]] $GroupIds = @(),
        [Parameter(Mandatory)] [string] $Module,
        [Parameter(Mandatory)] [string] $BestPracticeKey
    )

    $users = [string[]] @($UserIds)
    $groups = [string[]] @($GroupIds)
    $gaPrincipalIds = $null
    foreach ($type in 'User', 'Group') {
        $ids = if ($type -eq 'User') { $users } else { $groups }
        foreach ($id in $ids) {
            try {
                if ([string]::IsNullOrWhiteSpace($id)) { throw 'Emergency-access principal ID must not be blank.' }
                $encodedId = [uri]::EscapeDataString($id)
                $enabledMemberIds = @()
                if ($type -eq 'User') {
                    $principal = Invoke-WithTransientRetry -Description 'Verify break-glass user' -Action {
                        Invoke-MgGraphRequest -Method GET -Uri "$BaseUri/users/$encodedId`?`$select=id,accountEnabled,userPrincipalName"
                    }
                    if ($principal.id -isnot [string] -or $principal.id -ine $id) { throw 'Directory user response does not match the requested emergency-access ID.' }
                    if ($principal.accountEnabled -isnot [bool] -or -not $principal.accountEnabled) {
                        throw "Break-glass account $id is disabled or its enabled state could not be verified."
                    }
                }
                else {
                    $principal = Invoke-WithTransientRetry -Description 'Verify break-glass group' -Action {
                        Invoke-MgGraphRequest -Method GET -Uri "$BaseUri/groups/$encodedId`?`$select=id,displayName"
                    }
                    if ($principal.id -isnot [string] -or $principal.id -ine $id) { throw 'Directory group response does not match the requested emergency-access ID.' }
                    $members = Get-EntraGraphCollection -BaseUri $BaseUri `
                        -Uri "$BaseUri/groups/$encodedId/transitiveMembers/microsoft.graph.user?`$select=id,accountEnabled,userPrincipalName" `
                        -Description 'Read break-glass group members'
                    $enabledMemberIds = @($members | Where-Object {
                            $_.accountEnabled -is [bool] -and $_.accountEnabled -and
                            -not [string]::IsNullOrWhiteSpace([string] $_.id)
                        } | ForEach-Object { [string] $_.id })
                    if ($enabledMemberIds.Count -eq 0) { throw "Break-glass group $id contains no enabled user account." }
                }
                if ($null -eq $gaPrincipalIds) { $gaPrincipalIds = Get-EntraGlobalAdminPrincipalId -BaseUri $BaseUri }
                $role = Get-EntraGlobalAdminRecoveryState -BaseUri $BaseUri `
                    -PrincipalId $id -PrincipalType $type -GlobalAdminPrincipalIds @($gaPrincipalIds) `
                    -EnabledMemberIds $enabledMemberIds
                if (-not $role.HasGlobalAdmin) {
                    throw "Break-glass $type $id does not provide a permanently-assigned, tenant-wide Global Administrator role with no expiry."
                }
                $null = Add-EntraRunLogEntry -Module $Module -Action 'VerifyBreakGlass' -BestPracticeKey $BestPracticeKey `
                    -Status 'Succeeded' -Disposition 'AlreadyCompliant' -Readback 'Verified' -Target $id `
                    -Detail "Emergency-access $type is usable and provides permanent, tenant-wide Global Administrator recovery ($($role.RoleVia))."
            }
            catch {
                $null = Add-EntraRunLogEntry -Module $Module -Action 'VerifyBreakGlass' -BestPracticeKey $BestPracticeKey `
                    -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $id `
                    -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
                    -Detail "Emergency-access $type could not be verified. Resolve directory access, enabled membership and permanent Global Administrator assignment before rerunning: $($_.Exception.Message)"
                throw
            }
        }
    }
    return [pscustomobject] @{ userIds = [string[]] @($users); groupIds = [string[]] @($groups) }
}
