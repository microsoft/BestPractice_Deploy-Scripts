#requires -Version 7.0
<#
.SYNOPSIS
    Emergency access (break-glass) account handling for Conditional Access
    (Identity Protection guide, Priority 1).

.DESCRIPTION
    Resolves the emergency-access principals that every Conditional Access policy
    must exclude. It verifies the accounts/groups configured in
    ConditionalAccess.BreakGlass, and, when none are configured and
    CreateAccountIfMissing is set, creates a dedicated cloud-only break-glass
    account. The resolved principal IDs are written to the run's break-glass
    output file so the Conditional Access baseline can exclude them.

    A generated account password is never written to evidence; the operator must
    reset it in the portal and store it securely (see the end-user guide). All
    writes are gated by ShouldProcess and wrapped in the shared retry boundary.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context
)

$ErrorActionPreference = 'Stop'
$ConfirmPreference = 'None'

. (Join-Path $PSScriptRoot 'EntraRunLog.ps1')
. (Join-Path $PSScriptRoot 'EntraGraphClient.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'EntraPolicyComparison.ps1')
. (Join-Path $PSScriptRoot 'EntraDirectoryReads.ps1')
. (Join-Path $PSScriptRoot 'EntraSecurityDefaults.ps1')

$module = 'Setup-EmergencyAccess'
$bestPracticeKey = 'emergency-access-account'

if (-not $Context -or [string]::IsNullOrWhiteSpace([string] $Context.TenantAdminUpn)) {
    throw 'Setup-EmergencyAccess.ps1 requires Context.TenantAdminUpn and Graph connection settings.'
}

$v1 = $Config.Api.GraphBaseUri
$bg = $Config.ConditionalAccess.BreakGlass
$userIds = [System.Collections.Generic.List[string]]::new()
$groupIds = [System.Collections.Generic.List[string]]::new()
foreach ($u in @($Context.BreakGlassUserIds)) { if ($u) { $userIds.Add([string] $u) } }
foreach ($g in @($Context.BreakGlassGroupIds)) { if ($g) { $groupIds.Add([string] $g) } }

# Microsoft's emergency-access guidance requires the break-glass account to hold
# Global Administrator *permanently* assigned (not PIM-eligible) so a PIM outage
# cannot lock the tenant out. The role id and the assignment read live in
# EntraDirectoryReads.ps1 so the deployment health check evaluates recoverability
# exactly the same way this module does.
$globalAdminRoleId = Get-EntraGlobalAdminRoleId
$gaPrincipalIds = $null

# Verify configured principals exist, are usable, and can actually recover the
# tenant, so a typo or a disabled/under-privileged account cannot silently
# undermine the exclusion the CA baseline depends on.
foreach ($u in @($userIds)) {
    try {
        $account = Invoke-WithTransientRetry -Description 'Verify break-glass user' -Action {
            Invoke-MgGraphRequest -Method GET -Uri "$v1/users/$u`?`$select=id,accountEnabled,userPrincipalName"
        }
    }
    catch {
        Add-EntraRunLogEntry -Module $module -Action 'VerifyBreakGlass' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $u `
            -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
            -Detail "Configured break-glass user could not be verified: $($_.Exception.Message)"
        throw
    }

    if (-not [bool] $account.accountEnabled) {
        Add-EntraRunLogEntry -Module $module -Action 'VerifyBreakGlass' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $u `
            -Detail "Break-glass account '$($account.userPrincipalName)' is disabled; a disabled account cannot be used in an emergency. Enable it before deploying the baseline."
        throw "Break-glass account $u is disabled."
    }

    # Confirm the account can recover the tenant: it must hold a permanently
    # assigned Global Administrator role, directly or through a role-assignable
    # group. Any other role (or none) is not a valid break-glass account, and if
    # the role cannot be read the run stops rather than assume it is safe.
    try {
        if ($null -eq $gaPrincipalIds) { $gaPrincipalIds = Get-EntraGlobalAdminPrincipalId -BaseUri $v1 -RoleId $globalAdminRoleId }
        $roleState = Get-EntraGlobalAdminRecoveryState -BaseUri $v1 `
            -PrincipalId ([string] $u) -PrincipalType User `
            -GlobalAdminPrincipalIds @($gaPrincipalIds)
    }
    catch {
        Add-EntraRunLogEntry -Module $module -Action 'VerifyBreakGlass' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $u `
            -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
            -Detail "Could not confirm the break-glass account's Global Administrator role; stopping so it can be reviewed: $($_.Exception.Message)"
        throw
    }

    if ($roleState.HasGlobalAdmin) {
        Add-EntraRunLogEntry -Module $module -Action 'VerifyBreakGlass' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'AlreadyCompliant' -Readback 'Verified' -Target $u `
            -Detail "Break-glass account '$($account.userPrincipalName)' is enabled and holds a permanently assigned, tenant-wide Global Administrator role with no expiry ($($roleState.RoleVia))."
    }
    else {
        Add-EntraRunLogEntry -Module $module -Action 'VerifyBreakGlass' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $u `
            -Detail "Break-glass account '$($account.userPrincipalName)' is enabled but does not hold a permanently-assigned Global Administrator role. Microsoft's emergency-access guidance requires Global Administrator assigned permanently (not PIM-eligible). Assign it before deploying the baseline."
        throw "Break-glass account $u does not hold a permanently-assigned Global Administrator role."
    }
}
foreach ($g in @($groupIds)) {
    try {
        $group = Invoke-WithTransientRetry -Description 'Verify break-glass group' -Action {
            Invoke-MgGraphRequest -Method GET -Uri "$v1/groups/$g`?`$select=id,displayName"
        }
        $members = Get-EntraGraphCollection -BaseUri $v1 `
            -Uri "$v1/groups/$g/transitiveMembers/microsoft.graph.user?`$select=id,accountEnabled,userPrincipalName" `
            -Description 'Read break-glass group members'
        if ($null -eq $gaPrincipalIds) { $gaPrincipalIds = Get-EntraGlobalAdminPrincipalId -BaseUri $v1 -RoleId $globalAdminRoleId }
    }
    catch {
        Add-EntraRunLogEntry -Module $module -Action 'VerifyBreakGlass' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $g `
            -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
            -Detail "Configured break-glass group could not be verified; stopping so it can be reviewed: $($_.Exception.Message)"
        throw
    }

    # A break-glass group is only usable if it actually contains an enabled
    # emergency account (direct or nested, via transitive membership), and either
    # the group or one of those members holds a permanently-assigned Global
    # Administrator role.
    $enabledMembers = @(@($members) | Where-Object {
            [bool] (Get-EntraPolicyProperty -InputObject $_ -Name 'accountEnabled')
        })
    if ($enabledMembers.Count -eq 0) {
        Add-EntraRunLogEntry -Module $module -Action 'VerifyBreakGlass' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $g `
            -Detail "Break-glass group '$($group.displayName)' contains no enabled user account, so it cannot serve as an emergency-access exclusion. Add an enabled emergency account that holds Global Administrator."
        throw "Break-glass group $g contains no enabled user account."
    }

    $enabledMemberIds = @($enabledMembers | ForEach-Object {
            [string] (Get-EntraPolicyProperty -InputObject $_ -Name 'id')
        } | Where-Object { $_ })
    $roleState = Get-EntraGlobalAdminRecoveryState -BaseUri $v1 `
        -PrincipalId ([string] $g) -PrincipalType Group `
        -GlobalAdminPrincipalIds @($gaPrincipalIds) `
        -EnabledMemberIds $enabledMemberIds

    if ($roleState.HasGlobalAdmin) {
        Add-EntraRunLogEntry -Module $module -Action 'VerifyBreakGlass' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'AlreadyCompliant' -Readback 'Verified' -Target $g `
            -Detail "Break-glass group '$($group.displayName)' has $($enabledMembers.Count) enabled member(s) and provides a permanently assigned, tenant-wide Global Administrator role with no expiry ($($roleState.RoleVia))."
    }
    else {
        Add-EntraRunLogEntry -Module $module -Action 'VerifyBreakGlass' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $g `
            -Detail "Break-glass group '$($group.displayName)' has enabled members but neither the group nor any member holds a permanently assigned, tenant-wide Global Administrator role with no expiry. Assign Global Administrator permanently, not through PIM eligibility or temporary activation, before deploying."
        throw "Break-glass group $g provides no permanently-assigned Global Administrator."
    }
}

if ($userIds.Count -eq 0 -and $groupIds.Count -eq 0) {
    if ($bg.CreateAccountIfMissing -and
        (Test-EntraSecurityDefaultsWriteAllowed -BaseUri $v1 -Module $module -BestPracticeKey $bestPracticeKey)) {
        $identity = $Context.ConnectionInfo.TenantIdentity
        $domain = if ($identity -and $identity.ExpectedDomain) { $identity.ExpectedDomain }
                  elseif ($Context.TenantAdminUpn -match '@(?<d>[^@]+)$') { $Matches.d } else { $null }
        if (-not $domain) { throw 'Unable to derive a tenant domain for the break-glass account UPN.' }
        $upn = "$($bg.AccountUpnPrefix)@$domain"

        if ($PSCmdlet.ShouldProcess($upn, 'Create cloud-only break-glass account')) {
            # A random, strong password that is never emitted to evidence; the
            # operator resets and stores it out of band (see end-user guide).
            $password = ([guid]::NewGuid().ToString('N') + 'Aa1!')
            $body = @{
                accountEnabled = $true
                displayName = $bg.AccountDisplayName
                mailNickname = $bg.AccountUpnPrefix
                userPrincipalName = $upn
                passwordProfile = @{ forceChangePasswordNextSignIn = $false; password = $password }
            } | ConvertTo-Json -Depth 5
            $created = Invoke-WithTransientRetry -Description 'Create break-glass account' -Action {
                Invoke-MgGraphRequest -Method POST -Uri "$v1/users" -Body $body -ContentType 'application/json'
            }
            $password = $null
            $userIds.Add([string] $created.id)
            Add-EntraRunLogEntry -Module $module -Action 'CreateBreakGlass' -BestPracticeKey $bestPracticeKey `
                -Status 'Created' -Disposition 'Applicable' -Target $upn `
                -Detail 'Created a cloud-only break-glass account. It has no admin role yet: assign it Global Administrator, reset its password in the portal, and store the credentials securely. The next run confirms the role; the account is excluded from every Conditional Access policy automatically.'
        }
        else {
            Add-EntraRunLogEntry -Module $module -Action 'CreateBreakGlass' -BestPracticeKey $bestPracticeKey `
                -Status 'Info' -Disposition 'WillChange' -Target $upn -Readback 'NotAttempted' `
                -Detail "WhatIf: would create a cloud-only break-glass account '$upn' and exclude it from every Conditional Access policy."
        }
    }
    elseif (-not $bg.CreateAccountIfMissing) {
        Add-EntraRunLogEntry -Module $module -Action 'BreakGlass' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'GuidedOnly' `
            -Detail 'No emergency-access account is configured. Create one (Identity guide Priority 1), set ConditionalAccess.BreakGlass.ExcludeUserIds/ExcludeGroupIds, or set CreateAccountIfMissing. The Conditional Access baseline will not write until a break-glass exclusion exists.'
    }
}

# Local evidence output, not a tenant change; never suppressed under -WhatIf.
@{ userIds = @($userIds); groupIds = @($groupIds) } | ConvertTo-Json |
    Set-Content -LiteralPath $Context.BreakGlassOutputPath -Encoding utf8 -WhatIf:$false
