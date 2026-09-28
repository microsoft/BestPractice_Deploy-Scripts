#requires -Version 7.0
<#
.SYNOPSIS
    Offline actual-module tests for the public Conditional Access write boundary.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$entra = Join-Path $root 'Products\Entra'
$script:passed = 0
$tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
$user = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
$group = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
function Assert-True($Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION: $Message" }
}
function Throw-Http([int] $Code) {
    $errorObject = [Exception]::new("Synthetic HTTP $Code")
    $errorObject | Add-Member Response ([pscustomobject] @{ StatusCode = $Code })
    throw $errorObject
}
function Copy-Value($Value) { return $Value | ConvertTo-Json -Depth 40 | ConvertFrom-Json -AsHashtable }
function Get-MgContext {
    [CmdletBinding()]
    param()
    $s = $global:StandaloneCaTest
    $s.ContextReads++
    if ($s.Mode -eq 'MissingContext') { return $null }
    if ($s.Mode -eq 'MalformedContext') {
        return [pscustomobject] @{ Account = [string[]] @('admin@example.invalid'); TenantId = $s.Tenant }
    }
    if ($s.Mode -eq 'ArrayTenant') {
        return [pscustomobject] @{ Account = 'admin@example.invalid'; TenantId = [string[]] @($s.Tenant) }
    }
    return [pscustomobject] @{
        Account = $(switch ($s.Mode) { 'WrongAccount' {'other@example.invalid'} 'MissingAccount' {''} default {'ADMIN@EXAMPLE.INVALID'} })
        TenantId = $(switch ($s.Mode) { 'WrongTenant' {'dddddddd-dddd-4ddd-8ddd-dddddddddddd'} 'MissingTenant' {''} 'MalformedTenant' {'bad-id'} default {$s.Tenant.ToUpperInvariant()} })
    }
}
function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string] $Method, [string] $Uri, $Body, [string] $ContentType)
    $s = $global:StandaloneCaTest
    $s.Requests.Add(@{ Method = $Method; Uri = $Uri })
    $path = ([uri] $Uri).AbsolutePath
    if ($Method -eq 'GET') {
        if ($path -eq '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy') { return @{ isEnabled = ($s.Mode -eq 'SecurityDefaults') } }
        if ($path -eq '/v1.0/organization') {
            $s.IdentityReads++
            if ($s.Mode -eq 'OrganizationDenied') { Throw-Http 403 }
            if ($s.Mode -eq 'MissingOrganization') { return @{ value = @() } }
            if ($s.Mode -eq 'MultipleOrganizations') { return @{ value = @(@{id=$s.Tenant}, @{id=$s.Tenant}) } }
            if ($s.Mode -eq 'MalformedOrganization') { return @{ value = @(@{ id = [string[]] @($s.Tenant) }) } }
            return @{ value = @(@{ id = $(if ($s.Mode -eq 'WrongOrganization') {'dddddddd-dddd-4ddd-8ddd-dddddddddddd'} else {$s.Tenant}) }) }
        }
        if ($path -eq "/v1.0/users/$($s.User)") {
            $s.PrincipalReads++
            if ($s.Mode -in 'InvalidUser','FabricatedMarker') { Throw-Http 404 }
            if ($s.Mode -eq 'Denied') { Throw-Http 403 }
            $response = @{ id = $(if ($s.Mode -eq 'WrongUserResponse') {$s.Group} else {$s.User}); accountEnabled = ($s.Mode -ne 'Disabled') }
            if ($s.Mode -eq 'StringEnabled') { $response.accountEnabled = 'true' }
            if ($s.Mode -eq 'ObjectResponse') { return [pscustomobject] $response }
            return $response
        }
        if ($path -eq "/v1.0/groups/$($s.Group)") {
            $s.PrincipalReads++
            if ($s.Mode -eq 'InvalidGroup') { Throw-Http 404 }
            if ($s.Mode -eq 'GroupDenied') { Throw-Http 403 }
            $response = @{ id = $(if ($s.Mode -eq 'WrongGroupResponse') {$s.User} else {$s.Group}); displayName = 'Synthetic recovery group' }
            if ($s.Mode -eq 'GroupObjectResponse') { return [pscustomobject] $response }
            return $response
        }
        if ($path -eq "/v1.0/groups/$($s.Group)/transitiveMembers/microsoft.graph.user") {
            $s.MembershipReads++
            if ($s.Mode -eq 'MemberDenied') { Throw-Http 403 }
            return @{ value = @(@{ id = $s.User; accountEnabled = ($s.Mode -ne 'DisabledGroupMembers') }) }
        }
        if ($path -eq "/v1.0/users/$($s.User)/transitiveMemberOf/microsoft.graph.group") {
            $s.MembershipReads++
            return @{ value = @(@{ id = $s.Group }) }
        }
        if ($path -eq '/v1.0/roleManagement/directory/roleAssignmentScheduleInstances') {
            $s.RoleReads++
            if ($s.Mode -eq 'RoleDenied') { Throw-Http 403 }
            if ($s.Mode -in 'NoRole','GroupNoRole' -or ($s.Mode -eq 'RevokeBetweenWrites' -and $s.Writes -gt 0)) { return @{ value = @() } }
            if ($s.Mode -eq 'MutateCaller') {
                $s.Caller.BreakGlassUserIds[0] = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
            }
            return @{ value = @(@{
                principalId = $(if ($s.Mode -in 'UserViaGroup','GroupAssignedRole') {$s.Group} else {$s.User})
                assignmentType = $(if ($s.Mode -eq 'TemporaryRole') {'Activated'} else {'Assigned'})
                endDateTime = $(if ($s.Mode -eq 'ExpiringRole') {'2099-01-01T00:00:00Z'} else {$null})
                directoryScopeId = $(if ($s.Mode -eq 'ScopedRole') {'/administrativeUnits/synthetic'} else {'/'})
            }) }
        }
        if ($path -eq '/v1.0/identity/conditionalAccess/policies') { return @{ value = @($s.Existing) } }
        if ($path -like '/v1.0/identity/conditionalAccess/policies/*') { return Copy-Value $s.Stored[$path.Split('/')[-1]] }
    }
    if ($Method -in 'POST','PATCH' -and $path -like '/v1.0/identity/conditionalAccess/policies*') {
        Assert-True ($s.ContextReads -gt $s.Writes -and $s.IdentityReads -gt $s.Writes -and
            $s.PrincipalReads -gt $s.Writes -and $s.RoleReads -gt $s.Writes) 'Each write must have fresh context, organization, principal and role reads'
        $s.Writes++
        $payload = $Body | ConvertFrom-Json -AsHashtable
        if ($Method -eq 'PATCH') {
            Assert-True (-not $payload.ContainsKey('state')) 'Adoption must preserve existing enforcement state'
            $record = Copy-Value @($s.Existing | Where-Object id -eq $path.Split('/')[-1])[0]
            foreach ($key in $payload.Keys) { $record[$key] = $payload[$key] }
            Assert-True ('customer-exclusion' -in $record.conditions.users.excludeUsers) 'Customer exclusions were removed'
            Assert-True ($record.state -eq 'enabled') 'Existing policy enforcement state was lost'
        }
        else {
            $record = $payload
            $record.id = [guid]::NewGuid().ToString()
        }
        Assert-True ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' -notin $record.conditions.users.excludeUsers) 'Caller mutation reached serialized write'
        $s.Stored[$record.id] = $record
        return Copy-Value $record
    }
    throw "Unexpected synthetic SDK dispatch: $Method $Uri"
}

function Invoke-Case([string] $Mode, [bool] $Adopt) {
    $config = Import-PowerShellDataFile (Join-Path $entra 'Config\EntraConfig.psd1')
    $config.ConditionalAccess.Policies = @($config.ConditionalAccess.Policies |
        Where-Object Key -in 'block-legacy-authentication','require-mfa-all-users' |
        Select-Object -First $(if ($Mode -in 'TwoWrites','RevokeBetweenWrites') {2} else {1}))
    if ($Mode -eq 'EnabledCreate') { $config.ConditionalAccess.DefaultState = 'enabled' }
    if ($Mode -eq 'EmptyOptional') { $config.ConditionalAccess.RequireBreakGlassExclusion = $false }
    $groupMode = $Mode -in 'ValidGroup','GroupAssignedRole','InvalidGroup','GroupDenied','MemberDenied','WrongGroupResponse','GroupObjectResponse','DisabledGroupMembers','GroupNoRole'
    $context = @{
        TenantAdminUpn = 'admin@example.invalid'; TenantId = $tenant
        AssignmentScope = 'PilotGroup'; PilotGroupId = 'ffffffff-ffff-4fff-8fff-ffffffffffff'
        BreakGlassUserIds = [string[]] @(if (-not $groupMode -and $Mode -notin 'Empty','EmptyOptional') { $user })
        BreakGlassGroupIds = [string[]] @(if ($groupMode) { $group })
        verified = $true; RunId = 'fabricated-marker'
        BlockedItemKeys = $(if ($Mode -eq 'Blocked') {@('conditional-access-baseline')} else {@()})
        WriteBlockedItemKeys = $(if ($Mode -eq 'WriteBlocked') {@('conditional-access-baseline')} else {@()})
    }
    if ($Mode -eq 'MissingIntendedTenant') { $context.Remove('TenantId') }
    if ($Mode -eq 'WrongIntendedTenant') { $context.TenantId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' }
    if ($Mode -eq 'WhatIf') { $context.Remove('TenantId') }
    $existing = @()
    if ($Adopt) {
        foreach ($reference in $config.ConditionalAccess.Policies) {
            $template = Join-Path $entra (Join-Path $config.ConditionalAccess.PolicyTemplateDirectory $reference.File)
            $record = Get-Content $template -Raw | ConvertFrom-Json -AsHashtable
            $record.id = [guid]::NewGuid().ToString()
            $record.state = 'enabled'
            $record.conditions.users.excludeUsers = @('customer-exclusion')
            $existing += $record
        }
    }
    $global:StandaloneCaTest = @{
        Mode=$Mode; Tenant=$tenant; User=$user; Group=$group; Caller=$context
        Existing=$existing; Stored=@{}; Writes=0; ContextReads=0; IdentityReads=0; PrincipalReads=0; RoleReads=0; MembershipReads=0
        Requests=[Collections.Generic.List[object]]::new()
    }
    $global:EntraRunLog = [Collections.Generic.List[hashtable]]::new()
    $global:EntraRunLogPath = $null
    $failure = $null
    try {
        & (Join-Path $entra 'Modules\Setup-ConditionalAccessBaseline.ps1') -Config $config -Context $context `
            -AdoptExisting:$Adopt -WhatIf:($Mode -eq 'WhatIf') | Out-Null
    }
    catch { $failure = $_ }
    $s = $global:StandaloneCaTest
    $safeSkip = $Mode -in 'WhatIf','Blocked','WriteBlocked','SecurityDefaults','Empty'
    $success = $Mode -in 'ValidUser','ValidGroup','GroupAssignedRole','UserViaGroup','ObjectResponse','GroupObjectResponse','EnabledCreate','MutateCaller','TwoWrites'
    if ($success) {
        if ($failure) { throw $failure }
        Assert-True ($s.Writes -eq $(if ($Mode -eq 'TwoWrites') {2} else {1})) 'Valid standalone write count changed'
        if ($groupMode -or $Mode -eq 'UserViaGroup') { Assert-True ($s.MembershipReads -ge $s.Writes) 'Group recovery was not freshly verified' }
        foreach ($record in $s.Stored.Values) {
            $field = if ($groupMode) {'excludeGroups'} else {'excludeUsers'}
            $expected = if ($groupMode) {$group} else {$user}
            Assert-True ($expected -in $record.conditions.users[$field]) 'Verified recovery ID was not excluded'
            if (-not $Adopt) { Assert-True ($record.state -eq $config.ConditionalAccess.DefaultState) 'Configured creation state changed' }
        }
    }
    elseif ($safeSkip) {
        if ($failure) { throw $failure }
        Assert-True ($s.Writes -eq 0 -and $s.ContextReads -eq 0 -and $s.RoleReads -eq 0) 'Assessment/WhatIf gates triggered write verification or writes'
    }
    else {
        Assert-True ($null -ne $failure) "$Mode did not fail closed"
        Assert-True ($s.Writes -eq $(if ($Mode -eq 'RevokeBetweenWrites') {1} else {0})) "$Mode allowed an unverified write"
        Assert-True (@($global:EntraRunLog | Where-Object { $_.Action -eq 'VerifyWriteBoundary' -and $_.Status -eq 'Failed' }).Count -eq 1) 'Missing write-boundary failure evidence'
    }
    $writeRequests = @($s.Requests | Where-Object Method -in 'POST','PATCH')
    Assert-True ($writeRequests.Count -eq $s.Writes) 'An unverified write reached the SDK boundary'
    foreach ($request in $writeRequests) {
        Assert-True ($request.Method -eq $(if ($Adopt) {'PATCH'} else {'POST'})) 'Scenario did not exercise the intended write path'
    }
    $script:passed++
    Write-Host "PASS standalone $Mode Adopt=$Adopt"
}

try {
    foreach ($adopt in $false,$true) {
        foreach ($mode in 'ValidUser','ValidGroup','GroupAssignedRole','UserViaGroup','ObjectResponse','GroupObjectResponse',
            'EnabledCreate','MutateCaller','TwoWrites','RevokeBetweenWrites',
            'InvalidUser','InvalidGroup','Disabled','DisabledGroupMembers','NoRole','GroupNoRole','Denied','GroupDenied','MemberDenied','RoleDenied',
            'WrongUserResponse','WrongGroupResponse','StringEnabled','TemporaryRole','ExpiringRole','ScopedRole','FabricatedMarker',
            'WrongAccount','MissingAccount','MissingContext','MalformedContext','ArrayTenant','WrongTenant','MissingTenant','MalformedTenant',
            'MissingIntendedTenant','WrongIntendedTenant','WrongOrganization','MissingOrganization','MultipleOrganizations','MalformedOrganization','OrganizationDenied',
            'WhatIf','Blocked','WriteBlocked','SecurityDefaults','Empty','EmptyOptional') {
            Invoke-Case -Mode $mode -Adopt $adopt
        }
    }
    Write-Host "$script:passed standalone CA scenarios passed. Synthetic SDK only; no tenant validation."
}
finally {
    Remove-Variable StandaloneCaTest -Scope Global -ErrorAction SilentlyContinue
    foreach ($name in 'EntraRunLog','EntraRunLogPath') { Remove-Variable $name -Scope Global -ErrorAction SilentlyContinue }
}
