#requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$entra = Join-Path $root 'Products\Entra'
$script:assertions = 0

function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
    $script:assertions++
}

function Copy-TestValue {
    param($Value)
    return $Value | ConvertTo-Json -Depth 40 | ConvertFrom-Json -AsHashtable
}

# Synthetic responses only. Any unexpected request fails instead of reaching Graph.
function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string] $Method, [string] $Uri, $Body, [string] $ContentType)
    $mock = $global:IdentityReviewMock
    if ($Method -eq 'GET' -and $Uri -match '/policies/identitySecurityDefaultsEnforcementPolicy$') {
        return @{ isEnabled = $mock.SecurityDefaults }
    }
    if ($Method -eq 'GET' -and $Uri -match '/identity/conditionalAccess/policies$') {
        return @{ value = @($mock.Existing) }
    }
    if ($Method -eq 'POST' -and $Uri -match '/identity/conditionalAccess/policies$') {
        $mock.Writes++
        $mock.Created = $Body | ConvertFrom-Json -AsHashtable
        $mock.Created.id = '22222222-2222-2222-2222-222222222222'
        return Copy-TestValue $mock.Created
    }
    if ($Method -eq 'GET' -and $Uri -match '/identity/conditionalAccess/policies/22222222-2222-2222-2222-222222222222$') {
        $response = Copy-TestValue $mock.Created
        if ($mock.Mutate) { & $mock.Mutate $response }
        if ($mock.AsObject) { return $response | ConvertTo-Json -Depth 40 | ConvertFrom-Json }
        return $response
    }
    if ($Method -ne 'GET') { $mock.Writes++ }
    throw "Unexpected mocked request: $Method $Uri"
}

function Invoke-BaselineScenario {
    param(
        [string] $Key,
        [object[]] $Existing = @(),
        [scriptblock] $Mutate,
        [switch] $Preview,
        [switch] $Adopt,
        [switch] $Withhold,
        [switch] $SecurityDefaults,
        [switch] $AsObject,
        [switch] $ExpectFailure
    )
    $config = Import-PowerShellDataFile (Join-Path $entra 'Config\EntraConfig.psd1')
    $config.ConditionalAccess.Policies = @($config.ConditionalAccess.Policies | Where-Object Key -eq $Key)
    Assert-True ($config.ConditionalAccess.Policies.Count -eq 1) "Missing policy reference: $Key"
    $config.ConditionalAccess.Policies[0].Enabled = $true
    $global:IdentityReviewMock = @{
        Existing = $Existing; Created = $null; Writes = 0; Mutate = $Mutate
        SecurityDefaults = [bool] $SecurityDefaults; AsObject = [bool] $AsObject
    }
    $global:EntraRunLog = [System.Collections.Generic.List[hashtable]]::new()
    $global:EntraRunLogPath = $null
    $context = @{
        TenantAdminUpn = 'admin@example.invalid'
        AssignmentScope = 'PilotGroup'
        PilotGroupId = '33333333-3333-3333-3333-333333333333'
        BreakGlassUserIds = @('11111111-1111-1111-1111-111111111111')
        BreakGlassGroupIds = @()
        BlockedItemKeys = @()
        WriteBlockedItemKeys = $(if ($Withhold) { @('conditional-access-baseline') } else { @() })
    }
    $failure = $null
    try {
        & (Join-Path $entra 'Modules\Setup-ConditionalAccessBaseline.ps1') `
            -Config $config -Context $context -WhatIf:$Preview -AdoptExisting:$Adopt | Out-Null
    }
    catch { $failure = $_ }
    if ($ExpectFailure) {
        Assert-True ($null -ne $failure) "$Key accepted corrupt readback"
        Assert-True (@($global:EntraRunLog | Where-Object {
                    $_.Action -eq 'Readback' -and $_.Status -eq 'Failed' -and $_.Readback -eq 'Mismatch'
                }).Count -eq 1) "$Key did not record failed readback"
    }
    elseif ($failure) { throw $failure }
    return @{
        Created = $global:IdentityReviewMock.Created
        Writes = $global:IdentityReviewMock.Writes
        Log = @($global:EntraRunLog)
    }
}

try {
    . (Join-Path $root 'Products\Defender\Modules\DefenderRunLog.ps1')
    $verdict = Get-DefenderModuleVerdict -Entries @(
        @{ Status = 'Skipped'; Disposition = 'Blocked' },
        @{ Status = 'Failed'; Disposition = 'Applicable' })
    Assert-True ($verdict -eq 'FAILED') 'A blocked entry masked an operation failure'
    Assert-True ((Get-DefenderModuleVerdict -Entries @(
                @{ Status = 'Info'; Disposition = 'Blocked'; Readback = 'Failed' })) -eq 'FAILED') 'A blocked entry masked a readback failure'
    Assert-True ((Get-DefenderModuleVerdict -Entries @(
                @{ Status = 'Skipped'; Disposition = 'Blocked' })) -eq 'BLOCKED') 'Blocked-only verdict changed'
    $defenderConfig = Import-PowerShellDataFile (Join-Path $root 'Products\Defender\Config\DefenderConfig.psd1')
    $identity = @($defenderConfig.PermissionModel.Operations | Where-Object Key -eq 'tenant-identity')[0]
    Assert-True (($identity.GraphDelegatedScopes -join ',') -eq 'User.Read') 'Delegated identity consent was broadened unnecessarily'
    Assert-True ($identity.GraphApplicationPermissions -contains 'Organization.Read.All') 'Application permission contract changed'

    $config = Import-PowerShellDataFile (Join-Path $entra 'Config\EntraConfig.psd1')
    foreach ($reference in $config.ConditionalAccess.Policies) {
        $result = Invoke-BaselineScenario -Key $reference.Key -AsObject
        Assert-True ($result.Writes -eq 1) "$($reference.Key) did not create exactly one policy"
        Assert-True ($result.Created.state -eq 'enabledForReportingButNotEnforced') 'Creation enabled enforcement'
        Assert-True (@($result.Log | Where-Object {
                    $_.Action -eq 'Readback' -and $_.Readback -eq 'Verified'
                }).Count -eq 1) "$($reference.Key) did not verify the roundtrip"
        if ($reference.Key -in @('require-mfa-admins', 'require-mfa-admin-portals')) {
            Assert-True (@($result.Created.conditions.users.includeRoles).Count -gt 0) 'Admin role targeting was lost'
            Assert-True (-not $result.Created.conditions.users.ContainsKey('includeGroups')) 'Pilot members were added to role-scoped policy'
        }
        if ($reference.Key -eq 'require-mfa-azure-management') {
            Assert-True (($result.Created.conditions.users.includeUsers -join ',') -eq 'All') 'Azure management policy lost all-user targeting'
            Assert-True (-not $result.Created.conditions.users.ContainsKey('includeGroups')) 'Azure management still targets pilot only'
        }
        if ($reference.Key -eq 'require-compliant-device-or-mfa') {
            Assert-True ($result.Created.grantControls.operator -eq 'OR' -and
                'mfa' -in $result.Created.grantControls.builtInControls -and
                'compliantDevice' -in $result.Created.grantControls.builtInControls -and
                'domainJoinedDevice' -in $result.Created.grantControls.builtInControls) 'Device-or-MFA fallback is missing'
        }
        $preview = Invoke-BaselineScenario -Key $reference.Key -Preview
        Assert-True ($preview.Writes -eq 0) "$($reference.Key) wrote during WhatIf"
    }

    foreach ($mutation in @(
            { param($p) $p.Remove('sessionControls') | Out-Null },
            { param($p) $p.sessionControls.persistentBrowser.mode = 'always' },
            { param($p) $p.sessionControls.signInFrequency.value = 24 },
            { param($p) $p.sessionControls.signInFrequency.isEnabled = $false },
            { param($p) $p.sessionControls.signInFrequency.isEnabled = 'true' },
            { param($p) $p.conditions.devices.deviceFilter.rule = 'device.isCompliant -eq True' },
            { param($p) $p.state = 'enabled' })) {
        $null = Invoke-BaselineScenario -Key 'no-persistent-browser-session' -Mutate $mutation -ExpectFailure
    }
    $session = Invoke-BaselineScenario -Key 'no-persistent-browser-session' -Mutate {
        param($p)
        $p.sessionControls.applicationEnforcedRestrictions = $null
        $p.sessionControls.signInFrequency.extraServerMetadata = 'ignored'
    }
    Assert-True ($session.Writes -eq 1) 'Server-only session properties prevented readback'
    $existingSession = Copy-TestValue $session.Created
    $existingSession.Remove('sessionControls')
    $unchanged = $existingSession | ConvertTo-Json -Depth 30 -Compress
    $result = Invoke-BaselineScenario -Key 'no-persistent-browser-session' -Existing @($existingSession) -Adopt
    Assert-True ($result.Writes -eq 0) 'Existing session policy was automatically adopted'
    Assert-True (@($result.Log | Where-Object {
                $_.Disposition -eq 'GuidedOnly' -and $_.Readback -eq 'Mismatch'
            }).Count -eq 1) 'Missing session controls were not reported as drift'
    Assert-True (($existingSession | ConvertTo-Json -Depth 30 -Compress) -ceq $unchanged) 'Existing session state was mutated'

    $strength = Invoke-BaselineScenario -Key 'require-phishing-resistant-mfa-admins'
    $existingStrength = Copy-TestValue $strength.Created
    $existingStrength.grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
    $result = Invoke-BaselineScenario -Key 'require-phishing-resistant-mfa-admins' -Existing @($existingStrength) -Adopt
    Assert-True ($result.Writes -eq 0) 'Phishing-resistant policy was automatically adopted'
    Assert-True (@($result.Log | Where-Object {
                $_.Disposition -eq 'GuidedOnly' -and $_.Readback -eq 'Mismatch'
            }).Count -eq 1) 'Missing authentication strength was not reported'
    $null = Invoke-BaselineScenario -Key 'require-phishing-resistant-mfa-admins' -Mutate {
        param($p) $p.grantControls.authenticationStrength.id = '00000000-0000-0000-0000-000000000002'
    } -ExpectFailure
    $null = Invoke-BaselineScenario -Key 'require-mfa-admins' -Mutate {
        param($p) $p.conditions.users.includeRoles = @()
    } -ExpectFailure

    foreach ($key in @('require-mfa-admins', 'require-mfa-admin-portals', 'require-mfa-azure-management', 'require-compliant-device-or-mfa')) {
        $created = (Invoke-BaselineScenario -Key $key).Created
        $rerun = Invoke-BaselineScenario -Key $key -Existing @($created) -Adopt
        Assert-True ($rerun.Writes -eq 0) "$key silently migrated an existing policy"
        $blocked = Invoke-BaselineScenario -Key $key -Withhold
        Assert-True ($blocked.Writes -eq 0) "$key bypassed the high-risk gate"
        $protected = Invoke-BaselineScenario -Key $key -SecurityDefaults
        Assert-True ($protected.Writes -eq 0) "$key bypassed Security Defaults"
    }
    . (Join-Path $entra 'Modules\EntraPolicyComparison.ps1')
    foreach ($key in @('no-persistent-browser-session', 'require-phishing-resistant-mfa-admins')) {
        $invalidConfig = Copy-TestValue $config.ConditionalAccess
        ($invalidConfig.Policies | Where-Object Key -eq $key).ReviewExistingOnly = $false
        $rejected = $false
        try { Assert-EntraPolicyMigrationConfig -ConditionalAccess $invalidConfig }
        catch { $rejected = $true }
        Assert-True $rejected "$key accepted removal of the manual-review gate"
    }
    Write-Host "Identity regression checks passed ($script:assertions assertions)."
}
finally {
    Remove-Variable -Name IdentityReviewMock -Scope Global -ErrorAction SilentlyContinue
}
