#requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$product = Join-Path $root 'Products\Defender'
$connectScript = Join-Path $product 'Modules\Connect-DefenderServices.ps1'
$preflightScript = Join-Path $product 'Modules\Setup-DefenderPreflight.ps1'
$config = Import-PowerShellDataFile (Join-Path $product 'Config\DefenderConfig.psd1')
$script:passed = 0

function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
}

function Reset-TestState {
    $global:DefenderConnectionTest = @{
        Operator = 'operator@partner.example.invalid'
        CustomerDomain = 'customer.example.invalid'
        CustomerId = '11111111-1111-4111-8111-111111111111'
        HomeId = '22222222-2222-4222-8222-222222222222'
        Context = $null
        ConnectCount = 0
        DisconnectCount = 0
        Requests = [Collections.Generic.List[string]]::new()
        ConnectArguments = @{}
        WrongAccount = $false
        WrongTenant = $false
        ReadDenied = $false
    }
    $global:DefenderRunLog = [Collections.Generic.List[hashtable]]::new()
    $global:DefenderRunLogPath = $null
}

function New-TestContext {
    param([string] $Account, [string] $Tenant, [string[]] $Scopes = @('User.Read'), [string] $AuthType = 'Delegated')
    return [pscustomobject]@{ Account = $Account; TenantId = $Tenant; Scopes = $Scopes; AuthType = $AuthType }
}

function Get-MgContext {
    [CmdletBinding()]
    param()
    return $global:DefenderConnectionTest.Context
}

function Disconnect-MgGraph {
    [CmdletBinding()]
    param()
    $global:DefenderConnectionTest.DisconnectCount++
    $global:DefenderConnectionTest.Context = $null
}

function Connect-MgGraph {
    [CmdletBinding()]
    param([string] $TenantId, [string[]] $Scopes, [string] $ContextScope, [switch] $NoWelcome, [switch] $UseDeviceAuthentication)
    $s = $global:DefenderConnectionTest
    $s.ConnectCount++
    $s.ConnectArguments = @{ TenantId = $TenantId; Device = $UseDeviceAuthentication.IsPresent; Scopes = $Scopes }
    $tenant = if ($TenantId -in @($s.CustomerDomain, $s.CustomerId) -and -not $s.WrongTenant) {
        $s.CustomerId
    } else { $s.HomeId }
    $account = if ($s.WrongAccount) { 'different@partner.example.invalid' } else { $s.Operator }
    $s.Context = New-TestContext -Account $account -Tenant $tenant -Scopes $Scopes
}

function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string] $Method, [string] $Uri)
    $s = $global:DefenderConnectionTest
    Assert-True ($Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/v1.0/organization?$select=id,verifiedDomains') 'Unexpected request outside the synthetic identity endpoint'
    $s.Requests.Add($Uri)
    if ($s.ReadDenied) {
        $exception = [Exception]::new('Synthetic tenant read denied.')
        $exception | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{StatusCode=403})
        throw $exception
    }
    $domain = if ($s.Context.TenantId -eq $s.CustomerId) { $s.CustomerDomain } else { 'partner.example.invalid' }
    return @{ value = @(@{ id = $s.Context.TenantId; verifiedDomains = @(@{name=$domain}) }) }
}

function Invoke-TestConnection {
    param([switch] $ExplicitId, [switch] $Preflight, [switch] $ExpectFailure, [switch] $Device)
    $s = $global:DefenderConnectionTest
    $arguments = @{
        TenantAdminUpn = $s.Operator
        DelegatedOrganization = $s.CustomerDomain
        ConnectGraph = $true
        GraphScopes = @('User.Read')
        UseDeviceAuthentication = $Device.IsPresent
    }
    if ($ExplicitId) { $arguments.TenantId = $s.CustomerId }
    $failure = $null
    try {
        if ($Preflight) {
            $context = @{
                DelegatedOrganization = $s.CustomerDomain
                TenantId = $arguments.TenantId
                PermissionPlan = @{ GraphDelegatedScopes = @('User.Read') }
            }
            & $preflightScript -Config $config -Context $context -TenantAdminUpn $s.Operator | Out-Null
        }
        else { & $connectScript @arguments | Out-Null }
    }
    catch { $failure = $_ }
    if (-not $ExpectFailure -and $failure) { throw $failure }
    Assert-True (($null -ne $failure) -eq $ExpectFailure.IsPresent) 'Connection accepted an invalid account or tenant'
    if ($ExpectFailure) {
        Assert-True (@($global:DefenderRunLog | Where-Object Status -eq 'Failed').Count -gt 0) 'Connection failure was not recorded'
        Assert-True (@($global:DefenderRunLog | Where-Object {
                    $_.Action -eq 'ApiCapability' -and $_.Status -eq 'Succeeded'
                }).Count -eq 0) 'Failed authentication was reported as successful capability evidence'
    }
}

function Test-Case {
    param([string] $Name, [scriptblock] $Test)
    Reset-TestState
    & $Test
    $script:passed++
    Write-Host "PASS $Name"
}

try {
    Test-Case 'fresh GDAP sign-in selects the customer tenant without a GUID' {
        Invoke-TestConnection
        Assert-True ($global:DefenderConnectionTest.ConnectArguments.TenantId -eq 'customer.example.invalid') 'Customer domain was not passed to Connect-MgGraph'
    }
    Test-Case 'explicit tenant GUID remains authoritative' {
        Invoke-TestConnection -ExplicitId
        Assert-True ($global:DefenderConnectionTest.ConnectArguments.TenantId -eq $global:DefenderConnectionTest.CustomerId) 'Explicit tenant GUID was replaced'
    }
    Test-Case 'device authentication retains customer targeting' {
        Invoke-TestConnection -Device
        Assert-True $global:DefenderConnectionTest.ConnectArguments.Device 'Device authentication switch was lost'
        Assert-True ($global:DefenderConnectionTest.Context.TenantId -eq $global:DefenderConnectionTest.CustomerId) 'Device authentication used the home tenant'
    }
    Test-Case 'verified same-operator customer context is reused' {
        $s = $global:DefenderConnectionTest
        $s.Context = New-TestContext -Account $s.Operator.ToUpperInvariant() -Tenant $s.CustomerId
        Invoke-TestConnection
        Assert-True ($s.ConnectCount -eq 0 -and $s.DisconnectCount -eq 0) 'Valid cached context was unnecessarily reconnected'
        Assert-True ($s.Requests.Count -gt 0) 'Cached domain was not verified against the service'
    }
    Test-Case 'home-tenant cache is replaced for a delegated customer' {
        $s = $global:DefenderConnectionTest
        $s.Context = New-TestContext -Account $s.Operator -Tenant $s.HomeId
        Invoke-TestConnection
        Assert-True ($s.ConnectCount -eq 1 -and $s.DisconnectCount -eq 1) 'Wrong-tenant cache was reused'
    }
    Test-Case 'same-tenant different-operator cache is replaced before preflight' {
        $s = $global:DefenderConnectionTest
        $s.Context = New-TestContext -Account 'different@partner.example.invalid' -Tenant $s.CustomerId
        Invoke-TestConnection -Preflight
        Assert-True ($s.ConnectCount -eq 1 -and $s.DisconnectCount -eq 1) 'Another operator context was silently reused'
        Assert-True (@($global:DefenderRunLog | Where-Object {
                    $_.Action -eq 'ApiCapability' -and $_.Status -eq 'Succeeded'
                }).Count -eq 1) 'Valid reconnected preflight did not complete'
    }
    Test-Case 'missing scopes force a scoped reconnect' {
        $s = $global:DefenderConnectionTest
        $s.Context = New-TestContext -Account $s.Operator -Tenant $s.CustomerId -Scopes @()
        Invoke-TestConnection
        Assert-True ($s.ConnectCount -eq 1) 'Missing scope did not trigger a reconnect'
        Assert-True (($s.ConnectArguments.Scopes -join ',') -eq 'User.Read') 'Connection broadened the requested scopes'
    }
    Test-Case 'an app-only cache is not reused for a delegated run' {
        $s = $global:DefenderConnectionTest
        $s.Context = New-TestContext -Account $s.Operator -Tenant $s.CustomerId -AuthType 'AppOnly'
        Invoke-TestConnection
        Assert-True ($s.ConnectCount -eq 1 -and $s.Context.AuthType -eq 'Delegated') 'App-only cache was accepted as delegated authentication'
    }
    Test-Case 'wrong operator chosen during fresh sign-in fails closed' {
        $global:DefenderConnectionTest.WrongAccount = $true
        Invoke-TestConnection -Preflight -ExpectFailure
    }
    Test-Case 'explicit tenant mismatch after sign-in fails closed' {
        $global:DefenderConnectionTest.WrongTenant = $true
        Invoke-TestConnection -ExplicitId -ExpectFailure
    }
    Test-Case 'unreadable cached tenant is not reported verified' {
        $s = $global:DefenderConnectionTest
        $s.Context = New-TestContext -Account $s.Operator -Tenant $s.CustomerId
        $s.ReadDenied = $true
        Invoke-TestConnection -ExpectFailure
    }
    Test-Case 'non-GDAP sign-in explicitly targets the operator tenant' {
        $s = $global:DefenderConnectionTest
        & $connectScript -TenantAdminUpn $s.Operator -ConnectGraph -GraphScopes @('User.Read') | Out-Null
        Assert-True ($s.ConnectArguments.TenantId -eq 'partner.example.invalid') 'Default sign-in was not tenant-bound'
    }
    Test-Case 'capability evidence rejects an account changed after connection' {
        $s = $global:DefenderConnectionTest
        $context = @{
            DelegatedOrganization = $s.CustomerDomain
            PermissionPlan = @{ GraphDelegatedScopes = @('User.Read') }
        }
        . $preflightScript -Config $config -Context $context -TenantAdminUpn $s.Operator | Out-Null
        $global:DefenderRunLog.Clear()
        $s.Context.Account = 'different@partner.example.invalid'
        $failed = $false
        try { Test-DefenderApiCapability -ApiDefinition $config.Api -TenantAdminUpn $s.Operator }
        catch { $failed = $true }
        Assert-True $failed 'Preflight accepted an operator changed after connection'
        Assert-True (@($global:DefenderRunLog | Where-Object {
                    $_.Action -eq 'ApiCapability' -and $_.Status -eq 'Succeeded'
                }).Count -eq 0) 'Preflight reported a different operator as authenticated'
    }
    foreach ($mode in @('NonInteractive', 'PartialCertificate', 'AppOnly')) {
        Test-Case "$mode remains blocked before authentication" {
            $s = $global:DefenderConnectionTest
            $args = @{ TenantAdminUpn=$s.Operator; ConnectGraph=$true; GraphScopes=@('User.Read') }
            if ($mode -eq 'NonInteractive') { $args.NonInteractive = $true }
            else {
                $args.ClientId = '33333333-3333-4333-8333-333333333333'
                $args.CertificateThumbprint = '0' * 40
                if ($mode -eq 'AppOnly') { $args.TenantId = $s.CustomerId }
            }
            $failed = $false
            try { & $connectScript @args | Out-Null } catch { $failed = $true }
            Assert-True ($failed -and $s.ConnectCount -eq 0) 'Unsupported authentication reached Connect-MgGraph'
        }
    }
    Write-Host "Defender connection checks passed ($script:passed scenarios). No live authentication."
}
finally {
    Remove-Variable -Name DefenderConnectionTest -Scope Global -ErrorAction SilentlyContinue
}
