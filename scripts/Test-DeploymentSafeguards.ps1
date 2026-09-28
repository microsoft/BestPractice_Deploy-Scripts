#requires -Version 7.0
<#
.SYNOPSIS
    Offline module and orchestrator regressions for deployment safeguards.
.DESCRIPTION
    Executes repository scripts, not extracted copies. Graph, SDK discovery and
    SDK import are synthetic. All generated fixtures and reports stay in TempRoot.
#>
[CmdletBinding()]
param([string] $TempRoot = 'C:\temp\deployment-safeguard-remediation')

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$scratch = Join-Path $TempRoot ('regression-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
$script:passed = 0
function Assert-True($Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION: $Message" }
}
function Reset-State {
    $script:state = @{
        Account = 'operator@example.invalid'; Domain = 'example.invalid'
        Context = $null; Connects = 0; Disconnects = 0; DisconnectFails = $false
        Requests = [Collections.Generic.List[object]]::new()
        UserMode = 'New'; UserCreated = $false; CaWrites = 0
        CaObjects = @{}; LinkMode = ''; PageCalls = @{}
    }
    $global:DeploymentSafeguardTest = $script:state
    foreach ($product in 'Entra','Intune','Defender') {
        Set-Variable -Scope Global -Name "${product}RunLog" -Value ([Collections.Generic.List[hashtable]]::new())
        Set-Variable -Scope Global -Name "${product}RunLogPath" -Value $null
        Set-Variable -Scope Global -Name "${product}RunMetadata" -Value @{}
    }
}
function Test-Case([string] $Name, [scriptblock] $Action) {
    Reset-State
    & $Action
    $script:passed++
    Write-Host "PASS $Name"
}
function Throw-Http([int] $Status) {
    $failure = [Exception]::new("Synthetic HTTP $Status")
    $failure | Add-Member Response ([pscustomobject]@{StatusCode=$Status})
    throw $failure
}
function Get-Module {
    [CmdletBinding()]
    param([string[]] $Name, [switch] $ListAvailable)
    foreach ($n in $Name) { [pscustomobject]@{Name=$n; Version=[version]'2.30.0'} }
}
function Import-Module {
    [CmdletBinding()]
    param([string] $Name, [version] $RequiredVersion, [switch] $DisableNameChecking)
    if ($Name -notlike 'Microsoft.Graph.*') { throw "Unexpected module import: $Name" }
}
function Install-Module { throw 'Offline tests must not install modules.' }
function Get-MgDeviceManagement {}
function Get-CimInstance {
    [CmdletBinding()]
    param([string] $ClassName)
    return [pscustomobject]@{BuildNumber=22631; ProductType=1}
}
function Get-MgContext {
    [CmdletBinding()]
    param()
    return $global:DeploymentSafeguardTest.Context
}
function Disconnect-MgGraph {
    [CmdletBinding()]
    param()
    $global:DeploymentSafeguardTest.Disconnects++
    if ($global:DeploymentSafeguardTest.DisconnectFails) { throw 'Synthetic disconnect failure' }
    $global:DeploymentSafeguardTest.Context = $null
}
function Connect-MgGraph {
    [CmdletBinding()]
    param([string] $TenantId, [string[]] $Scopes, [switch] $NoWelcome, [string] $ContextScope)
    $global:DeploymentSafeguardTest.Connects++
    $global:DeploymentSafeguardTest.ConnectTenant = $TenantId
    $global:DeploymentSafeguardTest.Scopes = $Scopes
    $global:DeploymentSafeguardTest.Context = [pscustomobject]@{
        Account=$global:DeploymentSafeguardTest.Account; Scopes=$Scopes; AuthType='Delegated'
        TenantId='11111111-1111-4111-8111-111111111111'
    }
}
function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string] $Method, [string] $Uri, $Body, [string] $ContentType)
    $s = $global:DeploymentSafeguardTest
    $s.Requests.Add(@{Method=$Method; Uri=$Uri})
    $parsed = [uri] $Uri
    if ($parsed.Host -ne 'graph.microsoft.com' -or $parsed.Port -ne 443) {
        throw 'Invalid destination reached the mock SDK'
    }
    $path = $parsed.AbsolutePath
    if ($Method -eq 'GET' -and $path -eq '/v1.0/organization') {
        $domain = if ($s.CachedWrongTenant -and $s.Connects -eq 0) {'wrong.example.invalid'} else {$s.Domain}
        return @{value=@(@{id='11111111-1111-4111-8111-111111111111'; verifiedDomains=@(@{name=$domain})})}
    }
    if ($Method -eq 'GET' -and $path -eq '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy') {
        return @{isEnabled=$false}
    }
    if ($Method -eq 'GET' -and $path -like '/v1.0/users/*') {
        if ($s.UserMode -eq 'Denied') { Throw-Http 403 }
        if ($s.UserMode -eq 'New' -and -not $s.UserCreated) { Throw-Http 404 }
        return @{id='22222222-2222-4222-8222-222222222222'; accountEnabled=($s.UserMode -ne 'Disabled'); userPrincipalName='emergency@example.invalid'}
    }
    if ($Method -eq 'GET' -and $path -eq '/v1.0/groups/44444444-4444-4444-8444-444444444444') {
        return @{id='44444444-4444-4444-8444-444444444444'; displayName='Synthetic emergency group'}
    }
    if ($Method -eq 'GET' -and $path -eq '/v1.0/groups/44444444-4444-4444-8444-444444444444/transitiveMembers/microsoft.graph.user') {
        return @{value=@(@{id='22222222-2222-4222-8222-222222222222'; accountEnabled=$true})}
    }
    if ($Method -eq 'POST' -and $path -eq '/v1.0/users') {
        Assert-True (-not $s.UserCreated) 'Duplicate emergency account creation'
        $s.UserCreated = $true
        return @{id='22222222-2222-4222-8222-222222222222'}
    }
    if ($Method -eq 'GET' -and $path -like '/v1.0/roleManagement/*') {
        if ($s.UserMode -eq 'RoleDenied') { Throw-Http 403 }
        $roles = @()
        if ($s.UserMode -eq 'Verified') {
            $roles = @(@{principalId='22222222-2222-4222-8222-222222222222'; assignmentType='Assigned'; endDateTime=$null; directoryScopeId='/'})
        }
        return @{value=$roles}
    }
    if ($Method -eq 'GET' -and $path -eq '/v1.0/servicePrincipals') {
        return @{value=@(@{id='33333333-3333-4333-8333-333333333333'})}
    }
    if ($Method -eq 'POST' -and $path -eq '/v1.0/identity/conditionalAccess/policies') {
        $s.CaWrites++
        $policy = ConvertFrom-Json $Body -AsHashtable
        $policy.id = [guid]::NewGuid().ToString()
        $s.CaObjects[$policy.id] = $policy
        return $policy
    }
    if ($Method -eq 'GET' -and $path -like '/v1.0/identity/conditionalAccess/policies/*') {
        return $s.CaObjects[$path.Split('/')[-1]]
    }
    if ($Method -eq 'GET' -and ($path -match '/deviceAppManagement/' -or $path -eq '/v1.0/identity/conditionalAccess/policies')) {
        if (-not $s.PageCalls.ContainsKey($path)) { $s.PageCalls[$path] = 0 }
        $s.PageCalls[$path]++
        $page = @{value=@()}
        if ($s.LinkMode -and $s.PageCalls[$path] -eq 1) {
            $next = "$($parsed.GetLeftPart([UriPartial]::Path))?`$skiptoken=synthetic%2Btoken&`$top=2"
            $page['@odata.nextLink'] = switch ($s.LinkMode) {
                'Valid' { $next }
                'Host' { $next.Replace('graph.microsoft.com','example.invalid') }
                'Path' { 'https://graph.microsoft.com/v1.0/users?$skiptoken=synthetic' }
                'Version' { if ($next.Contains('/v1.0/')) { $next.Replace('/v1.0/','/beta/') } else { $next.Replace('/beta/','/v1.0/') } }
                'Port' { $next.Replace('graph.microsoft.com','graph.microsoft.com:444') }
                'UserInfo' { $next.Replace('https://','https://user@') }
                'EmptyUserInfo' { $next.Replace('https://','https://@') }
                'Fragment' { "$next#fragment" }
                'EmptyFragment' { "$next#" }
                'DotSegment' { $next.Replace('/deviceAppManagement/', '/extra/../deviceAppManagement/').Replace('/identity/', '/extra/../identity/') }
                'Malformed' { @{url=$next} }
                'Whitespace' { ' ' }
                'Relative' { '/v1.0/users' }
                'Cycle' { $Uri }
                default { throw 'Unknown paging test' }
            }
        }
        return $page
    }
    throw "Unexpected SDK dispatch: $Method $Uri"
}
function New-TestConfig([string] $Product, [string] $Name, [hashtable] $Replace = @{}) {
    $productRoot = Join-Path $root "Products\$Product"
    $out = Join-Path $scratch $Name
    New-Item -ItemType Directory -Path $out -Force | Out-Null
    $text = Get-Content (Join-Path $productRoot "Config\${Product}Config.psd1") -Raw
    $relative = [IO.Path]::GetRelativePath($productRoot, $out)
    $text = $text.Replace("OutputDirectory = '.\Reports'", "OutputDirectory = '$relative'")
    foreach ($key in $Replace.Keys) {
        Assert-True ($text.Contains($key)) "Missing fixture replacement: $key"
        $text = $text.Replace($key, $Replace[$key])
    }
    $path = Join-Path $out 'test-config.psd1'
    Set-Content -LiteralPath $path -Value $text -Encoding utf8
    return @{Path=$path; Directory=$out; Config=(Import-PowerShellDataFile $path)}
}
function Invoke-EntraRun($Fixture, [switch] $Preview, [switch] $SkipEmergency) {
    & (Join-Path $root 'Products\Entra\Deploy-EntraBestPractice.ps1') `
        -TenantAdminUpn 'operator@example.invalid' -ConfigPath $Fixture.Path `
        -IncludeHighRisk -CustomerApprovalId 'synthetic-approval' -BreakGlassExclusionsConfirmed `
        -RollbackAcknowledged -PilotGroupId '33333333-3333-4333-8333-333333333333' `
        -SkipTenantSecuritySettings -SkipDeploymentHealth -SkipEmergencyAccess:$SkipEmergency -WhatIf:$Preview | Out-Null
}
function Invoke-ExpectFailure([scriptblock] $Action, [string] $Pattern) {
    $failure = $null
    try { & $Action | Out-Null } catch { $failure = $_ }
    Assert-True ($null -ne $failure) 'Expected failure was not raised'
    if ($Pattern) { Assert-True ($failure.Exception.Message -match $Pattern) "Wrong failure: $($failure.Exception.Message)" }
    return $failure
}

try {
    foreach ($product in 'Entra','Intune') {
        foreach ($mode in 'Correct','Uppercase','Wrong','Missing','Cached','CachedWrong','CachedWrongTenant','WrongTenant','DisconnectFails','Gdap') {
            Test-Case "$product operator identity: $mode" {
                $upn = 'operator@example.invalid'
                $callArgs = @{TenantAdminUpn=$upn; GraphBaseUri='https://graph.microsoft.com/v1.0'; ConnectGraph=$true; Scopes=@('User.Read'); NonInteractive=$true}
                if ($mode -eq 'Uppercase') { $state.Account = $upn.ToUpperInvariant() }
                if ($mode -in 'Wrong','DisconnectFails') { $state.Account = 'other@example.invalid' }
                if ($mode -eq 'Missing') { $state.Account = '' }
                if ($mode -eq 'WrongTenant') { $state.Domain = 'wrong.example.invalid' }
                if ($mode -eq 'DisconnectFails') { $state.DisconnectFails = $true; $WarningPreference = 'Stop' }
                if ($mode -eq 'Gdap') { $callArgs.DelegatedOrganization = 'customer.example.invalid'; $state.Domain = $callArgs.DelegatedOrganization }
                if ($mode -in 'Cached','CachedWrong','CachedWrongTenant') {
                    $state.CachedWrongTenant = $mode -eq 'CachedWrongTenant'
                    $state.Context = [pscustomobject]@{Account=$(if ($mode -eq 'CachedWrong') {'other@example.invalid'} else {$upn.ToUpperInvariant()}); Scopes=@('User.Read')}
                }
                $connect = Join-Path $root "Products\$product\Modules\Connect-${product}Services.ps1"
                if ($mode -in 'Wrong','Missing','WrongTenant','DisconnectFails') {
                    $null = Invoke-ExpectFailure { & $connect @callArgs } 'operator|expected verified domain'
                    Assert-True ($state.Disconnects -eq 1) 'Invalid fresh context was not disconnected'
                    $log = Get-Variable -Scope Global -Name "${product}RunLog" -ValueOnly
                    Assert-True (@($log | Where-Object Status -eq 'Failed').Count -gt 0) 'Missing failure evidence'
                    Assert-True (@($log | Where-Object { $_.Detail -match 'reason=connected;' }).Count -eq 0) 'Premature connected evidence'
                }
                else {
                    $result = & $connect @callArgs
                    Assert-True $result.GraphConnected 'Valid context was rejected'
                    Assert-True ($state.Connects -eq $(if ($mode -eq 'Cached') {0} else {1})) 'Unexpected reconnect count'
                    if ($mode -ne 'Cached') { Assert-True (($state.Scopes -join ',') -eq 'User.Read') 'Scopes were broadened' }
                    if ($mode -eq 'Gdap') { Assert-True ($state.ConnectTenant -eq $callArgs.DelegatedOrganization) 'GDAP target changed' }
                }
            }
        }
    }
    foreach ($mode in 'New','Disabled','NoRole','Denied','RoleDenied','Verified','VerifiedPreview','Preview','Skipped') {
        Test-Case "Entra real orchestrator emergency boundary: $mode" {
            $state.UserMode = if ($mode -in 'Preview','Skipped') {'New'} elseif ($mode -eq 'VerifiedPreview') {'Verified'} else {$mode}
            $replace = @{'CreateAccountIfMissing = $false'='CreateAccountIfMissing = $true'}
            if ($mode -notin 'New','Preview') { $replace['ExcludeUserIds = @()'] = "ExcludeUserIds = @('22222222-2222-4222-8222-222222222222')" }
            $fixture = New-TestConfig 'Entra' "entra-$mode" $replace
            $bgPath = Join-Path $fixture.Directory 'entra-breakglass.json'
            @{runId='stale'; verified=$true; userIds=@('22222222-2222-4222-8222-222222222222'); groupIds=@()} |
                ConvertTo-Json | Set-Content $bgPath
            if ($mode -in 'Verified','VerifiedPreview','Preview','Skipped') {
                Invoke-EntraRun $fixture -Preview:($mode -in 'Preview','VerifiedPreview') -SkipEmergency:($mode -eq 'Skipped')
            }
            else {
                $null = Invoke-ExpectFailure { Invoke-EntraRun $fixture } 'Deployment stopped|disabled|Global Administrator|403'
            }
            Assert-True ($state.CaWrites -eq $(if ($mode -eq 'Verified') {12} else {0})) 'Unverified principals allowed CA writes, or verified apply failed'
            if ($mode -ne 'Skipped') {
                $handoff = Get-Content $bgPath -Raw | ConvertFrom-Json
                Assert-True ($handoff.verified -eq ($mode -in 'Verified','VerifiedPreview')) 'Handoff verification state is incorrect'
                Assert-True ($handoff.runId -ne 'stale') 'Stale evidence survived verification'
                if ($mode -notin 'Verified','VerifiedPreview') { Assert-True (@($handoff.userIds).Count -eq 0) 'Unverified IDs entered handoff' }
            }
            if ($mode -eq 'New') {
                Assert-True $state.UserCreated 'Opt-in did not create account'
                $null = Invoke-ExpectFailure { Invoke-EntraRun $fixture } 'already exists'
                Assert-True (@($state.Requests | Where-Object { $_.Method -eq 'POST' -and $_.Uri -match '/users$' }).Count -eq 1) 'Rerun attempted duplicate creation'
                $evidence = Get-Content (Join-Path $fixture.Directory 'entra-run-log.json') -Raw
                Assert-True ($evidence -notmatch 'passwordProfile|Aa1!') 'Secret appeared in evidence'
            }
        }
    }
    foreach ($evidenceFault in 'ReplaceUser','ReplaceGroup','AddGroup','RemoveGroup','StaleRun','StringMarker','MissingMarker') {
        Test-Case "Entra ignores diagnostic JSON substitution: $evidenceFault" {
            $state.UserMode = 'Verified'
            $state.EvidenceFault = $evidenceFault
            $fixture = New-TestConfig 'Entra' "evidence-$evidenceFault" @{
                'ExcludeUserIds = @()'="ExcludeUserIds = @('22222222-2222-4222-8222-222222222222')"
                'ExcludeGroupIds = @()'="ExcludeGroupIds = @('44444444-4444-4444-8444-444444444444')"
            }
            function Set-Content {
                [CmdletBinding(SupportsShouldProcess)]
                param([string] $LiteralPath, [Parameter(ValueFromPipeline)] $Value, [string] $Encoding)
                process {
                    $content = $Value
                    if ($LiteralPath -like '*entra-breakglass.json') {
                        $evidence = $content | ConvertFrom-Json -AsHashtable
                        if ($evidence.verified -eq $true) {
                            switch ($global:DeploymentSafeguardTest.EvidenceFault) {
                                'ReplaceUser' { $evidence.userIds = @('99999999-9999-4999-8999-999999999999') }
                                'ReplaceGroup' { $evidence.groupIds = @('99999999-9999-4999-8999-999999999999') }
                                'AddGroup' { $evidence.groupIds += '99999999-9999-4999-8999-999999999999' }
                                'RemoveGroup' { $evidence.groupIds = @() }
                                'StaleRun' { $evidence.runId = 'old-run' }
                                'StringMarker' { $evidence.verified = 'true' }
                                'MissingMarker' { $evidence.Remove('verified') }
                            }
                            $content = $evidence | ConvertTo-Json
                            $global:DeploymentSafeguardTest.EvidenceTampered = $true
                        }
                    }
                    Microsoft.PowerShell.Management\Set-Content -LiteralPath $LiteralPath -Value $content -Encoding $Encoding -WhatIf:$false
                    if ($LiteralPath -like '*entra-breakglass.json') { 'incidental diagnostic output' }
                }
            }
            function Get-Content {
                [CmdletBinding()]
                param([string] $LiteralPath, [switch] $Raw)
                if ($LiteralPath -like '*entra-breakglass.json') {
                    throw 'Diagnostic JSON must never be read for authorization'
                }
                Microsoft.PowerShell.Management\Get-Content -LiteralPath $LiteralPath -Raw:$Raw
            }
            Invoke-EntraRun $fixture
            Assert-True $state.EvidenceTampered 'Test did not substitute the diagnostic JSON'
            Assert-True ($state.CaWrites -eq 12) 'Diagnostic evidence changed authorized deployment'
            foreach ($policy in $state.CaObjects.Values) {
                Assert-True ('22222222-2222-4222-8222-222222222222' -in $policy.conditions.users.excludeUsers -and
                    '99999999-9999-4999-8999-999999999999' -notin $policy.conditions.users.excludeUsers) 'CA excluded substituted/unverified user instead of verified user'
                Assert-True (($policy.conditions.users.excludeGroups -join ',') -eq '44444444-4444-4444-8444-444444444444') 'CA exclusions changed after group evidence replacement/addition/removal'
            }
        }
    }
    foreach ($resultFault in 'Missing','Scalar','Multiple','StaleRun','StringMarker','MissingMarker',
        'WrongRunIdType','NullUsers','ObjectArray','ScalarGroup','BlankId','VerifiedEmpty','UnverifiedIds','ExtraField') {
        Test-Case "Entra rejects malformed in-memory module result: $resultFault" {
            $state.UserMode = 'Verified'
            $state.ResultFault = $resultFault
            $fixture = New-TestConfig 'Entra' "result-$resultFault" @{
                'ExcludeUserIds = @()'="ExcludeUserIds = @('22222222-2222-4222-8222-222222222222')"
            }
            $state.EmergencyScript = Join-Path $root 'Products\Entra\Modules\Setup-EmergencyAccess.ps1'
            $state.ResultWrapper = Join-Path $fixture.Directory 'result-boundary.ps1'
            # Fault injection at the return boundary, after the real module ran.
            @'
[CmdletBinding(SupportsShouldProcess)]
param([hashtable] $Config, [hashtable] $Context)
$result = & $global:DeploymentSafeguardTest.EmergencyScript -Config $Config -Context $Context -WhatIf:$WhatIfPreference
switch ($global:DeploymentSafeguardTest.ResultFault) {
    'Missing' { return }
    'Scalar' { return 'not a verification result' }
    'Multiple' { $result; $result; return }
    'StaleRun' { $result.runId = 'old-run' }
    'StringMarker' { $result.verified = 'true' }
    'MissingMarker' { $result.PSObject.Properties.Remove('verified') }
    'WrongRunIdType' { $result.runId = [guid] $result.runId }
    'NullUsers' { $result.userIds = $null }
    'ObjectArray' { $result.userIds = [object[]]@($result.userIds) }
    'ScalarGroup' { $result.groupIds = '44444444-4444-4444-8444-444444444444' }
    'BlankId' { $result.userIds = [string[]]@(' ') }
    'VerifiedEmpty' { $result.userIds = [string[]]@() }
    'UnverifiedIds' { $result.verified = $false }
    'ExtraField' { $result | Add-Member unexpected 'value' }
}
$result
'@ | Set-Content -LiteralPath $state.ResultWrapper
            function Join-Path {
                [CmdletBinding()]
                param([string] $Path, [string] $ChildPath)
                if ($ChildPath -eq 'Setup-EmergencyAccess.ps1') { return $global:DeploymentSafeguardTest.ResultWrapper }
                Microsoft.PowerShell.Management\Join-Path -Path $Path -ChildPath $ChildPath
            }
            $null = Invoke-ExpectFailure { Invoke-EntraRun $fixture } 'structured verification result|stale or malformed|inconsistent verified'
            Assert-True ($state.CaWrites -eq 0) 'Malformed module result allowed CA writes'
            $log = Get-Content (Microsoft.PowerShell.Management\Join-Path $fixture.Directory 'entra-run-log.json') -Raw | ConvertFrom-Json
            Assert-True (@($log.entries | Where-Object { $_.module -eq 'Setup-EmergencyAccess' -and $_.status -eq 'Failed' }).Count -gt 0) 'Malformed result did not produce failure evidence'
        }
    }
    foreach ($preview in $false,$true) {
        Test-Case "Emergency module returns exactly one copied structured result, WhatIf=$preview" {
            $state.UserMode = 'Verified'
            $fixture = New-TestConfig 'Entra' "result-copy-$preview"
            $context = @{
                TenantAdminUpn='operator@example.invalid'; RunId=[guid]::NewGuid()
                BreakGlassOutputPath=(Join-Path $fixture.Directory 'result.json')
                BreakGlassUserIds=[string[]]@('22222222-2222-4222-8222-222222222222')
                BreakGlassGroupIds=[string[]]@('44444444-4444-4444-8444-444444444444')
            }
            $results = @(& (Join-Path $root 'Products\Entra\Modules\Setup-EmergencyAccess.ps1') -Config $fixture.Config -Context $context -WhatIf:$preview)
            Assert-True ($results.Count -eq 1 -and $results[0] -is [pscustomobject]) 'Module emitted incidental success output'
            $result = $results[0]
            Assert-True ($result.verified -is [bool] -and $result.verified -and $result.runId -ceq [string] $context.RunId) 'Module result markers are invalid'
            Assert-True ($result.userIds -is [string[]] -and $result.groupIds -is [string[]]) 'Module result IDs are not typed arrays'
            $context.BreakGlassUserIds[0] = 'changed'
            $context.BreakGlassGroupIds[0] = 'changed'
            Assert-True ($result.userIds[0] -eq '22222222-2222-4222-8222-222222222222' -and $result.groupIds[0] -eq '44444444-4444-4444-8444-444444444444') 'Module result shares input arrays'
            Assert-True ($state.CaWrites -eq 0) 'Emergency verification wrote CA'
        }
    }
    Test-Case 'Emergency module independently stops with an invalidated handoff' {
        $fixture = New-TestConfig 'Entra' 'emergency-module' @{'CreateAccountIfMissing = $false'='CreateAccountIfMissing = $true'}
        $context = @{TenantAdminUpn='operator@example.invalid'; BreakGlassOutputPath=(Join-Path $fixture.Directory 'handoff.json'); RunId='synthetic-run'}
        $null = Invoke-ExpectFailure { & (Join-Path $root 'Products\Entra\Modules\Setup-EmergencyAccess.ps1') -Config $fixture.Config -Context $context } 'Deployment stopped'
        $handoff = Get-Content $context.BreakGlassOutputPath -Raw | ConvertFrom-Json
        Assert-True (-not $handoff.verified -and @($handoff.userIds).Count -eq 0) 'Module published unverified account'
        Assert-True (@($global:EntraRunLog | Where-Object { $_.Action -eq 'BreakGlassHandoff' -and $_.Status -eq 'Failed' }).Count -eq 1) 'Missing actionable handoff evidence'
    }
    Test-Case 'Defender JSON failure warns even with nonterminating error preference' {
        . (Join-Path $root 'Products\Defender\Modules\DefenderRunLog.ps1')
        $warnings = @()
        $ErrorActionPreference = 'Continue'
        $WarningPreference = 'Stop'
        Save-DefenderRunLogJson -Path $scratch -WarningVariable +warnings
        Assert-True (($warnings -join ' ') -match 'JSON run log could not') 'JSON failure was not surfaced as a warning'
    }
    foreach ($deploymentFails in $false,$true) {
        foreach ($jsonFails in $false,$true) {
            foreach ($htmlFails in $false,$true) {
                Test-Case "Defender evidence: deployment=$deploymentFails JSON=$jsonFails HTML=$htmlFails" {
                    $replace = @{}
                    if ($jsonFails) { $replace["JsonLogFileName = 'defender-run-log.json'"] = "JsonLogFileName = 'blocked-json'" }
                    if ($htmlFails) { $replace["HtmlReportFileName = 'defender-run-report.html'"] = "HtmlReportFileName = 'missing-html\report.html'" }
                    $fixture = New-TestConfig 'Defender' "defender-$deploymentFails-$jsonFails-$htmlFails" $replace
                    if ($jsonFails) { New-Item -ItemType Directory -Path (Join-Path $fixture.Directory 'blocked-json') | Out-Null }
                    if ($deploymentFails) { $state.Account = 'other@example.invalid' }
                    $warnings = @()
                    $failure = $null
                    $previous = $WarningPreference
                    try {
                        $WarningPreference = 'Stop'
                        & (Join-Path $root 'Products\Defender\Deploy-DefenderBestPractice.ps1') `
                            -TenantAdminUpn 'operator@example.invalid' -ConfigPath $fixture.Path `
                            -SkipPreflight -SkipMdoEop -SkipDefenderForBusiness -SkipMdeAdvanced -SkipDefenderForCloudApps `
                            -WarningVariable +warnings | Out-Null
                    }
                    catch { $failure = $_ }
                    finally { $WarningPreference = $previous }
                    Assert-True (($null -ne $failure) -eq $deploymentFails) 'Export failure changed deployment result'
                    if ($failure) { Assert-True ($failure.Exception.Message -match 'operator|account') 'Original deployment error was masked' }
                    Assert-True ((Test-Path (Join-Path $fixture.Directory 'defender-run-log.json')) -eq (-not $jsonFails)) 'JSON export was not independently attempted'
                    Assert-True ((Test-Path (Join-Path $fixture.Directory 'defender-run-report.html')) -eq (-not $htmlFails)) 'HTML export was not independently attempted'
                    if ($jsonFails) { Assert-True (($warnings -join ' ') -match 'JSON run log could not') 'Missing JSON warning' }
                    if ($htmlFails) { Assert-True (($warnings -join ' ') -match 'HTML report could not') 'Missing HTML warning' }
                    Assert-True (-not (Get-Variable DefenderRunLog -Scope Global -ErrorAction SilentlyContinue)) 'Run log was not cleared'
                    Assert-True (-not (Get-Variable DefenderRunMetadata -Scope Global -ErrorAction SilentlyContinue)) 'Run metadata was not cleared'
                }
            }
        }
    }
    foreach ($kind in 'Apps','Protection','CA') {
        foreach ($linkMode in 'Valid','Host','Path','Version','Port','UserInfo','EmptyUserInfo','Fragment','EmptyFragment','DotSegment','Malformed','Whitespace','Relative','Cycle') {
            Test-Case "Intune $kind collection boundary: $linkMode" {
                $state.LinkMode = $linkMode
                $config = Import-PowerShellDataFile (Join-Path $root 'Products\Intune\Config\IntuneConfig.psd1')
                $context = @{
                    TenantAdminUpn='operator@example.invalid'; AssignmentScope='PilotGroup'
                    PilotGroupId='33333333-3333-4333-8333-333333333333'; IncludeHighRisk=$true
                    RollbackAcknowledged=$true; BreakGlassUserIds=@('22222222-2222-4222-8222-222222222222')
                }
                $module = switch ($kind) {'Apps' {'Setup-AppDeployment'} 'Protection' {'Setup-AppProtectionPolicies'} 'CA' {'Setup-DeviceConditionalAccess'}}
                $callArgs = @{Config=$config; Context=$context; WhatIf=$true}
                if ($kind -eq 'CA') {
                    $callArgs.IncludeHighRisk=$true; $callArgs.EnableConditionalAccessEnforcement=$true
                    $callArgs.BreakGlassExclusionsConfirmed=$true; $callArgs.RollbackAcknowledged=$true
                }
                $invoke = { & (Join-Path $root "Products\Intune\Modules\$module.ps1") @callArgs }
                if ($linkMode -eq 'Valid') {
                    & $invoke | Out-Null
                    Assert-True (@($state.PageCalls.Values | Where-Object {$_ -eq 2}).Count -gt 0) 'Legitimate paging was not followed'
                }
                else {
                    $null = Invoke-ExpectFailure $invoke ''
                    Assert-True (@($state.PageCalls.Values | Where-Object {$_ -gt 1}).Count -eq 0) 'Unsafe next link reached SDK'
                }
                Assert-True (@($state.Requests | Where-Object Method -ne 'GET').Count -eq 0) 'Paging test unexpectedly wrote tenant state'
            }
        }
    }
    . (Join-Path $root 'Products\Intune\Modules\IntuneGraphClient.ps1')
    foreach ($hostName in 'graph.microsoft.com','graph.microsoft.us','dod-graph.microsoft.us','microsoftgraph.chinacloudapi.cn') {
        foreach ($version in 'v1.0','beta') {
            Test-Case "Approved Graph base: $hostName/$version" {
                Assert-IntuneGraphBaseUri "https://$hostName/$version"
                Assert-IntuneGraphBaseUri "https://${hostName}:443/$version/"
            }
        }
    }
    foreach ($badBase in 'http://graph.microsoft.com/beta','https://example.invalid/beta',
        'https://graph.microsoft.com:444/beta','https://user@graph.microsoft.com/beta',
        'https://graph.microsoft.com/beta#fragment','https://graph.microsoft.com/beta?x=1',
        'https://graph.microsoft.com/beta/../v1.0','https://graph.microsoft.com/beta/extra',
        'https://graph.microsoft.com//beta','https://graph.microsoft.com/beta#',
        'https://graph.microsoft.com/beta?','https://graph.microsoft.com/beta\',
        'https://graph.microsoft.com/%62eta','not-a-uri') {
        foreach ($key in 'GraphBaseUri','GraphBetaBaseUri') {
            Test-Case "Intune blocks $key before authentication: $badBase" {
                $default = if ($key -eq 'GraphBaseUri') {'https://graph.microsoft.com/v1.0'} else {'https://graph.microsoft.com/beta'}
                $fixture = New-TestConfig 'Intune' ([guid]::NewGuid().ToString('N')) @{"$key = '$default'"="$key = '$badBase'"}
                $null = Invoke-ExpectFailure {
                    & (Join-Path $root 'Products\Intune\Deploy-IntuneBestPractice.ps1') -TenantAdminUpn 'operator@example.invalid' -ConfigPath $fixture.Path
                } 'Graph API base'
                Assert-True ($state.Connects -eq 0 -and $state.Requests.Count -eq 0) 'Bad base reached authentication or dispatch'
                foreach ($module in 'Setup-AppDeployment','Setup-AppProtectionPolicies') {
                    $null = Invoke-ExpectFailure { & (Join-Path $root "Products\Intune\Modules\$module.ps1") -Config $fixture.Config -Context @{TenantAdminUpn='operator@example.invalid'} } 'Graph API base'
                    Assert-True ($state.Requests.Count -eq 0) 'Standalone bad base reached SDK'
                }
            }
        }
    }
    Write-Host "$script:passed safeguard scenarios passed. Synthetic module/orchestrator execution; no tenant validation."
}
finally {
    Remove-Variable -Scope Global -Name DeploymentSafeguardTest -ErrorAction SilentlyContinue
    foreach ($product in 'Entra','Intune','Defender') {
        foreach ($suffix in 'RunLog','RunLogPath','RunMetadata') {
            Remove-Variable -Scope Global -Name "$product$suffix" -ErrorAction SilentlyContinue
        }
    }
    Write-Host "Synthetic evidence retained at $scratch"
}
