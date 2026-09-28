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
    account and stops for operator setup. Returns one in-memory verification
    result with copied principal arrays for Conditional Access. The JSON file
    is diagnostic evidence only, never an authorization input.

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

if (-not $Context.RunId) { $Context.RunId = [guid]::NewGuid().ToString() }
# Invalidate previous evidence before any directory read, including failed reads.
$null = @{ runId = $Context.RunId; verified = $false; userIds = @(); groupIds = @() } |
    ConvertTo-Json | Set-Content -LiteralPath $Context.BreakGlassOutputPath -Encoding utf8 -WhatIf:$false

$v1 = $Config.Api.GraphBaseUri
$bg = $Config.ConditionalAccess.BreakGlass
$userIds = [System.Collections.Generic.List[string]]::new()
$groupIds = [System.Collections.Generic.List[string]]::new()
foreach ($u in @($Context.BreakGlassUserIds)) { if ($u) { $userIds.Add([string] $u) } }
foreach ($g in @($Context.BreakGlassGroupIds)) { if ($g) { $groupIds.Add([string] $g) } }

$verified = Get-EntraVerifiedEmergencyAccess -BaseUri $v1 `
    -UserIds $userIds.ToArray() -GroupIds $groupIds.ToArray() -Module $module -BestPracticeKey $bestPracticeKey
$userIds = [System.Collections.Generic.List[string]]::new([string[]] $verified.userIds)
$groupIds = [System.Collections.Generic.List[string]]::new([string[]] $verified.groupIds)

if ($userIds.Count -eq 0 -and $groupIds.Count -eq 0) {
    if ($bg.CreateAccountIfMissing -and
        (Test-EntraSecurityDefaultsWriteAllowed -BaseUri $v1 -Module $module -BestPracticeKey $bestPracticeKey)) {
        $identity = $Context.ConnectionInfo.TenantIdentity
        $domain = if ($identity -and $identity.ExpectedDomain) { $identity.ExpectedDomain }
                  elseif ($Context.TenantAdminUpn -match '@(?<d>[^@]+)$') { $Matches.d } else { $null }
        if (-not $domain) { throw 'Unable to derive a tenant domain for the break-glass account UPN.' }
        $upn = "$($bg.AccountUpnPrefix)@$domain"

        $existingAccount = $null
        try {
            $encodedUpn = [uri]::EscapeDataString($upn)
            $existingAccount = Invoke-WithTransientRetry -Description 'Check proposed break-glass account' -ExpectedStatusCodes @(404) -Action {
                Invoke-MgGraphRequest -Method GET -Uri "$v1/users/$encodedUpn`?`$select=id"
            }
        }
        catch {
            if ((Get-EntraHttpStatusCode -ErrorRecord $_) -ne 404) {
                $null = Add-EntraRunLogEntry -Module $module -Action 'VerifyBreakGlass' -BestPracticeKey $bestPracticeKey `
                    -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' -Target $upn `
                    -Detail 'Could not determine whether the proposed account already exists. Resolve directory read access before rerunning; no account was created.'
                throw
            }
        }
        if ($null -ne $existingAccount) {
            $reason = 'The proposed break-glass account already exists. Configure and test its credentials and permanent Global Administrator assignment, put its object ID in ConditionalAccess.BreakGlass.ExcludeUserIds, and rerun for verification. No account was created or automatically adopted.'
            $null = Add-EntraRunLogEntry -Module $module -Action 'VerifyBreakGlass' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' -Target $upn -Detail $reason
            throw $reason
        }

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
            try {
                $created = Invoke-WithTransientRetry -Description 'Create break-glass account' -Action {
                    Invoke-MgGraphRequest -Method POST -Uri "$v1/users" -Body $body -ContentType 'application/json'
                }
            }
            finally {
                $password = $null
                $body = $null
            }
            $null = Add-EntraRunLogEntry -Module $module -Action 'CreateBreakGlass' -BestPracticeKey $bestPracticeKey `
                -Status 'Created' -Disposition 'Applicable' -Readback 'NotAttempted' -Target $upn `
                -Detail 'Created a cloud-only account without an admin role. It is not a verified emergency-access exclusion.'
            $reason = 'Deployment stopped before Conditional Access writes. Reset and securely store the account credentials, configure and test emergency authentication and a permanent, tenant-wide Global Administrator assignment, then set ConditionalAccess.BreakGlass.ExcludeUserIds to the account object ID and rerun for verification. No privileges were granted automatically.'
            $null = Add-EntraRunLogEntry -Module $module -Action 'BreakGlassHandoff' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' -Target ([string] $created.id) -Detail $reason
            throw $reason
        }
        else {
            $null = Add-EntraRunLogEntry -Module $module -Action 'CreateBreakGlass' -BestPracticeKey $bestPracticeKey `
                -Status 'Info' -Disposition 'WillChange' -Target $upn -Readback 'NotAttempted' `
                -Detail "WhatIf: would create a cloud-only account '$upn', then stop before Conditional Access writes for operator credential and permanent Global Administrator setup. No verified exclusion is available."
        }
    }
    elseif (-not $bg.CreateAccountIfMissing) {
        $null = Add-EntraRunLogEntry -Module $module -Action 'BreakGlass' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'GuidedOnly' `
            -Detail 'No emergency-access account is configured. Create one (Identity guide Priority 1), set ConditionalAccess.BreakGlass.ExcludeUserIds/ExcludeGroupIds, or set CreateAccountIfMissing. The Conditional Access baseline will not write until a break-glass exclusion exists.'
    }
}

$result = [pscustomobject]@{
    runId = [string] $Context.RunId
    verified = ($userIds.Count + $groupIds.Count -gt 0)
    userIds = $userIds.ToArray()
    groupIds = $groupIds.ToArray()
}
# Local diagnostic output, not a tenant change or an authorization handoff.
$null = $result | ConvertTo-Json |
    Set-Content -LiteralPath $Context.BreakGlassOutputPath -Encoding utf8 -WhatIf:$false
return $result
