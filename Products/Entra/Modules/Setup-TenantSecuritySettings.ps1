#requires -Version 7.0
<#
.SYNOPSIS
    Tenant-wide identity hardening (Zero Trust "Configure Microsoft Entra for
    increased security").

.DESCRIPTION
    Applies the Business-Premium-appropriate, GA Graph settings from the Zero
    Trust configuration guidance: restrict user consent, enable the admin
    consent workflow, restrict guest access, and disable password expiration.

    Each setting is opt-in via TenantSecurity.<Setting>.Apply. When Apply is
    $false the module reads the current value and reports it against the
    recommendation (GuidedOnly) without changing anything. Every write is
    idempotent (read-before-write), gated by ShouldProcess, wrapped in the shared
    retry boundary, and read back. Settings that conflict with Conditional Access
    (security defaults) or require higher licenses are documented in Coverage.md,
    not applied here.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [switch] $AdoptExisting
)

$ErrorActionPreference = 'Stop'
$ConfirmPreference = 'None'

. (Join-Path $PSScriptRoot 'EntraRunLog.ps1')
. (Join-Path $PSScriptRoot 'EntraGraphClient.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'EntraSecurityDefaults.ps1')

$module = 'Setup-TenantSecuritySettings'
$bestPracticeKey = 'tenant-security-settings'

if ($Context -and @($Context.BlockedItemKeys) -contains $bestPracticeKey) {
    Add-EntraRunLogEntry -Module $module -Action 'TenantSecurity' -BestPracticeKey $bestPracticeKey `
        -Status 'Skipped' -Disposition 'Blocked' -Detail 'Tenant security settings were withheld by preflight or a gate.'
    return
}

if (-not $Context -or [string]::IsNullOrWhiteSpace([string] $Context.TenantAdminUpn)) {
    throw 'Setup-TenantSecuritySettings.ps1 requires Context.TenantAdminUpn and Graph connection settings.'
}

$v1 = $Config.Api.GraphBaseUri
$ts = $Config.TenantSecurity

function Set-EntraTenantSetting {
    param(
        [Parameter(Mandatory)] [string] $Action,
        [Parameter(Mandatory)] [bool] $Apply,
        [Parameter(Mandatory)] [bool] $AlreadyCompliant,
        [Parameter(Mandatory)] [string] $CompliantDetail,
        [Parameter(Mandatory)] [string] $DriftDetail,
        [Parameter(Mandatory)] [scriptblock] $WriteAction,
        [Parameter(Mandatory)] [scriptblock] $Readback
    )
    if ($AlreadyCompliant) {
        Add-EntraRunLogEntry -Module $module -Action $Action -BestPracticeKey $bestPracticeKey `
            -Status 'Skipped' -Disposition 'AlreadyCompliant' -Readback 'Verified' -Detail $CompliantDetail
        return
    }
    if (-not $Apply) {
        Add-EntraRunLogEntry -Module $module -Action $Action -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'GuidedOnly' -Detail "Assessment only (Apply=`$false): $DriftDetail"
        return
    }
    if (-not (Test-EntraSecurityDefaultsWriteAllowed -BaseUri $v1 -Module $module -BestPracticeKey $bestPracticeKey)) {
        return
    }
    if (-not $PSCmdlet.ShouldProcess($Action, 'Apply tenant security setting')) {
        Add-EntraRunLogEntry -Module $module -Action $Action -BestPracticeKey $bestPracticeKey `
            -Status 'Info' -Disposition 'WillChange' -Readback 'NotAttempted' -Detail "WhatIf: would apply. $DriftDetail"
        return
    }
    try {
        Invoke-WithTransientRetry -Description "Apply $Action" -Action $WriteAction
        Add-EntraRunLogEntry -Module $module -Action $Action -BestPracticeKey $bestPracticeKey `
            -Status 'Updated' -Disposition 'Applicable' -Detail "Applied. $DriftDetail"
    }
    catch {
        Add-EntraRunLogEntry -Module $module -Action $Action -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Applicable' -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
            -Detail "Failed to apply ${Action}: $($_.Exception.Message)"
        throw
    }
    $verdict = $null
    try {
        $verdict = & $Readback
    }
    catch {
        Add-EntraRunLogEntry -Module $module -Action "$Action.Readback" -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' -Detail "Read-back could not confirm ${Action}; stopping to report the unconfirmed change: $($_.Exception.Message)"
        throw
    }
    if (-not $verdict) {
        Add-EntraRunLogEntry -Module $module -Action "$Action.Readback" -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Detail "Read-back did not confirm ${Action}; stopping so the discrepancy can be reviewed."
        throw "Tenant security setting '$Action' could not be confirmed after write."
    }
    Add-EntraRunLogEntry -Module $module -Action "$Action.Readback" -BestPracticeKey $bestPracticeKey `
        -Status 'Info' -Disposition 'Applicable' -Readback 'Verified' -Detail "Read-back confirmed ${Action}."
}

# --- User consent + guest access live on authorizationPolicy ---------------
$authPolicy = Invoke-WithTransientRetry -Description 'Read authorizationPolicy' -Action {
    Invoke-MgGraphRequest -Method GET -Uri "$v1/policies/authorizationPolicy"
}

$uc = $ts.UserConsent
$currentGrants = @($authPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
$desiredGrants = @($uc.PermissionGrantPoliciesAssigned)
Set-EntraTenantSetting -Action 'UserConsent' -Apply ([bool] $uc.Apply) `
    -AlreadyCompliant (($currentGrants -join ',') -eq ($desiredGrants -join ',')) `
    -CompliantDetail "User consent already restricted to: $($desiredGrants -join ', ')." `
    -DriftDetail "Restrict user app consent to: $($desiredGrants -join ', ') (currently: $($currentGrants -join ', '))." `
    -WriteAction {
        # Read-modify-write: preserve every other user-role permission the
        # customer has set and change only the consent-grant assignment.
        $current = $authPolicy.defaultUserRolePermissions
        $perms = @{}
        if ($current -is [System.Collections.IDictionary]) {
            foreach ($k in @($current.Keys)) { $perms[$k] = $current[$k] }
        }
        elseif ($current) {
            foreach ($p in $current.PSObject.Properties) { $perms[$p.Name] = $p.Value }
        }
        $perms['permissionGrantPoliciesAssigned'] = $desiredGrants
        $body = @{ defaultUserRolePermissions = $perms } | ConvertTo-Json -Depth 6
        Invoke-MgGraphRequest -Method PATCH -Uri "$v1/policies/authorizationPolicy" -Body $body -ContentType 'application/json' | Out-Null
    } `
    -Readback {
        $after = Invoke-MgGraphRequest -Method GET -Uri "$v1/policies/authorizationPolicy"
        (@($after.defaultUserRolePermissions.permissionGrantPoliciesAssigned) -join ',') -eq ($desiredGrants -join ',')
    }

$ga = $ts.GuestAccess
Set-EntraTenantSetting -Action 'GuestAccess' -Apply ([bool] $ga.Apply) `
    -AlreadyCompliant (($authPolicy.allowInvitesFrom -eq $ga.AllowInvitesFrom) -and ([string] $authPolicy.guestUserRoleId -eq [string] $ga.GuestUserRoleId)) `
    -CompliantDetail "Guest access already restricted (invitesFrom=$($authPolicy.allowInvitesFrom))." `
    -DriftDetail "Set allowInvitesFrom=$($ga.AllowInvitesFrom) and guestUserRoleId to the restricted role (currently invitesFrom=$($authPolicy.allowInvitesFrom))." `
    -WriteAction {
        $body = @{ allowInvitesFrom = $ga.AllowInvitesFrom; guestUserRoleId = $ga.GuestUserRoleId } | ConvertTo-Json
        Invoke-MgGraphRequest -Method PATCH -Uri "$v1/policies/authorizationPolicy" -Body $body -ContentType 'application/json' | Out-Null
    } `
    -Readback {
        $after = Invoke-MgGraphRequest -Method GET -Uri "$v1/policies/authorizationPolicy"
        ($after.allowInvitesFrom -eq $ga.AllowInvitesFrom) -and ([string] $after.guestUserRoleId -eq [string] $ga.GuestUserRoleId)
    }

# --- Admin consent workflow -----------------------------------------------
$acw = $ts.AdminConsentWorkflow
$acwPolicy = Invoke-WithTransientRetry -Description 'Read adminConsentRequestPolicy' -Action {
    Invoke-MgGraphRequest -Method GET -Uri "$v1/policies/adminConsentRequestPolicy"
}
if ($acw.Apply -and $acw.IsEnabled -and @($acw.ReviewerGroupIds).Count -eq 0) {
    Add-EntraRunLogEntry -Module $module -Action 'AdminConsentWorkflow' -BestPracticeKey $bestPracticeKey `
        -Status 'Succeeded' -Disposition 'GuidedOnly' `
        -Detail 'Cannot enable the admin consent workflow without reviewers. Set TenantSecurity.AdminConsentWorkflow.ReviewerGroupIds to at least one group, then re-run.'
}
else {
    Set-EntraTenantSetting -Action 'AdminConsentWorkflow' -Apply ([bool] $acw.Apply) `
        -AlreadyCompliant ([bool] $acwPolicy.isEnabled -eq [bool] $acw.IsEnabled) `
        -CompliantDetail "Admin consent workflow already isEnabled=$($acwPolicy.isEnabled)." `
        -DriftDetail "Set admin consent workflow isEnabled=$($acw.IsEnabled) with $(@($acw.ReviewerGroupIds).Count) reviewer group(s)." `
        -WriteAction {
            # Preserve the customer's existing workflow settings and merge our
            # reviewer group(s) with any already configured, rather than
            # replacing the whole policy.
            $existingReviewers = @($acwPolicy.reviewers)
            $newReviewers = @(@($acw.ReviewerGroupIds) | ForEach-Object {
                @{ query = "/groups/$_"; queryType = 'MicrosoftGraph'; queryRoot = $null }
            })
            $mergedReviewers = @(($existingReviewers + $newReviewers) | Where-Object { $_ } |
                Group-Object { [string] $_.query } | ForEach-Object { $_.Group[0] })
            $body = @{
                isEnabled = [bool] $acw.IsEnabled
                notifyReviewers = $(if ($null -ne $acwPolicy.notifyReviewers) { [bool] $acwPolicy.notifyReviewers } else { $true })
                remindersEnabled = $(if ($null -ne $acwPolicy.remindersEnabled) { [bool] $acwPolicy.remindersEnabled } else { $true })
                requestDurationInDays = $(if ($acwPolicy.requestDurationInDays) { $acwPolicy.requestDurationInDays } else { 30 })
                reviewers = $mergedReviewers
            } | ConvertTo-Json -Depth 6
            Invoke-MgGraphRequest -Method PUT -Uri "$v1/policies/adminConsentRequestPolicy" -Body $body -ContentType 'application/json' | Out-Null
        } `
        -Readback {
            $after = Invoke-MgGraphRequest -Method GET -Uri "$v1/policies/adminConsentRequestPolicy"
            [bool] $after.isEnabled -eq [bool] $acw.IsEnabled
        }
}

# --- Password expiration on the primary verified domain --------------------
$pe = $ts.PasswordExpiration
$neverExpire = 2147483647
$domains = Invoke-WithTransientRetry -Description 'Read domains' -Action {
    Invoke-MgGraphRequest -Method GET -Uri "$v1/domains"
}
$primary = @($domains.value | Where-Object { $_.isDefault }) | Select-Object -First 1
if (-not $primary) { $primary = @($domains.value | Where-Object { $_.isInitial }) | Select-Object -First 1 }
if ($primary) {
    $current = $primary.passwordValidityPeriodInDays
    if (-not $pe.DisableExpiration) {
        # This toolkit only manages *disabling* expiration; with DisableExpiration
        # false it leaves the customer's password expiration untouched.
        Add-EntraRunLogEntry -Module $module -Action 'PasswordExpiration' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'GuidedOnly' `
            -Detail "PasswordExpiration.DisableExpiration is false; leaving password expiration on $($primary.id) unchanged (current validity=$current days)."
    }
    else {
        Set-EntraTenantSetting -Action 'PasswordExpiration' -Apply ([bool] $pe.Apply) `
            -AlreadyCompliant ($current -eq $neverExpire) `
            -CompliantDetail "Password expiration already disabled on $($primary.id)." `
            -DriftDetail "Disable password expiration on domain $($primary.id) (current validity=$current days)." `
            -WriteAction {
                $body = @{ passwordValidityPeriodInDays = $neverExpire; passwordNotificationWindowInDays = 14 } | ConvertTo-Json
                Invoke-MgGraphRequest -Method PATCH -Uri "$v1/domains/$($primary.id)" -Body $body -ContentType 'application/json' | Out-Null
            } `
            -Readback {
                $after = Invoke-MgGraphRequest -Method GET -Uri "$v1/domains/$($primary.id)"
                $after.passwordValidityPeriodInDays -eq $neverExpire
            }
    }
}
