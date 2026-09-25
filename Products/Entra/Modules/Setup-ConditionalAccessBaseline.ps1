#requires -Version 7.0
<#
.SYNOPSIS
    Conditional Access baseline (Identity Protection guide, Priority 1).

.DESCRIPTION
    Creates the Conditional Access policies listed in ConditionalAccess.Policies
    from the templates in ConditionalAccess.PolicyTemplateDirectory. Every policy
    is created in ConditionalAccess.DefaultState (report-only by default), scoped
    to the pilot group for all-users-style policies, and always excludes the
    break-glass principals resolved by Setup-EmergencyAccess.

    High risk: Conditional Access can deny sign-in tenant-wide. The write only
    runs when the orchestrator has cleared the item; otherwise the module reports
    what it would create. Idempotent on display name, gated by ShouldProcess,
    wrapped in the shared retry boundary, and read back. The original ten-policy
    baseline has historical Business Premium pilot evidence; the newer P1
    additions require separate pilot validation.
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
. (Join-Path $PSScriptRoot 'EntraPolicyComparison.ps1')
. (Join-Path $PSScriptRoot 'EntraDirectoryReads.ps1')
. (Join-Path $PSScriptRoot 'EntraSecurityDefaults.ps1')

$module = 'Setup-ConditionalAccessBaseline'
$bestPracticeKey = 'conditional-access-baseline'
$ca = $Config.ConditionalAccess
Assert-EntraPolicyMigrationConfig -ConditionalAccess $ca

function ConvertTo-EntraArray {
    param([AllowNull()] $Value)
    # The unary comma keeps a single-element array from unrolling to a scalar on
    # return, which would make Graph reject the collection-typed member.
    if ($null -eq $Value) { return , @() }
    return , @($Value)
}

# Graph requires collection-typed members; the exported templates carry some of
# them as scalars. Normalize the known array fields so a POST is accepted.
function Set-EntraArrayFields {
    param([Parameter(Mandatory)] [hashtable] $Policy)
    if ($Policy.grantControls -is [hashtable] -and $Policy.grantControls.ContainsKey('builtInControls')) {
        $Policy.grantControls.builtInControls = ConvertTo-EntraArray $Policy.grantControls.builtInControls
    }
    $conditions = $Policy.conditions
    if ($conditions -is [hashtable]) {
        if ($conditions.ContainsKey('clientAppTypes')) { $conditions.clientAppTypes = ConvertTo-EntraArray $conditions.clientAppTypes }
        foreach ($node in @('applications', 'users', 'platforms')) {
            if ($conditions[$node] -is [hashtable]) {
                foreach ($field in @($conditions[$node].Keys | ForEach-Object { $_ })) {
                    if ($field -match '^(include|exclude)(Applications|Users|Groups|Roles|Platforms|UserActions)$') {
                        $conditions[$node][$field] = ConvertTo-EntraArray $conditions[$node][$field]
                    }
                }
            }
        }
    }
}

# A name match alone does not prove an existing policy provides the required
# protections. Compare the security-relevant fields (state, grant controls,
# targeted apps/user-actions/principals, client-app types) and confirm the
# break-glass principals are excluded before treating a policy as compliant.
# The break-glass half is shared with the deployment health check so the two
# can never disagree about whether a tenant is safe.
function Test-EntraPolicyCompliant {
    param(
        [Parameter(Mandatory)] [hashtable] $Desired,
        [Parameter(Mandatory)] $Existing,
        [string[]] $BreakGlassUsers = @(),
        [string[]] $BreakGlassGroups = @()
    )

    $existingState = Get-EntraPolicyProperty $Existing 'state'
    if ($existingState -notin @('enabled', 'enabledForReportingButNotEnforced', 'disabled')) { return $false }
    if ($existingState -eq 'disabled' -and (Get-EntraPolicyProperty $Desired 'state') -ne 'disabled') { return $false }

    $dg = Get-EntraPolicyProperty $Desired 'grantControls'
    $eg = Get-EntraPolicyProperty $Existing 'grantControls'
    if (((Get-EntraNormalizedSet (Get-EntraPolicyProperty $dg 'builtInControls')) -join ',') -ne
        ((Get-EntraNormalizedSet (Get-EntraPolicyProperty $eg 'builtInControls')) -join ',')) { return $false }
    if ((Get-EntraPolicyProperty $dg 'operator') -ne (Get-EntraPolicyProperty $eg 'operator')) { return $false }
    $desiredStrength = Get-EntraPolicyProperty $dg 'authenticationStrength'
    $existingStrength = Get-EntraPolicyProperty $eg 'authenticationStrength'
    if ((Get-EntraPolicyProperty $desiredStrength 'id') -ne (Get-EntraPolicyProperty $existingStrength 'id')) { return $false }

    $dc = Get-EntraPolicyProperty $Desired 'conditions'
    $ec = Get-EntraPolicyProperty $Existing 'conditions'
    if (((Get-EntraNormalizedSet (Get-EntraPolicyProperty $dc 'clientAppTypes')) -join ',') -ne
        ((Get-EntraNormalizedSet (Get-EntraPolicyProperty $ec 'clientAppTypes')) -join ',')) { return $false }
    $desiredApps = Get-EntraPolicyProperty $dc 'applications'
    $existingApps = Get-EntraPolicyProperty $ec 'applications'
    foreach ($field in 'includeApplications', 'excludeApplications', 'includeUserActions') {
        if (((Get-EntraNormalizedSet (Get-EntraPolicyProperty $desiredApps $field)) -join ',') -ne
            ((Get-EntraNormalizedSet (Get-EntraPolicyProperty $existingApps $field)) -join ',')) { return $false }
    }
    $desiredUsers = Get-EntraPolicyProperty $dc 'users'
    $existingUsers = Get-EntraPolicyProperty $ec 'users'
    foreach ($field in 'includeUsers', 'includeGroups', 'includeRoles') {
        if (((Get-EntraNormalizedSet (Get-EntraPolicyProperty $desiredUsers $field)) -join ',') -ne
            ((Get-EntraNormalizedSet (Get-EntraPolicyProperty $existingUsers $field)) -join ',')) { return $false }
    }
    foreach ($field in 'excludeUsers', 'excludeGroups', 'excludeRoles') {
        if (((Get-EntraNormalizedSet (Get-EntraPolicyProperty $desiredUsers $field)) -join ',') -ne
            ((Get-EntraNormalizedSet (Get-EntraPolicyProperty $existingUsers $field)) -join ',')) { return $false }
    }
    $desiredPlatforms = Get-EntraPolicyProperty $dc 'platforms'
    $existingPlatforms = Get-EntraPolicyProperty $ec 'platforms'
    foreach ($field in 'includePlatforms', 'excludePlatforms') {
        if (((Get-EntraNormalizedSet (Get-EntraPolicyProperty $desiredPlatforms $field)) -join ',') -ne
            ((Get-EntraNormalizedSet (Get-EntraPolicyProperty $existingPlatforms $field)) -join ',')) { return $false }
    }
    $desiredFlows = Get-EntraPolicyProperty $dc 'authenticationFlows'
    $existingFlows = Get-EntraPolicyProperty $ec 'authenticationFlows'
    if ((Get-EntraPolicyProperty $desiredFlows 'transferMethods') -ne
        (Get-EntraPolicyProperty $existingFlows 'transferMethods')) { return $false }
    foreach ($field in 'signInRiskLevels', 'userRiskLevels') {
        if (((Get-EntraNormalizedSet (Get-EntraPolicyProperty $dc $field)) -join ',') -ne
            ((Get-EntraNormalizedSet (Get-EntraPolicyProperty $ec $field)) -join ',')) { return $false }
    }
    $desiredLocations = Get-EntraPolicyProperty $dc 'locations'
    $existingLocations = Get-EntraPolicyProperty $ec 'locations'
    foreach ($field in 'includeLocations', 'excludeLocations') {
        if (((Get-EntraNormalizedSet (Get-EntraPolicyProperty $desiredLocations $field)) -join ',') -ne
            ((Get-EntraNormalizedSet (Get-EntraPolicyProperty $existingLocations $field)) -join ',')) { return $false }
    }

    if (-not (Test-EntraBreakGlassExcluded -Policy $Existing `
                -BreakGlassUsers $BreakGlassUsers -BreakGlassGroups $BreakGlassGroups)) {
        return $false
    }

    return $true
}

# When adopting an existing same-named policy, change only what this tool
# manages — ensure the required grant controls and the break-glass exclusion —
# and preserve every other tenant-specific setting by starting from the existing
# policy. Only grantControls and conditions are returned, so a PATCH leaves
# state, session controls, and display name untouched.
function Get-EntraAdoptBody {
    param(
        [Parameter(Mandatory)] $Existing,
        [Parameter(Mandatory)] [hashtable] $Desired,
        [string[]] $BreakGlassUsers = @(),
        [string[]] $BreakGlassGroups = @()
    )

    # Deep copy so the customer's existing complex objects are preserved intact.
    $work = ($Existing | ConvertTo-Json -Depth 30) | ConvertFrom-Json -AsHashtable
    $body = @{}

    $requiredControls = @($Desired.grantControls.builtInControls | Where-Object { $_ })
    if ($work.grantControls -is [hashtable]) {
        $gc = $work.grantControls
        $gc['builtInControls'] = @(@($gc['builtInControls']) + $requiredControls | Where-Object { $_ } | Select-Object -Unique)
        if ([string]::IsNullOrWhiteSpace([string] $gc['operator'])) {
            $gc['operator'] = if ($Desired.grantControls.operator) { $Desired.grantControls.operator } else { 'OR' }
        }
        $body['grantControls'] = $gc
    }
    elseif ($Desired.grantControls) {
        $body['grantControls'] = $Desired.grantControls
    }

    if ($work.conditions -isnot [hashtable]) { $work.conditions = @{} }
    if ($work.conditions.users -isnot [hashtable]) { $work.conditions.users = @{} }
    $users = $work.conditions.users
    if ($BreakGlassUsers.Count) { $users['excludeUsers'] = @(@($users['excludeUsers']) + $BreakGlassUsers | Where-Object { $_ } | Select-Object -Unique) }
    if ($BreakGlassGroups.Count) { $users['excludeGroups'] = @(@($users['excludeGroups']) + $BreakGlassGroups | Where-Object { $_ } | Select-Object -Unique) }
    $body['conditions'] = $work.conditions

    return $body
}

if ($Context -and @($Context.BlockedItemKeys) -contains $bestPracticeKey) {
    Add-EntraRunLogEntry -Module $module -Action 'ConditionalAccess' -BestPracticeKey $bestPracticeKey `
        -Status 'Skipped' -Disposition 'Blocked' -Detail 'Conditional Access baseline was withheld by preflight or a gate.'
    return
}

if (-not $Context -or [string]::IsNullOrWhiteSpace([string] $Context.TenantAdminUpn)) {
    throw 'Setup-ConditionalAccessBaseline.ps1 requires Context.TenantAdminUpn and Graph connection settings.'
}

$v1 = $Config.Api.GraphBaseUri
$breakGlassUsers = @(@($Context.BreakGlassUserIds) | Where-Object { $_ })
$breakGlassGroups = @(@($Context.BreakGlassGroupIds) | Where-Object { $_ })

# Fail closed: never create an enforcing-capable policy set without an emergency
# exclusion, even in report-only, so promotion to enabled stays safe.
if ($ca.RequireBreakGlassExclusion -and $breakGlassUsers.Count -eq 0 -and $breakGlassGroups.Count -eq 0) {
    Add-EntraRunLogEntry -Module $module -Action 'ConditionalAccess' -BestPracticeKey $bestPracticeKey `
        -Status 'Skipped' -Disposition 'Blocked' `
        -Detail 'No break-glass exclusion is available. Configure ConditionalAccess.BreakGlass or run Setup-EmergencyAccess with CreateAccountIfMissing before deploying the baseline.'
    return
}

$writeWithheld = @($Context.WriteBlockedItemKeys) -contains $bestPracticeKey

# Resolve the assignment target for the all-users-style policies.
$targetGroup = $null
$tenantWide = $Context.AssignmentScope -eq 'TenantWide'
if (-not $tenantWide) { $targetGroup = [string] $Context.PilotGroupId }

$state = $ca.DefaultState
$templateDir = Join-Path (Split-Path -Parent $PSScriptRoot) $ca.PolicyTemplateDirectory

# Read existing policies once, in full, for idempotency and protection
# comparison. Fail closed: without this list the tool cannot tell an existing
# policy from a missing one, so it must not proceed to create (and risk
# duplicating existing policies) when the read fails.
$existingByName = @{}
Add-EntraRunLogEntry -Module $module -Action 'Stage' -Status 'Info' `
    -Detail 'Existing Conditional Access assessment'
try {
    $existing = Get-EntraGraphCollection -BaseUri $v1 `
        -Uri "$v1/identity/conditionalAccess/policies" -Description 'Read existing Conditional Access policies'
    foreach ($p in @($existing)) {
        if ($p.displayName) {
            $name = [string] $p.displayName
            if (-not $existingByName.ContainsKey($name)) { $existingByName[$name] = @() }
            $existingByName[$name] += $p
        }
    }
}
catch {
    Add-EntraRunLogEntry -Module $module -Action 'ReadExisting' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -Disposition 'Blocked' -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
        -Detail "Could not enumerate existing Conditional Access policies; stopping before any write so existing policies are not duplicated: $($_.Exception.Message)"
    throw
}

$currentTier = $null
foreach ($policyRef in @($ca.Policies)) {
    $tier = Get-EntraPolicyTier -PolicyReference $policyRef
    if ($tier -ne $currentTier) {
        $currentTier = $tier
        $tierName = if ($tier -eq 'P1Hardened') { 'P1 optional/hardened policies' } else { 'Business Premium / P1 baseline' }
        Add-EntraRunLogEntry -Module $module -Action 'Stage' -Status 'Info' `
            -Detail "$tierName - assessment and gated deployment"
    }
    if (-not (Test-EntraPolicySelected -PolicyReference $policyRef)) {
        Add-EntraRunLogEntry -Module $module -Action 'PolicySelection' -BestPracticeKey $bestPracticeKey `
            -Status 'Skipped' -Disposition 'Skipped' -Target $policyRef.Key `
            -Detail "$tier policy is not selected (Enabled=false). Existing tenant policies are not disabled or deleted."
        continue
    }
    $templatePath = Join-Path $templateDir $policyRef.File
    if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
        Add-EntraRunLogEntry -Module $module -Action 'Create' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Target $policyRef.Key -Detail "Policy template not found: $($policyRef.File)"
        throw "Policy template not found: $templatePath"
    }

    $policy = Get-Content -Raw -LiteralPath $templatePath | ConvertFrom-Json -AsHashtable
    $templateName = [string] $policy.displayName
    $displayName = Get-EntraPolicyDisplayName -DisplayName $templateName -PolicyReference $policyRef -ConditionalAccess $ca
    $policy.displayName = $displayName
    Set-EntraArrayFields -Policy $policy
    $policy.state = $state

    if ($policy.conditions -isnot [hashtable]) { $policy.conditions = @{} }
    if ($policy.conditions.users -isnot [hashtable]) { $policy.conditions.users = @{} }
    $users = $policy.conditions.users

    # Scope all-users-style policies (those the template targets by group) to the
    # pilot group, or to every user under -AssignTenantWide. Role- and
    # app-scoped policies keep their template scope.
    if ($users.ContainsKey('includeGroups') -and @($users.includeGroups).Count -gt 0) {
        if ($tenantWide) {
            $users.Remove('includeGroups') | Out-Null
            $users.includeUsers = @('All')
        }
        elseif (-not [string]::IsNullOrWhiteSpace($targetGroup)) {
            $users.includeGroups = @($targetGroup)
        }
    }

    # Always exclude the break-glass principals, merged with any template roles.
    if ($breakGlassUsers.Count -gt 0) {
        $users.excludeUsers = @(@($users['excludeUsers']) + $breakGlassUsers | Where-Object { $_ } | Select-Object -Unique)
    }
    if ($breakGlassGroups.Count -gt 0) {
        $users.excludeGroups = @(@($users['excludeGroups']) + $breakGlassGroups | Where-Object { $_ } | Select-Object -Unique)
    }

    $candidateNames = Get-EntraPolicyDisplayNames -DisplayName $templateName -PolicyReference $policyRef -ConditionalAccess $ca
    $policyMatches = @(
        foreach ($name in $candidateNames) {
            if ($existingByName.ContainsKey($name)) { $existingByName[$name] }
        }
    )
    if ($policyMatches.Count -gt 1) {
        Add-EntraRunLogEntry -Module $module -Action 'ExistingPolicy' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Target $policyRef.Key `
            -Detail 'Multiple current or legacy policy names match this baseline item. Reconcile the policies manually; none was overwritten or duplicated.'
        throw "Ambiguous existing policies for baseline item '$($policyRef.Key)'."
    }
    $existingPolicy = if ($policyMatches.Count -eq 1) { $policyMatches[0] } else { $null }
    $reviewExistingOnly = (Get-EntraPolicyProperty $policyRef 'ReviewExistingOnly') -eq $true

    if ($existingPolicy -and $reviewExistingOnly) {
        $comparedControlsMatch = Test-EntraPolicyCompliant -Desired $policy -Existing $existingPolicy `
            -BreakGlassUsers $breakGlassUsers -BreakGlassGroups $breakGlassGroups
        $comparisonDetail = if ($comparedControlsMatch) {
            'The compared controls match, but this is not verified compliance or approval.'
        } else { 'The compared controls do not match the intended policy.' }
        Add-EntraRunLogEntry -Module $module -Action 'Create' -BestPracticeKey $bestPracticeKey `
            -Status 'Skipped' -Disposition 'GuidedOnly' -Target $displayName `
            -Readback $(if ($comparedControlsMatch) { 'NotAttempted' } else { 'Mismatch' }) `
            -Detail "$comparisonDetail This existing policy requires manual review of grants, authentication strength/flow, user actions, targeting, prerequisites and emergency access. It was not changed or duplicated, including with AdoptExisting."
        continue
    }

    # A name match is not proof of compliance. Only treat an existing policy as
    # complete when it actually carries the required protections and excludes
    # the break-glass principals; otherwise report drift instead of silently
    # accepting it, and never create a second policy with the same name.
    if ($existingPolicy -and -not $AdoptExisting) {
        if (Test-EntraPolicyCompliant -Desired $policy -Existing $existingPolicy -BreakGlassUsers $breakGlassUsers -BreakGlassGroups $breakGlassGroups) {
            Add-EntraRunLogEntry -Module $module -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Skipped' -Disposition 'AlreadyCompliant' -Target $displayName -Readback 'Verified' `
                -Detail 'An existing Conditional Access policy matches this baseline item and the compared controls, scope and emergency-access exclusions. Its existing name and settings are unchanged.'
        }
        else {
            Add-EntraRunLogEntry -Module $module -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Skipped' -Disposition 'GuidedOnly' -Target $displayName -Readback 'Mismatch' `
                -Detail 'An existing Conditional Access policy matches a current or previous name but not the compared protections or emergency-access exclusions. Review it, or rerun with -AdoptExisting for the supported in-place update. No duplicate policy was created.'
        }
        continue
    }

    if ($writeWithheld) {
        Add-EntraRunLogEntry -Module $module -Action 'ConditionalAccess' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'GuidedOnly' -Target $displayName `
            -Detail "Assessment only: would create '$displayName' (tier=$tier, state=$state, recommended target=$($policyRef.RecommendedState)); write withheld until IncludeHighRisk with CustomerApprovalId, BreakGlassExclusionsConfirmed, RollbackAcknowledged and an approved assignment scope are supplied."
        continue
    }

    if (@($users['includeGroups']) -contains '{ID}') {
        Add-EntraRunLogEntry -Module $module -Action 'AssignmentGate' -BestPracticeKey $bestPracticeKey `
            -Status 'Skipped' -Disposition 'Blocked' -Target $policyRef.Key `
            -Detail 'PilotGroupId is required to replace the template group placeholder. No policy was written.'
        continue
    }
    if (-not (Test-EntraSecurityDefaultsWriteAllowed -BaseUri $v1 -Module $module -BestPracticeKey $bestPracticeKey)) {
        continue
    }
    if (-not $PSCmdlet.ShouldProcess($displayName, "Create Conditional Access policy (state=$state)")) {
        Add-EntraRunLogEntry -Module $module -Action 'ConditionalAccess' -BestPracticeKey $bestPracticeKey `
            -Status 'Info' -Disposition 'WillChange' -Target $displayName -Readback 'NotAttempted' `
            -Detail "WhatIf: would create '$displayName' in state=$state, break-glass excluded, recommended target=$($policyRef.RecommendedState)."
        continue
    }

    $policy.Remove('id') | Out-Null
    $body = $policy | ConvertTo-Json -Depth 30
    $created = $null
    $wasAdopt = [bool]($existingPolicy -and $AdoptExisting)
    if ($wasAdopt) {
        # Update the existing policy in place (never POST a duplicate), changing
        # only what this tool manages: ensure the required grant controls and the
        # break-glass exclusion, and preserve the customer's other conditions,
        # session controls, targeting, and state.
        $adoptBody = (Get-EntraAdoptBody -Existing $existingPolicy -Desired $policy -BreakGlassUsers $breakGlassUsers -BreakGlassGroups $breakGlassGroups) | ConvertTo-Json -Depth 30
        try {
            Invoke-WithTransientRetry -Description "Update Conditional Access policy '$displayName'" -Action {
                Invoke-MgGraphRequest -Method PATCH -Uri "$v1/identity/conditionalAccess/policies/$($existingPolicy.id)" -Body $adoptBody -ContentType 'application/json' | Out-Null
            }
            $created = [pscustomobject]@{ id = [string] $existingPolicy.id }
            Add-EntraRunLogEntry -Module $module -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Adopted' -Disposition 'Applicable' -Target $displayName `
                -Detail "Adopted the existing Conditional Access policy: ensured the required grant controls and the break-glass exclusion; left its other conditions, session controls, targeting, and state unchanged."
        }
        catch {
            Add-EntraRunLogEntry -Module $module -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Applicable' -Target $displayName `
                -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
                -Detail "Failed to update Conditional Access policy '$displayName': $($_.Exception.Message)"
            throw
        }
    }
    else {
        try {
            $created = Invoke-WithTransientRetry -Description "Create Conditional Access policy '$displayName'" -Action {
                Invoke-MgGraphRequest -Method POST -Uri "$v1/identity/conditionalAccess/policies" -Body $body -ContentType 'application/json'
            }
            Add-EntraRunLogEntry -Module $module -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Created' -Disposition 'Applicable' -Target $displayName `
                -Detail "Created Conditional Access policy in state=$state (recommended target=$($policyRef.RecommendedState))."
        }
        catch {
            Add-EntraRunLogEntry -Module $module -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Applicable' -Target $displayName `
                -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
                -Detail "Failed to create Conditional Access policy '$displayName': $($_.Exception.Message)"
            throw
        }
    }

    $verify = $null
    try {
        $verify = Invoke-WithTransientRetry -Description "Read back Conditional Access policy '$displayName'" -RetryStatusCodes 404 -MaxAttempts 5 -Action {
            Invoke-MgGraphRequest -Method GET -Uri "$v1/identity/conditionalAccess/policies/$($created.id)"
        }
    }
    catch {
        Add-EntraRunLogEntry -Module $module -Action 'Readback' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Target $displayName -Readback 'NotAttempted' `
            -Detail "Read-back could not be completed; stopping to report the unconfirmed change: $($_.Exception.Message)"
        throw
    }
    if (-not $verify) {
        Add-EntraRunLogEntry -Module $module -Action 'Readback' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Target $displayName -Readback 'Mismatch' `
            -Detail 'Read-back returned no policy after the write. Stopping so the discrepancy can be reviewed.'
        throw "Conditional Access policy '$displayName' could not be read back after write."
    }
    if ($wasAdopt) {
        # Adopt preserves state and targeting, so confirm the two guarantees the
        # tool actually makes: the required grant controls and the break-glass
        # exclusion are present.
        $verifiedControls = Get-EntraNormalizedSet $verify.grantControls.builtInControls
        $missingControls = @(@($policy.grantControls.builtInControls) | Where-Object { $_ -and ($_ -notin $verifiedControls) })
        $verifiedExUsers = Get-EntraNormalizedSet $verify.conditions.users.excludeUsers
        $verifiedExGroups = Get-EntraNormalizedSet $verify.conditions.users.excludeGroups
        $missingExclusions = @(@($breakGlassUsers | Where-Object { $_ -notin $verifiedExUsers }) + @($breakGlassGroups | Where-Object { $_ -notin $verifiedExGroups }))
        if ($missingControls.Count -gt 0 -or $missingExclusions.Count -gt 0) {
            Add-EntraRunLogEntry -Module $module -Action 'Readback' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Target $displayName -Readback 'Mismatch' `
                -Detail 'Read-back did not confirm the adopted policy carries the required grant controls and break-glass exclusion. Stopping so the discrepancy can be reviewed.'
            throw "Adopted Conditional Access policy '$displayName' could not be confirmed after write."
        }
        Add-EntraRunLogEntry -Module $module -Action 'Readback' -BestPracticeKey $bestPracticeKey `
            -Status 'Info' -Disposition 'Applicable' -Target $displayName -Readback 'Verified' `
            -Detail "Read-back confirmed the required grant controls and break-glass exclusion; other settings preserved (state='$($verify.state)')."
    }
    else {
        if ($verify.state -ne $state -or
            ($reviewExistingOnly -and -not (Test-EntraPolicyCompliant -Desired $policy -Existing $verify `
                -BreakGlassUsers $breakGlassUsers -BreakGlassGroups $breakGlassGroups))) {
            Add-EntraRunLogEntry -Module $module -Action 'Readback' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Target $displayName -Readback 'Mismatch' `
                -Detail "Read-back did not confirm the expected state='$state' or the required grant, authentication strength/flow, user action, targeting, platforms and emergency-access exclusions. Stopping so the discrepancy can be reviewed."
            throw "Conditional Access policy '$displayName' could not be confirmed after write (state='$($verify.state)')."
        }
        Add-EntraRunLogEntry -Module $module -Action 'Readback' -BestPracticeKey $bestPracticeKey `
            -Status 'Info' -Disposition 'Applicable' -Target $displayName -Readback 'Verified' `
            -Detail $(if ($reviewExistingOnly) {
                "Read-back confirmed state='$($verify.state)' and the compared grants, authentication strength/flow, user action, targeting, platforms and emergency-access exclusions."
            } else { "Read-back confirmed state='$($verify.state)'." })
    }
}
