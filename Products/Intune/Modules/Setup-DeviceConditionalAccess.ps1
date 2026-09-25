#requires -Version 7.0
<#
.SYNOPSIS
    Device-based Conditional Access for Intune enrollment (guide task 10).

.DESCRIPTION
    Creates the Conditional Access policy that requires multifactor
    authentication and a compliant device for the Microsoft Intune Enrollment
    application, and ensures that application's service principal exists first
    (newer tenants do not create it automatically).

    This is the highest blast-radius action in the baseline. The orchestrator
    only lets this module run after IncludeHighRisk, EnableConditionalAccessEnforcement,
    BreakGlassExclusionsConfirmed, and RollbackAcknowledged are all supplied;
    otherwise the item is blocked upstream and this module returns immediately.
    The policy is created in the state named by ConditionalAccess.DefaultState,
    which is restricted to report-only in the current release so a first run
    cannot deny access. The operator-supplied emergency-access user and group
    IDs are written into the exclusion list. Promoting the policy to enabled is
    a deliberate portal change. Equivalent same-name policies are idempotent;
    collisions are blocked. All changes are gated by ShouldProcess and wrapped
    in the shared retry.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [switch] $IncludeHighRisk,
    [switch] $EnableConditionalAccessEnforcement,
    [switch] $BreakGlassExclusionsConfirmed,
    [switch] $RollbackAcknowledged
)

$ErrorActionPreference = 'Stop'
$ConfirmPreference = 'None'

. (Join-Path $PSScriptRoot 'IntuneRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

function Get-IntuneCaProperty {
    param([AllowNull()] $InputObject, [Parameter(Mandatory)] [string] $Name)

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject[$Name]
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-IntuneCaPropertyResult {
    param([AllowNull()] $InputObject, [Parameter(Mandatory)] [string] $Name)

    if ($null -eq $InputObject) {
        return [pscustomobject] @{ Exists = $false; Value = $null }
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $exists = $InputObject.Contains($Name)
        $value = $null
        if ($exists) {
            $value = $InputObject[$Name]
            if ($value -is [array] -and $value.Count -eq 0) {
                $value = [object[]]::new(0)
            }
        }
        return [pscustomobject] @{
            Exists = $exists
            Value = $value
        }
    }
    $property = $InputObject.PSObject.Properties[$Name]
    $value = $null
    if ($null -ne $property) {
        $value = $property.Value
        if ($value -is [array] -and $value.Count -eq 0) {
            $value = [object[]]::new(0)
        }
    }
    return [pscustomobject] @{
        Exists = $null -ne $property
        Value = $value
    }
}

function Test-IntuneCaStringSetEqual {
    param([object[]] $Actual, [string[]] $Expected)

    $actualStrings = @($Actual | ForEach-Object { [string] $_ } | Sort-Object -Unique)
    $expectedStrings = @($Expected | ForEach-Object { [string] $_ } | Sort-Object -Unique)
    if ($actualStrings.Count -ne $expectedStrings.Count) { return $false }
    foreach ($value in $expectedStrings) {
        if ($value -notin $actualStrings) { return $false }
    }
    return $true
}

function Test-IntuneCaOnlyAllowedProperties {
    param(
        [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [string[]] $AllowedNames
    )

    if ($null -eq $InputObject) { return $false }
    $names = if ($InputObject -is [System.Collections.IDictionary]) {
        @($InputObject.Keys | ForEach-Object { [string] $_ })
    }
    else {
        @($InputObject.PSObject.Properties.Name)
    }

    foreach ($name in $names) {
        if ($name -in $AllowedNames) { continue }
        $property = Get-IntuneCaPropertyResult $InputObject $name
        if (-not $property.Exists -or $null -eq $property.Value) { continue }
        if ($property.Value -is [string] -and
            [string]::IsNullOrWhiteSpace([string] $property.Value)) {
            continue
        }
        if ($property.Value -is [System.Collections.IEnumerable] -and
            $property.Value -isnot [string] -and
            @($property.Value).Count -eq 0) {
            continue
        }
        return $false
    }
    return $true
}

function Get-IntuneConditionalAccessPolicies {
    param([Parameter(Mandatory)] [string] $GraphBaseUri)

    $base = [uri] $GraphBaseUri
    $expectedPathPrefix = $base.AbsolutePath.TrimEnd('/') + '/'
    $visited = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $policies = [System.Collections.Generic.List[object]]::new()
    $nextUri = "$GraphBaseUri/identity/conditionalAccess/policies"

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        if (-not $visited.Add($nextUri)) {
            throw 'Microsoft Graph returned a pagination cycle for Conditional Access policies.'
        }
        $parsedNext = $null
        if (-not [uri]::TryCreate($nextUri, [UriKind]::Absolute, [ref] $parsedNext) -or
            $parsedNext.Scheme -ne 'https' -or
            -not [string]::Equals(
                $parsedNext.Host,
                $base.Host,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not $parsedNext.AbsolutePath.StartsWith(
                $expectedPathPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'Microsoft Graph returned a Conditional Access next link outside the configured Graph API path.'
        }

        $response = Invoke-WithTransientRetry -Description 'Read existing Conditional Access policies' -Action {
            Invoke-MgGraphRequest -Method GET -Uri $nextUri
        }
        $value = Get-IntuneCaPropertyResult $response 'value'
        if (-not $value.Exists -or $null -eq $value.Value) {
            throw 'Microsoft Graph returned no Conditional Access policy collection.'
        }
        foreach ($policy in @($value.Value)) {
            if ($null -eq $policy) {
                throw 'Microsoft Graph returned a null Conditional Access policy.'
            }
            $policies.Add($policy)
        }
        $nextLink = Get-IntuneCaPropertyResult $response '@odata.nextLink'
        $nextUri = if ($nextLink.Exists) { [string] $nextLink.Value } else { $null }
    }

    return @($policies)
}

function Get-IntuneEnrollmentServicePrincipals {
    param(
        [Parameter(Mandatory)] [string] $GraphBaseUri,
        [Parameter(Mandatory)] [string] $AppId
    )

    $spResponse = Invoke-WithTransientRetry -Description 'Read Intune enrollment service principal' -Action {
        Invoke-MgGraphRequest -Method GET -Uri "$GraphBaseUri/servicePrincipals?`$filter=appId eq '$AppId'"
    }
    $spCollection = Get-IntuneCaPropertyResult $spResponse 'value'
    if (-not $spCollection.Exists -or $null -eq $spCollection.Value) {
        throw 'Microsoft Graph returned no Intune enrollment service principal collection.'
    }
    foreach ($servicePrincipal in @($spCollection.Value)) {
        if ($null -eq $servicePrincipal) {
            throw 'Microsoft Graph returned a null Intune enrollment service principal.'
        }
    }
    return @($spCollection.Value)
}

function Wait-IntuneEnrollmentServicePrincipal {
    param(
        [Parameter(Mandatory)] [string] $GraphBaseUri,
        [Parameter(Mandatory)] [string] $AppId
    )

    return @(Invoke-WithTransientRetry `
        -Description 'Verify Intune enrollment service principal propagation' `
        -MaxAttempts 5 `
        -AdditionalTransientStatusCodes @(404) `
        -Action {
            $principals = @(Get-IntuneEnrollmentServicePrincipals `
                    -GraphBaseUri $GraphBaseUri -AppId $AppId)
            if ($principals.Count -eq 0) {
                $exception = [Exception]::new(
                    'Microsoft Graph has not projected the Intune enrollment service principal yet.'
                )
                $exception | Add-Member -NotePropertyName Response `
                    -NotePropertyValue ([pscustomobject] @{ StatusCode = 404 })
                throw $exception
            }
            return $principals
        })
}

function Test-IntuneEnrollmentCaEquivalent {
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string] $EnrollmentAppId,
        [Parameter(Mandatory)] [string] $AssignmentScope,
        [string] $PilotGroupId,
        [string[]] $BreakGlassUserIds = @(),
        [string[]] $BreakGlassGroupIds = @(),
        [Parameter(Mandatory)] [string] $ExpectedState
    )

    if ([string] (Get-IntuneCaProperty $Policy 'state') -ne $ExpectedState) {
        return $false
    }

    $conditions = Get-IntuneCaProperty $Policy 'conditions'
    if (-not (Test-IntuneCaOnlyAllowedProperties `
            -InputObject $conditions `
            -AllowedNames @('applications', 'users', 'clientAppTypes', '@odata.type'))) {
        return $false
    }
    $applications = Get-IntuneCaProperty $conditions 'applications'
    if (-not (Test-IntuneCaOnlyAllowedProperties `
            -InputObject $applications `
            -AllowedNames @('includeApplications', '@odata.type'))) {
        return $false
    }
    $includeApplications = @()
    $includeApplicationsValue = Get-IntuneCaProperty $applications 'includeApplications'
    if ($null -ne $includeApplicationsValue) {
        $includeApplications = @($includeApplicationsValue)
    }
    if ($includeApplications.Count -ne 1 -or
        [string] $includeApplications[0] -ne $EnrollmentAppId) {
        return $false
    }

    $users = Get-IntuneCaProperty $conditions 'users'
    if (-not (Test-IntuneCaOnlyAllowedProperties `
            -InputObject $users `
            -AllowedNames @(
                'includeUsers',
                'includeGroups',
                'excludeUsers',
                'excludeGroups',
                '@odata.type'
            ))) {
        return $false
    }
    $includeUsersValue = Get-IntuneCaProperty $users 'includeUsers'
    $includeGroupsValue = Get-IntuneCaProperty $users 'includeGroups'
    $excludeUsersValue = Get-IntuneCaProperty $users 'excludeUsers'
    $excludeGroupsValue = Get-IntuneCaProperty $users 'excludeGroups'
    $includeUsers = @()
    $includeGroups = @()
    $excludeUsers = @()
    $excludeGroups = @()
    if ($null -ne $includeUsersValue) { $includeUsers = @($includeUsersValue) }
    if ($null -ne $includeGroupsValue) { $includeGroups = @($includeGroupsValue) }
    if ($null -ne $excludeUsersValue) { $excludeUsers = @($excludeUsersValue) }
    if ($null -ne $excludeGroupsValue) { $excludeGroups = @($excludeGroupsValue) }
    if ($AssignmentScope -eq 'TenantWide') {
        if ($includeUsers.Count -ne 1 -or
            [string] $includeUsers[0] -ne 'All' -or
            $includeGroups.Count -ne 0) {
            return $false
        }
    }
    elseif ($includeUsers.Count -ne 0 -or
        $includeGroups.Count -ne 1 -or
        [string] $includeGroups[0] -ne $PilotGroupId) {
        return $false
    }

    if (-not (Test-IntuneCaStringSetEqual `
            -Actual $excludeUsers -Expected $BreakGlassUserIds) -or
        -not (Test-IntuneCaStringSetEqual `
            -Actual $excludeGroups -Expected $BreakGlassGroupIds)) {
        return $false
    }

    $clientAppTypesValue = Get-IntuneCaProperty $conditions 'clientAppTypes'
    $clientAppTypes = @()
    if ($null -ne $clientAppTypesValue) {
        $clientAppTypes = @($clientAppTypesValue)
    }
    if ($clientAppTypes.Count -ne 1 -or [string] $clientAppTypes[0] -ne 'all') {
        return $false
    }

    $grantControls = Get-IntuneCaProperty $Policy 'grantControls'
    if (-not (Test-IntuneCaOnlyAllowedProperties `
            -InputObject $grantControls `
            -AllowedNames @('operator', 'builtInControls', '@odata.type'))) {
        return $false
    }
    $builtInControlsValue = Get-IntuneCaProperty $grantControls 'builtInControls'
    $builtInControls = @()
    if ($null -ne $builtInControlsValue) {
        $builtInControls = @($builtInControlsValue)
    }
    if ([string] (Get-IntuneCaProperty $grantControls 'operator') -ne 'AND' -or
        $builtInControls.Count -ne 2 -or
        'mfa' -notin $builtInControls -or
        'compliantDevice' -notin $builtInControls) {
        return $false
    }

    $sessionControls = Get-IntuneCaProperty $Policy 'sessionControls'
    if (-not (Test-IntuneCaOnlyAllowedProperties `
            -InputObject $sessionControls `
            -AllowedNames @('signInFrequency', '@odata.type'))) {
        return $false
    }
    $signInFrequency = Get-IntuneCaProperty $sessionControls 'signInFrequency'
    if (-not (Test-IntuneCaOnlyAllowedProperties `
            -InputObject $signInFrequency `
            -AllowedNames @(
                'isEnabled',
                'frequencyInterval',
                'authenticationType',
                '@odata.type'
            ))) {
        return $false
    }
    return [bool] (Get-IntuneCaProperty $signInFrequency 'isEnabled') -and
        [string] (Get-IntuneCaProperty $signInFrequency 'frequencyInterval') -eq 'everyTime' -and
        [string] (Get-IntuneCaProperty $signInFrequency 'authenticationType') -eq
            'primaryAndSecondaryAuthentication'
}

$bestPracticeKey = 'device-conditional-access'
$module = 'Setup-DeviceConditionalAccess'

# The orchestrator blocks this item unless every high-risk gate was supplied.
if ($Context -and @($Context.BlockedItemKeys) -contains $bestPracticeKey) {
    Add-IntuneRunLogEntry -Module $module -Action 'ConditionalAccess' -BestPracticeKey $bestPracticeKey `
        -Status 'Skipped' -Disposition 'Blocked' `
    -Detail "Conditional Access was withheld: policy creation requires IncludeHighRisk, EnableConditionalAccessEnforcement, BreakGlassExclusionsConfirmed, and RollbackAcknowledged. Configured default state is '$($Config.ConditionalAccess.DefaultState)'."
    return
}

try {
    if (-not $Context -or [string]::IsNullOrWhiteSpace([string] $Context.TenantAdminUpn)) {
        throw 'Setup-DeviceConditionalAccess.ps1 requires Context.TenantAdminUpn from a pre-authenticated Graph connection.'
    }
    if (-not $IncludeHighRisk -or
        -not $EnableConditionalAccessEnforcement -or
        -not $BreakGlassExclusionsConfirmed -or
        -not $RollbackAcknowledged -or
        -not [bool] $Context.IncludeHighRisk -or
        -not [bool] $Context.RollbackAcknowledged) {
        $reason = 'Conditional Access creation requires IncludeHighRisk, EnableConditionalAccessEnforcement, BreakGlassExclusionsConfirmed, and RollbackAcknowledged in both the module call and verified context.'
        Add-IntuneRunLogEntry -Module $module -Action 'ConditionalAccess' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
            -Detail $reason
        throw $reason
    }
    if ([string] $Config.ConditionalAccess.DefaultState -ne
        'enabledForReportingButNotEnforced') {
        $reason = 'ConditionalAccess.DefaultState must remain enabledForReportingButNotEnforced in the current release.'
        Add-IntuneRunLogEntry -Module $module -Action 'ConditionalAccess' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
            -Detail $reason
        throw $reason
    }

    $v1 = $Config.Api.GraphBaseUri
    $appId = $Config.ConditionalAccess.EnrollmentAppId
    $displayName = $Config.ConditionalAccess.DisplayName
    $state = $Config.ConditionalAccess.DefaultState
    $assignmentScope = [string] $Context.AssignmentScope
    $breakGlassUserIds = @($Context.BreakGlassUserIds)
    $breakGlassGroupIds = @($Context.BreakGlassGroupIds)
    if ($assignmentScope -eq 'TenantWide') {
        if ($Config.Assignment.AllowTenantWideAssignmentForHighRisk -isnot [bool] -or
            -not $Config.Assignment.AllowTenantWideAssignmentForHighRisk) {
            throw 'Tenant-wide Conditional Access assignment is disabled by Assignment.AllowTenantWideAssignmentForHighRisk in configuration.'
        }
    }
    elseif ($assignmentScope -ne 'PilotGroup' -or
        [string]::IsNullOrWhiteSpace([string] $Context.PilotGroupId)) {
        throw 'Conditional Access creation requires Context.PilotGroupId unless tenant-wide assignment was explicitly approved.'
    }
    if ($breakGlassUserIds.Count -eq 0 -and $breakGlassGroupIds.Count -eq 0) {
        throw 'Conditional Access creation requires at least one emergency-access user or group exclusion.'
    }

    # Read the prerequisite state, but resolve policy collisions before making
    # any tenant change.
    $servicePrincipalExists = @(Get-IntuneEnrollmentServicePrincipals `
            -GraphBaseUri $v1 -AppId $appId).Count -gt 0

    # Check name collisions and semantic equivalents, including renamed
    # policies, before any prerequisite or policy write.
    $existingPolicies = @(Get-IntuneConditionalAccessPolicies -GraphBaseUri $v1)
    $sameNamePolicies = @(
        $existingPolicies |
            Where-Object { $_.displayName -eq $displayName }
    )
    if ($sameNamePolicies.Count -gt 1) {
        $reason = "Multiple Conditional Access policies named '$displayName' exist. Resolve the duplicate collision before rerunning."
        Add-IntuneRunLogEntry -Module $module -Action 'ConditionalAccess' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Target $displayName `
            -Readback 'NotAttempted' -Detail $reason
        throw $reason
    }
    $equivalentPolicyExists = $false
    if ($sameNamePolicies.Count -eq 1) {
        if (-not (Test-IntuneEnrollmentCaEquivalent `
                -Policy $sameNamePolicies[0] `
                -EnrollmentAppId $appId `
                -AssignmentScope $assignmentScope `
                -PilotGroupId ([string] $Context.PilotGroupId) `
                -BreakGlassUserIds $breakGlassUserIds `
                -BreakGlassGroupIds $breakGlassGroupIds `
                -ExpectedState $state)) {
            $reason = "A Conditional Access policy named '$displayName' already exists but does not match the toolkit's report-only pilot definition. The create-only writer will not adopt or overwrite it."
            Add-IntuneRunLogEntry -Module $module -Action 'ConditionalAccess' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Target $displayName `
                -Readback 'NotAttempted' -Detail $reason
            throw $reason
        }
        $equivalentPolicyExists = $true
    }
    else {
        $equivalentPolicyExists = @($existingPolicies | Where-Object {
            Test-IntuneEnrollmentCaEquivalent `
                -Policy $_ `
                -EnrollmentAppId $appId `
                -AssignmentScope $assignmentScope `
                -PilotGroupId ([string] $Context.PilotGroupId) `
                -BreakGlassUserIds $breakGlassUserIds `
                -BreakGlassGroupIds $breakGlassGroupIds `
                -ExpectedState $state
        }).Count -gt 0
    }

    # Ensure the Microsoft Intune Enrollment service principal exists only
    # after a policy collision has been ruled out.
    if (-not $servicePrincipalExists) {
        if ($PSCmdlet.ShouldProcess("Intune Enrollment service principal ($appId)", 'Create service principal')) {
            Invoke-WithTransientRetry -Description 'Create Intune enrollment service principal' -Action {
                Invoke-MgGraphRequest -Method POST -Uri "$v1/servicePrincipals" `
                    -Body (@{ appId = $appId } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
            }
            Add-IntuneRunLogEntry -Module $module -Action 'ServicePrincipal' -BestPracticeKey $bestPracticeKey `
                -Status 'Created' -Disposition 'Applicable' `
                -Detail 'Created the Microsoft Intune Enrollment service principal.'
            try {
                $createdPrincipals = @(Wait-IntuneEnrollmentServicePrincipal `
                        -GraphBaseUri $v1 -AppId $appId)
            }
            catch {
                $reason = 'Created the Microsoft Intune Enrollment service principal, but Microsoft Graph did not return it after bounded propagation checks. Confirm the Enterprise application exists and rerun before creating Conditional Access.'
                Add-IntuneRunLogEntry -Module $module -Action 'ServicePrincipal' -BestPracticeKey $bestPracticeKey `
                    -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' `
                    -Detail $reason
                throw $reason
            }
            Add-IntuneRunLogEntry -Module $module -Action 'ServicePrincipal' -BestPracticeKey $bestPracticeKey `
                -Status 'Info' -Disposition 'Applicable' -Readback 'Verified' `
                -Detail 'Verified the Microsoft Intune Enrollment service principal after creation.'
        }
        else {
            Add-IntuneRunLogEntry -Module $module -Action 'ServicePrincipal' -BestPracticeKey $bestPracticeKey `
                -Status 'Info' -Disposition 'WillChange' -Readback 'NotAttempted' `
                -Detail 'WhatIf: would create the Microsoft Intune Enrollment service principal.'
        }
    }
    else {
        Add-IntuneRunLogEntry -Module $module -Action 'ServicePrincipal' -BestPracticeKey $bestPracticeKey `
            -Status 'Skipped' -Disposition 'AlreadyCompliant' -Readback 'Verified' `
            -Detail 'The Microsoft Intune Enrollment service principal already exists.'
    }

    if ($equivalentPolicyExists) {
        Add-IntuneRunLogEntry -Module $module -Action 'ConditionalAccess' -BestPracticeKey $bestPracticeKey `
            -Status 'Skipped' -Disposition 'AlreadyCompliant' -Target $displayName -Readback 'Verified' `
            -Detail 'An equivalent report-only Conditional Access policy already exists; leaving its name and settings unchanged.'
        return
    }

    if (-not $PSCmdlet.ShouldProcess($displayName, "Create Conditional Access policy (state=$state)")) {
        Add-IntuneRunLogEntry -Module $module -Action 'ConditionalAccess' -BestPracticeKey $bestPracticeKey `
            -Status 'Info' -Disposition 'WillChange' -Target $displayName -Readback 'NotAttempted' `
            -Detail "WhatIf: would create '$displayName' requiring MFA and a compliant device for app $appId, sign-in frequency every time, state=$state."
        return
    }

    $userConditions = if ($assignmentScope -eq 'TenantWide') {
        @{ includeUsers = @('All') }
    }
    else {
        @{ includeGroups = @([string] $Context.PilotGroupId) }
    }
    if ($breakGlassUserIds.Count -gt 0) {
        $userConditions['excludeUsers'] = $breakGlassUserIds
    }
    if ($breakGlassGroupIds.Count -gt 0) {
        $userConditions['excludeGroups'] = $breakGlassGroupIds
    }

    $policyBody = @{
        displayName = $displayName
        state       = $state
        conditions  = @{
            applications   = @{ includeApplications = @($appId) }
            users          = $userConditions
            clientAppTypes = @('all')
        }
        grantControls = @{
            operator        = 'AND'
            builtInControls = @('mfa', 'compliantDevice')
        }
        sessionControls = @{
            signInFrequency = @{
                isEnabled          = $true
                frequencyInterval  = 'everyTime'
                authenticationType = 'primaryAndSecondaryAuthentication'
            }
        }
    } | ConvertTo-Json -Depth 10

    $created = Invoke-WithTransientRetry -Description "Create Conditional Access policy '$displayName'" -Action {
        Invoke-MgGraphRequest -Method POST -Uri "$v1/identity/conditionalAccess/policies" `
            -Body $policyBody -ContentType 'application/json'
    }
    $createdId = [string] $created.id
    if ([string]::IsNullOrWhiteSpace($createdId)) {
        throw "Microsoft Graph returned no ID for the created Conditional Access policy '$displayName'."
    }
    $encodedCreatedId = [uri]::EscapeDataString($createdId)
    Add-IntuneRunLogEntry -Module $module -Action 'ConditionalAccess' -BestPracticeKey $bestPracticeKey `
        -Status 'Created' -Disposition 'Applicable' -Target $displayName `
        -Detail "Created Conditional Access policy requiring MFA and a compliant device for Intune enrollment (state=$state) with the operator-supplied emergency-access exclusions. Verify the exclusions in the portal before promoting it to enabled."

    $verify = Invoke-WithTransientRetry -Description "Read back Conditional Access policy '$displayName'" -Action {
        Invoke-MgGraphRequest -Method GET -Uri "$v1/identity/conditionalAccess/policies/$encodedCreatedId"
    } -MaxAttempts 5 -AdditionalTransientStatusCodes @(404)
    $readback = if ($verify -and (Test-IntuneEnrollmentCaEquivalent `
            -Policy $verify `
            -EnrollmentAppId $appId `
            -AssignmentScope $assignmentScope `
            -PilotGroupId ([string] $Context.PilotGroupId) `
            -BreakGlassUserIds $breakGlassUserIds `
            -BreakGlassGroupIds $breakGlassGroupIds `
            -ExpectedState $state)) { 'Verified' } else { 'Mismatch' }
    if ($readback -ne 'Verified') {
        $reason = 'Conditional Access readback did not match the configured report-only pilot definition.'
        Add-IntuneRunLogEntry -Module $module -Action 'Readback' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Target $displayName -Readback $readback `
            -Detail $reason
        throw $reason
    }
    Add-IntuneRunLogEntry -Module $module -Action 'Readback' -BestPracticeKey $bestPracticeKey `
        -Status 'Info' -Disposition 'Applicable' -Target $displayName -Readback $readback `
        -Detail "Read-back returned state='$($verify.state)'."
}
catch {
    $status = Get-IntuneHttpStatusCode -ErrorRecord $_
    Add-IntuneRunLogEntry -Module $module -Action 'ConditionalAccess' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -HttpStatusCode $status `
        -Detail "Conditional Access configuration failed. Reason=$($_.Exception.Message)"
    throw
}
