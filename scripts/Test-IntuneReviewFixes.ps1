#requires -Version 7.0
<#
.SYNOPSIS
    Offline synthetic regressions for Intune policy readback and collision guards.
.DESCRIPTION
    Runs the public modules with an in-memory Graph fake. No SDK, Pester,
    network, credentials, tenant exports, or additional fixture files are used.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$global:IntuneReviewTest = @{}
$root = Split-Path -Parent $PSScriptRoot
$product = Join-Path $root 'Products\Intune'
$modules = Join-Path $product 'Modules'
$global:IntuneReviewTest.config = Import-PowerShellDataFile (Join-Path $product 'Config\IntuneConfig.psd1')
$global:IntuneReviewTest.context = @{
    TenantAdminUpn = 'operator@example.invalid'
    IncludeHighRisk = $true
    AssignmentScope = 'PilotGroup'
    PilotGroupId = '11111111-1111-1111-1111-111111111111'
}
$global:IntuneReviewTest.passed = 0

function Assert-True($Condition, [string] $Message) {
    if (-not $Condition) { throw "ASSERTION: $Message" }
}

function Copy-Json($Value) {
    return ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Value -Depth 40) -AsHashtable -NoEnumerate
}

function Reset-Evidence {
    $global:IntuneRunLog = [System.Collections.Generic.List[hashtable]]::new()
    $global:IntuneRunLogPath = $null
    $global:IntuneRunMetadata = @{}
    $global:IntuneReviewTest.calls.Clear()
    $global:IntuneReviewTest.lastGraphError = $null
}

function Reset-State([string] $Kind, [string] $Fault = '', [switch] $PSObjects) {
    $global:IntuneReviewTest.kind = $Kind
    $global:IntuneReviewTest.fault = $Fault
    $global:IntuneReviewTest.psObjects = $PSObjects.IsPresent
    $global:IntuneReviewTest.objects = [ordered] @{}
    $global:IntuneReviewTest.assignments = @{}
    $global:IntuneReviewTest.actions = @{}
    $global:IntuneReviewTest.calls = [System.Collections.Generic.List[object]]::new()
    Reset-Evidence
}

function Throw-Denied {
    $error = [Exception]::new('Synthetic read denied.')
    $error | Add-Member Response ([pscustomobject] @{ StatusCode = 403 })
    throw $error
}

function Get-FakePage($Items, [string] $Uri) {
    $page = @{ value = @($Items) }
    if ($global:IntuneReviewTest.fault -eq 'MalformedCollection') { return @{ value = @{ wrong = 'not an array' } } }
    if ($global:IntuneReviewTest.fault -eq 'MissingCollection') { return @{} }
    if ($global:IntuneReviewTest.fault -eq 'NullItem') { return @{ value = @($null) } }
    if ($global:IntuneReviewTest.fault -eq 'UnsafePage') { $page['@odata.nextLink'] = 'https://example.invalid/beta/data' }
    if ($global:IntuneReviewTest.fault -eq 'WrongVersionPage') { $page['@odata.nextLink'] = $Uri.Replace('/beta/', '/v1.0/') }
    if ($global:IntuneReviewTest.fault -eq 'WrongPathPage') { $page['@odata.nextLink'] = 'https://graph.microsoft.com/beta/organization' }
    if ($global:IntuneReviewTest.fault -eq 'WrongPortPage') { $page['@odata.nextLink'] = $Uri.Replace('graph.microsoft.com', 'graph.microsoft.com:444') }
    if ($global:IntuneReviewTest.fault -eq 'PageCycle') { $page['@odata.nextLink'] = $Uri }
    if ($global:IntuneReviewTest.fault -in @('Paged', 'BroaderSecondPage')) {
        if ($Uri.Contains('?')) {
            $page.value = @($Items | Select-Object -Skip 1)
        }
        elseif (@($Items).Count -gt 1) {
            $page.value = @($Items | Select-Object -First 1)
            $page['@odata.nextLink'] = "$Uri`?`$skiptoken=synthetic"
        }
    }
    return $page
}

function Invoke-FakeGraph([string] $Method, [string] $Uri, [string] $Body) {
    $global:IntuneReviewTest.calls.Add(@{ Method = $Method; Uri = $Uri })
    $path = ([uri] $Uri).AbsolutePath
    Assert-True (([uri] $Uri).Host -eq 'graph.microsoft.com') 'Unexpected Graph host.'

    if ($global:IntuneReviewTest.kind -eq 'App') {
        if ($Method -ne 'GET') { throw 'Unexpected app protection write.' }
        if ($path -match '^/v1.0/deviceAppManagement/(androidManagedAppProtections|iosManagedAppProtections)$') {
            return @{ value = @($global:IntuneReviewTest.objects.Values | Where-Object resource -eq $Matches[1]) }
        }
        if ($path -match '^/v1.0/deviceAppManagement/(androidManagedAppProtections|iosManagedAppProtections)/[^/]+/(assignments|apps)$') {
            return @{ value = @() }
        }
        throw "Unexpected app route: $Method $path"
    }

    $basePath = if ($global:IntuneReviewTest.kind -eq 'Compliance') {
        '/v1.0/deviceManagement/deviceCompliancePolicies'
    } else { '/beta/deviceManagement/deviceEnrollmentConfigurations' }
    Assert-True ($path -eq $basePath -or $path.StartsWith("$basePath/")) 'Wrong API version or collection.'
    $suffix = $path.Substring($basePath.Length).TrimStart('/')
    $parts = @($suffix.Split('/'))
    $id = [uri]::UnescapeDataString($parts[0])

    if ($suffix -eq '') {
        if ($Method -eq 'GET') {
            if ($global:IntuneReviewTest.fault -eq 'InventoryDenied') { Throw-Denied }
            return Get-FakePage @($global:IntuneReviewTest.objects.Values) $Uri
        }
        Assert-True ($Method -eq 'POST') 'The writer must remain create-only.'
        $created = $Body | ConvertFrom-Json -AsHashtable
        $id = if ($global:IntuneReviewTest.kind -eq 'Compliance') {
            '00000000-0000-0000-0000-{0:d12}' -f ($global:IntuneReviewTest.objects.Count + 1)
        } else { 'restriction/with space {0}' -f ($global:IntuneReviewTest.objects.Count + 1) }
        if ($global:IntuneReviewTest.kind -eq 'Compliance') {
            $global:IntuneReviewTest.actions[$id] = @($created.scheduledActionsForRule)
            $null = $created.Remove('scheduledActionsForRule')
        }
        else {
            Assert-True ($created.'@odata.type' -ceq '#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration') 'Enrollment writer discriminator must be singular.'
            Assert-True ($created.Contains('platformType') -and $created.Contains('platformRestriction')) 'Enrollment writer must use the singular payload shape.'
            Assert-True (-not $created.Contains('iosRestriction')) 'Mixed enrollment payload shape.'
        }
        $created.id = $id
        $created.version = 42
        $global:IntuneReviewTest.objects[$id] = $created
        $global:IntuneReviewTest.assignments[$id] = @()
        return @{ id = $id }
    }

    Assert-True ($global:IntuneReviewTest.objects.Contains($id)) 'Unknown or incorrectly encoded object ID.'
    if ($parts.Count -eq 1 -and $Method -eq 'GET') {
        if ($global:IntuneReviewTest.fault -eq 'ReadDenied') { Throw-Denied }
        $actual = Copy-Json $global:IntuneReviewTest.objects[$id]
        if ($global:IntuneReviewTest.fault -eq 'WrongType') { $actual.'@odata.type' = '#microsoft.graph.unexpectedConfiguration' }
        if ($global:IntuneReviewTest.fault -eq 'Ownership') { $actual.description = 'Customer policy' }
        if ($global:IntuneReviewTest.kind -eq 'Compliance') {
            switch ($global:IntuneReviewTest.fault) {
                'Setting' { $actual.passwordRequired = $false }
                'NullBoolean' { $actual.deviceThreatProtectionEnabled = $null }
                'StringBoolean' { $actual.deviceThreatProtectionEnabled = 'False' }
                'StringNumber' { $actual.passwordMinimumLength = '6' }
                'MissingField' { $null = $actual.Remove('passwordRequired') }
            }
        }
        else {
            switch ($global:IntuneReviewTest.fault) {
                'Setting' { $actual.platformRestriction.personalDeviceEnrollmentBlocked = $false }
                'NullBoolean' { $actual.platformRestriction.platformBlocked = $null }
                'StringBoolean' { $actual.platformRestriction.platformBlocked = 'False' }
                'NullString' { $actual.platformRestriction.osMinimumVersion = $null }
                'Platform' { $actual.platformType = 'windows' }
                'ArrayShape' { $actual.platformRestriction.blockedSkus = @{} }
                'MissingField' { $null = $actual.platformRestriction.Remove('platformBlocked') }
                'NoComplexAnnotation' { $null = $actual.platformRestriction.Remove('@odata.type') }
                'WrongComplexAnnotation' { $actual.platformRestriction.'@odata.type' = '#microsoft.graph.unexpectedType' }
            }
        }
        return $actual
    }
    if ($parts.Count -eq 2 -and $parts[1] -eq 'assign' -and $Method -eq 'POST') {
        if ($global:IntuneReviewTest.fault -eq 'AssignDenied') { Throw-Denied }
        $bodyObject = $Body | ConvertFrom-Json -AsHashtable
        $global:IntuneReviewTest.assignments[$id] = if ($global:IntuneReviewTest.kind -eq 'Compliance') {
            @($bodyObject.assignments)
        } else { @($bodyObject.enrollmentConfigurationAssignments) }
        return $null
    }
    if ($parts.Count -eq 2 -and $parts[1] -eq 'assignments' -and $Method -eq 'GET') {
        if ($global:IntuneReviewTest.fault -eq 'AssignmentDenied') { Throw-Denied }
        $values = Copy-Json @($global:IntuneReviewTest.assignments[$id])
        if ($global:IntuneReviewTest.fault -eq 'MissingAssignment') { $values = @() }
        if ($values.Count -gt 0) {
            if ($global:IntuneReviewTest.fault -eq 'WrongAssignment') { $values[0].target.groupId = '22222222-2222-2222-2222-222222222222' }
            if ($global:IntuneReviewTest.fault -eq 'FilteredAssignment') {
                $values[0].target.deviceAndAppManagementAssignmentFilterType = 'include'
                $values[0].target.deviceAndAppManagementAssignmentFilterId = 'synthetic-filter'
            }
            if ($global:IntuneReviewTest.fault -eq 'NoFilterDefaults') {
                $values[0].target.deviceAndAppManagementAssignmentFilterType = 'none'
                $values[0].target.deviceAndAppManagementAssignmentFilterId = $null
            }
            if ($global:IntuneReviewTest.fault -in @('BroaderAssignment', 'BroaderSecondPage')) {
                $values += @{ target = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' } }
            }
            if ($global:IntuneReviewTest.fault -eq 'ExtraExclusion') {
                $values += @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'excluded' } }
            }
        }
        return Get-FakePage $values $Uri
    }
    if ($parts.Count -eq 2 -and $parts[1] -eq 'scheduledActionsForRule' -and $Method -eq 'GET') {
        if ($global:IntuneReviewTest.fault -eq 'ActionsDenied') { Throw-Denied }
        $rules = @(
            for ($i = 0; $i -lt $global:IntuneReviewTest.actions[$id].Count; $i++) {
                @{ id = "rule/$i with space"; ruleName = $global:IntuneReviewTest.actions[$id][$i].ruleName }
            }
        )
        if ($global:IntuneReviewTest.fault -eq 'ExtraRule') { $rules += @{ id = 'extra-rule'; ruleName = 'unexpected' } }
        return Get-FakePage $rules $Uri
    }
    if ($parts.Count -eq 4 -and $parts[1] -eq 'scheduledActionsForRule' -and
        $parts[3] -eq 'scheduledActionConfigurations' -and $Method -eq 'GET') {
        if ($global:IntuneReviewTest.fault -eq 'ChildDenied') { Throw-Denied }
        $ruleId = [uri]::UnescapeDataString($parts[2])
        if ($ruleId -eq 'extra-rule') { return @{ value = @() } }
        Assert-True ($ruleId -match '^rule/(\d+) with space$') 'Child rule ID was not encoded correctly.'
        $values = Copy-Json @($global:IntuneReviewTest.actions[$id][[int] $Matches[1]].scheduledActionConfigurations)
        foreach ($child in $values) { $child.id = 'server-only-action-id' }
        switch ($global:IntuneReviewTest.fault) {
            'ChildMismatch' { $values[0].gracePeriodHours = 72 }
            'ChildStringNumber' { $values[0].gracePeriodHours = '0' }
            'ChildNullString' { $values[0].notificationTemplateId = $null }
            'MissingChild' { $values = @() }
            'ExtraChild' { $values += @{ actionType = 'retire'; gracePeriodHours = 0 } }
        }
        return Get-FakePage $values $Uri
    }
    throw "Unexpected route: $Method $path"
}

function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string] $Method, [string] $Uri, [string] $Body, [string] $ContentType)
    try { $result = Invoke-FakeGraph $Method $Uri $Body }
    catch { $global:IntuneReviewTest.lastGraphError = $_; throw }
    if ($global:IntuneReviewTest.psObjects -and $null -ne $result) {
        return ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $result -Depth 40) -NoEnumerate
    }
    return $result
}

function Invoke-RealModule([switch] $ExpectFailure, [switch] $WhatIf, [switch] $WithoutGates) {
    $name = switch ($global:IntuneReviewTest.kind) {
        'Compliance' { 'Setup-DeviceCompliancePolicies.ps1' }
        'Enrollment' { 'Setup-EnrollmentRestrictions.ps1' }
        'App' { 'Setup-AppProtectionPolicies.ps1' }
    }
    $arguments = @{ Config = $global:IntuneReviewTest.config; Context = $global:IntuneReviewTest.context; WhatIf = $WhatIf.IsPresent }
    if ($global:IntuneReviewTest.kind -ne 'App' -and -not $WithoutGates) { $arguments.IncludeHighRisk = $true }
    if ($global:IntuneReviewTest.kind -eq 'Enrollment' -and -not $WithoutGates) { $arguments.EnableEnrollmentRestrictions = $true }
    $caught = $null
    try { & (Join-Path $modules $name) @arguments 6>$null }
    catch { $caught = $_ }
    if (-not $ExpectFailure -and $caught) {
        throw "$caught`nMock diagnostic: $($global:IntuneReviewTest.lastGraphError)`n$($global:IntuneReviewTest.lastGraphError.ScriptStackTrace)"
    }
    Assert-True (([bool] $caught) -eq $ExpectFailure.IsPresent) "ExpectedFailure=$ExpectFailure for $($global:IntuneReviewTest.kind)/$($global:IntuneReviewTest.fault)."
    if ($ExpectFailure) {
        Assert-True (@($global:IntuneRunLog | Where-Object Status -eq 'Failed').Count -gt 0) 'Failure must be logged.'
        Assert-True (@($global:IntuneRunLog | Where-Object Readback -eq 'Verified').Count -eq 0) 'Failure must not claim verification.'
    }
}

function Assert-NoWrites {
    Assert-True (@($global:IntuneReviewTest.calls | Where-Object Method -ne 'GET').Count -eq 0) 'Unexpected write.'
}

function Assert-Verified([int] $Count) {
    Assert-True (@($global:IntuneRunLog | Where-Object Readback -eq 'Verified').Count -eq $Count) 'Expected verified readback for every policy.'
}

function Test-Case([string] $Name, [scriptblock] $Test) {
    try {
        & $Test
        $global:IntuneReviewTest.passed++
        Write-Host "PASS $Name"
    }
    catch { throw "FAIL $Name`n$($_ | Out-String)`n$($_.ScriptStackTrace)" }
}

. (Join-Path $modules 'IntuneAssignmentScope.ps1')
. (Join-Path $modules 'IntunePolicyReadback.ps1')

Test-Case 'assignment classifier empty, exclusions, broad precedence, malformed targets' {
    $exclude = @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'excluded' } }
    $broad = @{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }
    Assert-True ((Get-IntuneAssignmentScopeResult -Assignments @()).Scope -eq 'None') 'Empty must be None.'
    foreach ($pilot in @('', $global:IntuneReviewTest.context.PilotGroupId)) {
        $result = Get-IntuneAssignmentScopeResult -Assignments @($exclude) -PilotGroupId $pilot -ExclusionBehavior Count
        Assert-True ($result.Scope -eq 'Unknown' -and $result.ExclusionCount -eq 1) 'Exclusions alone must be Unknown.'
    }
    foreach ($targets in @(@($broad, $exclude), @($exclude, $broad))) {
        $result = Get-IntuneAssignmentScopeResult -Assignments $targets -ExclusionBehavior Count
        Assert-True ($result.Scope -eq 'Broad' -and $result.ExclusionCount -eq 1) 'Broad precedence and exclusion count.'
    }
    $caught = $false
    try { Get-IntuneAssignmentScopeResult -Assignments @($broad, @{ target = $null }) }
    catch { $caught = $true }
    Assert-True $caught 'Malformed targets after broad must throw.'
}

Test-Case 'managed JSON comparisons are typed and unordered only for set-like fields' {
    foreach ($pair in @(@($false, 'False'), @($false, $null), @('', $null), @(0, '0'), @(@(), $null), @(@{}, @()))) {
        Assert-True (-not (Test-IntuneManagedValue $pair[0] $pair[1])) 'Distinct JSON values compared equal.'
    }
    $expected = @{ roleScopeTagIds = @('1', '2'); scheduledActionsForRule = @(
        @{ ruleName = 'A'; scheduledActionConfigurations = @(@{ actionType = 'block' }, @{ actionType = 'notification' }) },
        @{ ruleName = 'B'; scheduledActionConfigurations = @() }
    ) }
    $actual = [pscustomobject] @{ roleScopeTagIds = @('2', '1'); id = 'metadata'; scheduledActionsForRule = @(
        [pscustomobject] @{ ruleName = 'B'; scheduledActionConfigurations = @(); id = 'server' },
        [pscustomobject] @{ ruleName = 'A'; scheduledActionConfigurations = @(@{ actionType = 'notification' }, @{ actionType = 'block' }) }
    ) }
    Assert-True (Test-IntuneManagedValue $expected $actual) 'Unordered collections or PSObject metadata mismatch.'
    Assert-True (-not (Test-IntuneManagedValue @('1', '2') @('2', '1'))) 'Unknown arrays must remain ordered.'
    Assert-True (Test-IntuneManagedValue 0 ([double] 0)) 'JSON numeric CLR variants must match.'
}

foreach ($kindName in @('Compliance', 'Enrollment')) {
    foreach ($objectShape in @($false, $true)) {
        Test-Case "$kindName create and matching rerun, PSObjects=$objectShape" {
            Reset-State $kindName -PSObjects:$objectShape
            Invoke-RealModule
            $count = $global:IntuneReviewTest.objects.Count
            Assert-True ($count -gt 0) 'Create did not execute.'
            Assert-Verified $count
            if ($kindName -eq 'Compliance') {
                Assert-True (@($global:IntuneReviewTest.calls | Where-Object Uri -match '/scheduledActionConfigurations$').Count -eq $count) 'Must read actual child endpoints.'
            }
            Reset-Evidence
            $global:IntuneReviewTest.fault = 'Paged'
            Invoke-RealModule
            Assert-NoWrites
            Assert-Verified $count
        }
    }
    foreach ($failure in @('Setting', 'WrongType', 'Ownership', 'NullBoolean', 'StringBoolean', 'MissingField',
            'MissingAssignment', 'WrongAssignment', 'BroaderAssignment', 'BroaderSecondPage', 'FilteredAssignment',
            'ExtraExclusion', 'ReadDenied', 'AssignmentDenied')) {
        Test-Case "$kindName rejects postwrite $failure" {
            Reset-State $kindName $failure
            Invoke-RealModule -ExpectFailure
        }
    }
    foreach ($failure in @('Setting', 'MissingAssignment', 'WrongAssignment', 'BroaderAssignment', 'Ownership', 'ReadDenied')) {
        Test-Case "$kindName rejects existing $failure without writes" {
            Reset-State $kindName
            Invoke-RealModule
            Reset-Evidence
            $global:IntuneReviewTest.fault = $failure
            Invoke-RealModule -ExpectFailure
            Assert-NoWrites
        }
    }
    Test-Case "$kindName failed assignment stays blocked on rerun" {
        Reset-State $kindName 'AssignDenied'
        Invoke-RealModule -ExpectFailure
        Reset-Evidence
        $global:IntuneReviewTest.fault = ''
        Invoke-RealModule -ExpectFailure
        Assert-NoWrites
    }
    foreach ($collision in @('Unmanaged', 'Duplicate')) {
        Test-Case "$kindName blocks $collision collisions" {
            Reset-State $kindName
            Invoke-RealModule
            $firstId = @($global:IntuneReviewTest.objects.Keys)[0]
            if ($collision -eq 'Unmanaged') { $global:IntuneReviewTest.objects[$firstId].description = 'Customer owned' }
            else {
                $copy = Copy-Json $global:IntuneReviewTest.objects[$firstId]
                $copy.id = '99999999-9999-9999-9999-999999999999'
                $global:IntuneReviewTest.objects[$copy.id] = $copy
                $global:IntuneReviewTest.assignments[$copy.id] = $global:IntuneReviewTest.assignments[$firstId]
                $global:IntuneReviewTest.actions[$copy.id] = $global:IntuneReviewTest.actions[$firstId]
            }
            Reset-Evidence
            Invoke-RealModule -ExpectFailure
            Assert-NoWrites
        }
    }
    Test-Case "$kindName WhatIf and missing high-risk gates never write" {
        Reset-State $kindName
        Invoke-RealModule -WhatIf
        Assert-NoWrites
        Assert-True (@($global:IntuneRunLog | Where-Object Disposition -eq 'WillChange').Count -gt 0) 'Missing WhatIf evidence.'
        Reset-Evidence
        Invoke-RealModule -WithoutGates
        Assert-NoWrites
    }
    Test-Case "$kindName rejects unapproved tenant-wide writes" {
        Reset-State $kindName
        $original = $global:IntuneReviewTest.context.AssignmentScope
        try {
            $global:IntuneReviewTest.context.AssignmentScope = 'TenantWide'
            Invoke-RealModule -ExpectFailure
            Assert-NoWrites
        } finally { $global:IntuneReviewTest.context.AssignmentScope = $original }
    }
    Test-Case "$kindName accepts explicit no-filter defaults" {
        Reset-State $kindName 'NoFilterDefaults'
        Invoke-RealModule
        Assert-Verified $global:IntuneReviewTest.objects.Count
    }
}

foreach ($failure in @('ChildMismatch', 'ChildDenied', 'ChildStringNumber', 'ChildNullString',
        'MissingChild', 'ExtraChild', 'ExtraRule', 'ActionsDenied', 'StringNumber')) {
    Test-Case "Compliance rejects $failure" {
        Reset-State Compliance $failure
        Invoke-RealModule -ExpectFailure
    }
}
foreach ($failure in @('Platform', 'NullString', 'ArrayShape', 'WrongComplexAnnotation', 'InventoryDenied', 'UnsafePage', 'WrongVersionPage',
        'WrongPathPage', 'WrongPortPage', 'PageCycle', 'MalformedCollection', 'MissingCollection', 'NullItem')) {
    Test-Case "Enrollment rejects $failure" {
        Reset-State Enrollment $failure
        Invoke-RealModule -ExpectFailure
    }
}

Test-Case 'Enrollment inventories singular and plural shapes without confusing unrelated types' {
    Reset-State Enrollment
    Invoke-RealModule
    $legacy = @{
        id = 'legacy/opaque id'
        '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'
        displayName = 'Legacy customer restrictions'
        description = ''
    }
    foreach ($platform in @('ios', 'windows', 'windowsMobile', 'android', 'macOS')) {
        $legacy["${platform}Restriction"] = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $true }
    }
    $global:IntuneReviewTest.objects[$legacy.id] = $legacy
    $global:IntuneReviewTest.assignments[$legacy.id] = @()
    $global:IntuneReviewTest.objects['limit'] = @{ id = 'limit'; '@odata.type' = '#microsoft.graph.deviceEnrollmentLimitConfiguration' }
    Reset-Evidence
    Invoke-RealModule -WithoutGates
    Assert-NoWrites
    $expectedCount = $global:IntuneReviewTest.objects.Count - 1
    Assert-True (@($global:IntuneRunLog | Where-Object Detail -like "ConfigurationCount=$expectedCount;*").Count -eq 1) 'Both enrollment shapes must be inventoried.'
    Assert-True (@($global:IntuneReviewTest.calls | Where-Object Uri -like '*/limit/assignments').Count -eq 0) 'Unrelated configurations must not be assessed as restrictions.'
}

Test-Case 'Enrollment accepts an omitted non-derived complex type annotation' {
    Reset-State Enrollment 'NoComplexAnnotation'
    Invoke-RealModule
    Assert-Verified $global:IntuneReviewTest.objects.Count
}

foreach ($collisionPlatform in @('androidManagedAppProtections', 'iosManagedAppProtections')) {
    Test-Case "App protection existing guard blocks $collisionPlatform collision" {
        Reset-State App
        foreach ($resource in @('androidManagedAppProtections', 'iosManagedAppProtections')) {
            $definition = if ($resource.StartsWith('android')) { $global:IntuneReviewTest.config.AppProtection.Android } else { $global:IntuneReviewTest.config.AppProtection.Ios }
            $global:IntuneReviewTest.objects[$resource] = @{
                id = $resource; resource = $resource; displayName = $definition.DisplayName
                description = $(if ($resource -eq $collisionPlatform) { 'Customer owned' } else { $global:IntuneReviewTest.config.ManagedByTag })
            }
        }
        Invoke-RealModule -ExpectFailure
        Assert-NoWrites
        Assert-True (@($global:IntuneRunLog | Where-Object { $_.Disposition -eq 'Blocked' -and $_.Detail -like '*not managed by the toolkit*' }).Count -eq 1) 'Must exercise the actual unmanaged collision guard.'
    }
}
Test-Case 'App protection WhatIf never posts' {
    Reset-State App
    Invoke-RealModule -WhatIf
    Assert-NoWrites
}
Test-Case 'Existing managed app protection remains review-only' {
    Reset-State App
    foreach ($resource in @('androidManagedAppProtections', 'iosManagedAppProtections')) {
        $definition = if ($resource.StartsWith('android')) {
            $global:IntuneReviewTest.config.AppProtection.Android
        } else { $global:IntuneReviewTest.config.AppProtection.Ios }
        $global:IntuneReviewTest.objects[$resource] = @{
            id = $resource; resource = $resource; displayName = $definition.DisplayName
            description = $global:IntuneReviewTest.config.ManagedByTag
        }
    }
    Invoke-RealModule
    Assert-NoWrites
    Assert-True (@($global:IntuneRunLog | Where-Object {
                $_.Action -eq 'Deploy' -and $_.Disposition -eq 'GuidedOnly' -and $_.Readback -eq 'NotAttempted'
            }).Count -eq 2) 'Existing app protection must require review for both platforms.'
    Assert-True (@($global:IntuneRunLog | Where-Object Readback -eq 'Verified').Count -eq 0) 'Inventory must not claim verified app protection.'
}
Test-Case 'Intune tenant identity scopes remain least privileged' {
    Assert-True ($global:IntuneReviewTest.config.Api.GraphScopes.Count -eq 11) 'Unexpected scope count.'
    Assert-True ($global:IntuneReviewTest.config.Api.GraphScopes -contains 'User.Read') 'Missing User.Read.'
    Assert-True ($global:IntuneReviewTest.config.Api.GraphScopes -notcontains 'Organization.Read.All') 'Unnecessary tenant identity scope escalation.'
}

Write-Host "$($global:IntuneReviewTest.passed) tests passed. Offline synthetic module execution only; no tenant validation."
Remove-Variable -Name IntuneReviewTest -Scope Global
