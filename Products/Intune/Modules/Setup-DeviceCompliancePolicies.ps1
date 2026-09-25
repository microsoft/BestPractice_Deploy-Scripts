#requires -Version 7.0
<#
.SYNOPSIS
    Per-platform device compliance policy assessment and deployment (guide task 7).

.DESCRIPTION
    Inventories existing Microsoft Graph v1.0 compliance policies, then creates
    the per-platform baseline compliance policies (Windows incl. Secure Boot and
    code integrity, iOS, Android work profile) from the payloads in
    DeviceCompliance.PayloadDirectory and assigns them to the pilot group or all
    licensed users.

    High risk: a new compliance policy can mark existing devices noncompliant and
    deny access where compliant-device Conditional Access is enforced. The write
    only runs when the orchestrator has cleared the item (IncludeHighRisk);
    otherwise the module assesses and reports without changing tenant state.
    Idempotent on display name; every change is gated by ShouldProcess, wrapped
    in the shared transient-retry boundary, and read back.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [switch] $AdoptExisting,
    [switch] $IncludeHighRisk
)

$ErrorActionPreference = 'Stop'
$ConfirmPreference = 'None'

. (Join-Path $PSScriptRoot 'IntuneRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'Get-IntunePolicyCatalog.ps1')
. (Join-Path $PSScriptRoot 'IntuneGraphClient.ps1')

function Get-ComplianceProperty {
    param([AllowNull()] $InputObject, [Parameter(Mandatory)] [string] $Name)

    $exists = $false
    $value = $null
    if ($null -eq $InputObject) {
        return [pscustomobject] @{ Exists = $exists; Value = $value }
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $exists = $InputObject.Contains($Name)
        if ($exists) { $value = $InputObject[$Name] }
        return [pscustomobject] @{ Exists = $exists; Value = $value }
    }
    $property = $InputObject.PSObject.Properties[$Name]
    $exists = $null -ne $property
    if ($exists) { $value = $property.Value }
    return [pscustomobject] @{ Exists = $exists; Value = $value }
}

function Get-ComplianceCollection {
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string] $InitialUri,
        [Parameter(Mandatory)] [string] $GraphBaseUri,
        [Parameter(Mandatory)] [string] $EvidenceTarget,
        [int[]] $ExpectedStatusCodes = @()
    )

    $base = [uri] $GraphBaseUri
    $pathPrefix = $base.AbsolutePath.TrimEnd('/') + '/'
    $visited = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $InitialUri

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        if (-not $visited.Add($nextUri)) {
            throw "Microsoft Graph returned a pagination cycle for $EvidenceTarget."
        }
        $parsed = $null
        if (-not [uri]::TryCreate($nextUri, [UriKind]::Absolute, [ref] $parsed) -or
            $parsed.Scheme -ne 'https' -or
            -not [string]::Equals($parsed.Host, $base.Host, [StringComparison]::OrdinalIgnoreCase) -or
            -not $parsed.AbsolutePath.StartsWith($pathPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Microsoft Graph returned an unsafe next link for $EvidenceTarget."
        }

        $response = Invoke-WithTransientRetry -Description "Get $EvidenceTarget" `
            -ExpectedStatusCodes $ExpectedStatusCodes -Action {
            try {
                Invoke-IntuneGraphRequest -Method 'GET' -Uri $nextUri `
                    -EvidenceTarget $EvidenceTarget `
                    -ExpectedStatusCodes $ExpectedStatusCodes `
                    -DeferFailureEvidence
            }
            catch {
                $status = Get-IntuneHttpStatusCode -ErrorRecord $_
                $safe = [Exception]::new("Microsoft Graph request failed for $EvidenceTarget.")
                if ($status) {
                    $safe | Add-Member -NotePropertyName Response `
                        -NotePropertyValue ([pscustomobject] @{ StatusCode = $status })
                }
                throw $safe
            }
        }
        $value = Get-ComplianceProperty -InputObject $response -Name 'value'
        if (-not $value.Exists -or $null -eq $value.Value) {
            throw "Microsoft Graph returned no value collection for $EvidenceTarget."
        }
        foreach ($item in @($value.Value)) {
            if ($null -eq $item) {
                throw "Microsoft Graph returned a null item for $EvidenceTarget."
            }
            $items.Add($item)
        }
        $next = Get-ComplianceProperty -InputObject $response -Name '@odata.nextLink'
        $nextUri = if ($next.Exists) { [string] $next.Value } else { $null }
    }
    return @($items)
}

$bestPracticeKey = 'device-compliance-policies'
if ($Context -and @($Context.BlockedItemKeys) -contains $bestPracticeKey) {
    Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
        -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
        -Status 'Skipped' -Disposition 'Skipped' `
        -Detail 'Skipped because preflight or operator gating blocked device-compliance-policies.'
    return
}

try {
    if (-not $Context -or
        [string]::IsNullOrWhiteSpace([string] $Context.TenantAdminUpn)) {
        throw 'Setup-DeviceCompliancePolicies.ps1 requires Context.TenantAdminUpn from a pre-authenticated Graph connection.'
    }

    $collectionUri = Resolve-IntuneGraphUri -BaseUri $Config.Api.GraphBaseUri `
        -RelativePath 'deviceManagement/deviceCompliancePolicies'
    $policies = @(Get-ComplianceCollection -InitialUri $collectionUri `
            -GraphBaseUri $Config.Api.GraphBaseUri `
            -EvidenceTarget 'device compliance policies')
    $catalogStatus = 'Available'
    try {
        $catalog = @(Get-IntunePolicyCatalog -Config $Config)
    }
    catch {
        $catalog = @()
        $catalogStatus = 'Unavailable'
        Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
            -Action 'CatalogAssessment' -BestPracticeKey $bestPracticeKey `
            -Status 'Info' `
            -Detail 'WARNING: Candidate policy catalog validation failed. Live tenant compliance inventory will continue without catalog counts.'
    }
    $complianceCandidates = @($catalog | Where-Object Kind -eq 'Compliance')
    $baselineCandidates = @(
        $complianceCandidates | Where-Object Tier -eq 'Baseline'
    )
    $advancedCandidates = @(
        $complianceCandidates | Where-Object Tier -eq 'Advanced'
    )
    $windowsCandidates = @(
        $complianceCandidates | Where-Object Tier -eq 'Windows'
    )

    $platformCounts = [ordered] @{
        AndroidDeviceAdministrator = 0
        AndroidWorkProfile = 0
        iOS = 0
        macOS = 0
        Windows = 0
        GuidedBeta = 0
        Unknown = 0
    }
    $assignmentCount = 0
    $scheduledActionCount = 0
    $scheduledActionReadback = 'Available'

    foreach ($policy in $policies) {
        $id = Get-ComplianceProperty -InputObject $policy -Name 'id'
        $type = Get-ComplianceProperty -InputObject $policy -Name '@odata.type'
        $parsedId = [guid]::Empty
        if (-not $id.Exists -or
            -not [guid]::TryParse([string] $id.Value, [ref] $parsedId) -or
            [string]::IsNullOrWhiteSpace([string] $type.Value)) {
            throw 'Microsoft Graph returned a malformed device compliance policy identity.'
        }

        switch -Regex ([string] $type.Value) {
            'androidCompliancePolicy$' { $platformCounts.AndroidDeviceAdministrator++; break }
            'androidWorkProfileCompliancePolicy$' { $platformCounts.AndroidWorkProfile++; break }
            'iosCompliancePolicy$' { $platformCounts.iOS++; break }
            'macOSCompliancePolicy$' { $platformCounts.macOS++; break }
            'windows10CompliancePolicy$' { $platformCounts.Windows++; break }
            '(androidDeviceOwner|aospDeviceOwner)CompliancePolicy$' {
                $platformCounts.GuidedBeta++
                break
            }
            default { $platformCounts.Unknown++ }
        }

        $assignmentUri = Resolve-IntuneGraphUri -BaseUri $Config.Api.GraphBaseUri `
            -RelativePath "deviceManagement/deviceCompliancePolicies/$($id.Value)/assignments"
        $assignmentCount += @(Get-ComplianceCollection -InitialUri $assignmentUri `
                -GraphBaseUri $Config.Api.GraphBaseUri `
                -EvidenceTarget 'device compliance policy assignments').Count

        if ($scheduledActionReadback -eq 'Available') {
            $actionsUri = Resolve-IntuneGraphUri -BaseUri $Config.Api.GraphBaseUri `
                -RelativePath "deviceManagement/deviceCompliancePolicies/$($id.Value)/scheduledActionsForRule"
            try {
                $scheduledActionCount += @(Get-ComplianceCollection -InitialUri $actionsUri `
                        -GraphBaseUri $Config.Api.GraphBaseUri `
                        -EvidenceTarget 'device compliance scheduled actions' `
                        -ExpectedStatusCodes @(400)).Count
            }
            catch {
                $status = Get-IntuneHttpStatusCode -ErrorRecord $_
                if ($status -ne 400) {
                    throw
                }
                $scheduledActionReadback = 'Unavailable'
                Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                    -Action 'ScheduledActionReadback' `
                    -BestPracticeKey $bestPracticeKey -Status 'Info' `
                    -HttpStatusCode $status `
                    -Detail 'Microsoft Graph v1.0 returned 400 because no GET route matched the documented scheduledActionsForRule relationship. Policy and assignment inventory will continue without a scheduled-action count.'
            }
        }
    }

    $scheduledActionCountText = if ($scheduledActionReadback -eq 'Available') {
        [string] $scheduledActionCount
    }
    else {
        'Unavailable'
    }
    $detail = 'PolicyCount={0}; AndroidDeviceAdministrator={1}; AndroidWorkProfile={2}; iOS={3}; macOS={4}; Windows={5}; GuidedBeta={6}; Unknown={7}; AssignmentCount={8}; ScheduledActionCount={9}; ScheduledActionReadback={10}; CatalogComplianceCandidates={11}; CatalogBaselineCandidates={12}; CatalogAdvancedCandidates={13}; CatalogWindowsCandidates={14}; CatalogStatus={15}; CatalogApplyStatus=Blocked; Assessment=InventoryOnly.' -f `
        $policies.Count,
        $platformCounts.AndroidDeviceAdministrator,
        $platformCounts.AndroidWorkProfile,
        $platformCounts.iOS,
        $platformCounts.macOS,
        $platformCounts.Windows,
        $platformCounts.GuidedBeta,
        $platformCounts.Unknown,
        $assignmentCount,
        $scheduledActionCountText,
        $scheduledActionReadback,
        $complianceCandidates.Count,
        $baselineCandidates.Count,
        $advancedCandidates.Count,
        $windowsCandidates.Count,
        $catalogStatus
    Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
        -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
        -Status 'Succeeded' -Disposition 'GuidedOnly' -Detail $detail

    # ---- Write phase ----
    if (@($Context.WriteBlockedItemKeys) -contains $bestPracticeKey -or
        -not $IncludeHighRisk -or
        -not [bool] $Context.IncludeHighRisk) {
        Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
            -Action 'CompliancePolicies' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'GuidedOnly' `
            -Detail 'Assessment only: creating compliance policies is withheld until IncludeHighRisk is supplied. A new compliance policy can mark devices noncompliant and deny access under compliant-device Conditional Access.'
        return
    }

    if ([string] $Context.AssignmentScope -eq 'TenantWide') {
        if ($Context.RollbackAcknowledged -ne $true) {
            $reason = 'Tenant-wide device compliance assignment requires Context.RollbackAcknowledged from the verified run context.'
            Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                -Action 'CompliancePolicies' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
                -Detail $reason
            throw $reason
        }
        if ($Config.Assignment.AllowTenantWideAssignmentForHighRisk -isnot [bool] -or
            -not $Config.Assignment.AllowTenantWideAssignmentForHighRisk) {
            $reason = 'Tenant-wide device compliance assignment is disabled by Assignment.AllowTenantWideAssignmentForHighRisk in configuration.'
            Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                -Action 'CompliancePolicies' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
                -Detail $reason
            throw $reason
        }
    }
    elseif ([string] $Context.AssignmentScope -ne 'PilotGroup' -or
        [string]::IsNullOrWhiteSpace([string] $Context.PilotGroupId)) {
        $reason = 'Device compliance policy creation requires a verified PilotGroup assignment scope and Context.PilotGroupId unless tenant-wide assignment was explicitly authorized.'
        Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
            -Action 'CompliancePolicies' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
            -Detail $reason
        throw $reason
    }

    $productRoot = Split-Path -Parent $PSScriptRoot
    $payloadDir = Join-Path $productRoot $Config.DeviceCompliance.PayloadDirectory
    $payloads = @(
        Get-ChildItem -LiteralPath $payloadDir -Filter *.json -File |
            Sort-Object Name |
            ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json }
    )
    $expectedNames = @($payloads | ForEach-Object displayName)
    $tag = $Config.ManagedByTag
    $existingNames = @{}
    foreach ($p in $policies) {
        $dn = Get-ComplianceProperty -InputObject $p -Name 'displayName'
        if ($dn.Exists -and $dn.Value) {
            $description = Get-ComplianceProperty -InputObject $p -Name 'description'
            $isManaged = $description.Exists -and
                $description.Value -is [string] -and
                ([string] $description.Value).Contains($tag, [StringComparison]::Ordinal)
            $name = [string] $dn.Value
            if ($isManaged -and $name -notin $expectedNames) {
                $reason = 'A toolkit-managed compliance policy has an unexpected name. Reconcile its recorded object ID and configured name before creating more policies; renamed managed objects are not duplicated.'
                Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                    -Action 'Collision' -BestPracticeKey $bestPracticeKey `
                    -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
                    -Detail $reason
                throw $reason
            }
            if (-not $existingNames.ContainsKey($name)) {
                $existingNames[$name] = [pscustomobject] @{
                    ManagedCount = 0
                    UnmanagedCount = 0
                }
            }
            if ($isManaged) {
                $existingNames[$name].ManagedCount++
            }
            else {
                $existingNames[$name].UnmanagedCount++
            }
        }
    }

    $assignmentTarget = $null
    $assignmentDetail = $null
    if ($Context.AssignmentScope -eq 'TenantWide') {
        $assignmentTarget = @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' }
        $assignmentDetail = 'all licensed users'
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string] $Context.PilotGroupId)) {
        $assignmentTarget = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $Context.PilotGroupId }
        $assignmentDetail = "pilot group $($Context.PilotGroupId)"
    }

    $createUri = Resolve-IntuneGraphUri -BaseUri $Config.Api.GraphBaseUri `
        -RelativePath 'deviceManagement/deviceCompliancePolicies'

    foreach ($payload in $payloads) {
        $dn = [string] $payload.displayName

        if ($existingNames.ContainsKey($dn) -and
            $existingNames[$dn].UnmanagedCount -gt 0) {
            $reason = "A compliance policy named '$dn' already exists but is not managed by the toolkit. Rename it or choose a different payload name; the create-only writer will not adopt or overwrite it."
            Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Target $dn `
                -Readback 'NotAttempted' -Detail $reason
            throw $reason
        }

        if ($existingNames.ContainsKey($dn) -and
            $existingNames[$dn].ManagedCount -gt 0) {
            Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Skipped' -Disposition 'AlreadyCompliant' -Target $dn -Readback 'Verified' `
                -Detail "A compliance policy named '$dn' already exists; leaving it unchanged. The current writer is create-only and does not refresh existing policies."
            continue
        }

        if ($payload.PSObject.Properties.Name -contains 'description') {
            $payload.description = ("$($payload.description) $tag").Trim()
        }
        else {
            $payload | Add-Member -NotePropertyName description -NotePropertyValue $tag -Force
        }

        if (-not $PSCmdlet.ShouldProcess($dn, 'Create device compliance policy and assign')) {
            Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Info' -Disposition 'WillChange' -Target $dn -Readback 'NotAttempted' `
                -Detail "WhatIf: would create compliance policy '$dn' and assign to $([string]::IsNullOrWhiteSpace($assignmentDetail) ? 'no target (none provided)' : $assignmentDetail)."
            continue
        }

        $created = $null
        try {
            $created = Invoke-WithTransientRetry -Description "Create compliance policy '$dn'" -Action {
                Invoke-MgGraphRequest -Method POST -Uri $createUri -Body ($payload | ConvertTo-Json -Depth 20) -ContentType 'application/json'
            }
            Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Created' -Disposition 'Applicable' -Target $dn `
                -Detail "Created device compliance policy '$dn'."
        }
        catch {
            Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                -Action 'Create' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Applicable' -Target $dn `
                -HttpStatusCode (Get-IntuneHttpStatusCode -ErrorRecord $_) `
                -Detail "Failed to create compliance policy '$dn': $($_.Exception.Message)"
            throw
        }

        $createdId = [string] $created.id
        if ([string]::IsNullOrWhiteSpace($createdId)) {
            throw "Microsoft Graph returned no ID for the created compliance policy '$dn'."
        }
        $encodedCreatedId = [uri]::EscapeDataString($createdId)

        if ($assignmentTarget) {
            $assignUri = Resolve-IntuneGraphUri -BaseUri $Config.Api.GraphBaseUri `
                -RelativePath "deviceManagement/deviceCompliancePolicies/$encodedCreatedId/assign"
            $assignBody = @{ assignments = @(@{ target = $assignmentTarget }) } | ConvertTo-Json -Depth 10
            try {
                Invoke-WithTransientRetry -Description "Assign compliance policy '$dn'" -Action {
                    Invoke-MgGraphRequest -Method POST -Uri $assignUri -Body $assignBody -ContentType 'application/json' | Out-Null
                }
                Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                    -Action 'Assign' -BestPracticeKey $bestPracticeKey `
                    -Status 'Succeeded' -Disposition 'Applicable' -Target $dn `
                    -Detail "Assigned '$dn' to $assignmentDetail."
            }
            catch {
                Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                    -Action 'Assign' -BestPracticeKey $bestPracticeKey `
                    -Status 'Failed' -Disposition 'Applicable' -Target $dn `
                    -HttpStatusCode (Get-IntuneHttpStatusCode -ErrorRecord $_) `
                    -Detail "Created '$dn' but failed to assign it: $($_.Exception.Message)"
                throw
            }
        }

        $readbackUri = Resolve-IntuneGraphUri -BaseUri $Config.Api.GraphBaseUri `
            -RelativePath "deviceManagement/deviceCompliancePolicies/$encodedCreatedId"
        try {
            $verify = Invoke-WithTransientRetry -Description "Read back compliance policy '$dn'" -Action {
                Invoke-MgGraphRequest -Method GET -Uri $readbackUri
            }
            $readback = if ($verify -and $verify.displayName -eq $dn) { 'Verified' } else { 'Mismatch' }
            if ($readback -ne 'Verified') {
                $reason = "Compliance policy readback did not confirm the configured display name '$dn'."
                Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                    -Action 'Readback' -BestPracticeKey $bestPracticeKey `
                    -Status 'Failed' -Disposition 'Blocked' -Target $dn -Readback $readback `
                    -Detail $reason
                throw $reason
            }
            Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                -Action 'Readback' -BestPracticeKey $bestPracticeKey `
                -Status 'Info' -Disposition 'Applicable' -Target $dn -Readback $readback `
                -Detail "Read-back returned displayName='$($verify.displayName)'."
        }
        catch {
            if ([string] $_.Exception.Message -eq "Compliance policy readback did not confirm the configured display name '$dn'.") {
                throw
            }
            Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
                -Action 'Readback' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Target $dn -Readback 'NotAttempted' `
                -Detail "Read-back could not be completed: $($_.Exception.Message)"
            throw
        }
    }
}
catch {
    $status = Get-IntuneHttpStatusCode -ErrorRecord $_
    Add-IntuneRunLogEntry -Module 'Setup-DeviceCompliancePolicies' `
        -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -HttpStatusCode $status `
        -Detail "Device compliance policy assessment failed. Reason=$($_.Exception.Message)"
    throw
}
