#requires -Version 7.0
<#
.SYNOPSIS
    Allowlisted read-only collectors for Purview configuration validation.

.DESCRIPTION
    Every collector reads tenant state and returns normalized managed fields
    plus optional unscored differences. No collector writes, and no collector
    executes a command name, property path, or script supplied by the
    Deployment Plan.

    Dispatch is a hardcoded switch keyed by the adapter identifiers in
    References/ValidationAdapters.psd1. The validation model derives an
    allowlisted adapter from schema 1.2 intended state; a plan cannot introduce
    one. Assert-PurviewValidationAdapterCoverage fails the run if the switch
    and the allowlist ever diverge.

    Transient read failures go through the shared retry boundary
    (Invoke-WithTransientRetry). A mismatch that survives the retries is drift,
    never a retry candidate.

    EXPORTS (via dot-source):
      * Assert-PurviewValidationAdapterCoverage
      * New-PurviewValidationContext
      * Get-PurviewValidationEntitlement
      * Invoke-PurviewValidationCollection
#>

Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'PurviewValidationModel.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

# Reads are retried far less aggressively than writes. A validation run is
# interactive and a half-read report is recoverable, so a long backoff buys
# nothing that a rerun does not.
$script:PurviewValidationReadAttempts = 3
$script:PurviewValidationReadBackoff = @(2, 5)

# Microsoft built-in sensitivity labels are created with an internal Name of
# 'defa4170-0d19-0005-NNNN-bc88714345d2'. The modern label scheme appends
# 'Group' to that Name for label groups. Both forms are the same identity.
$script:PurviewBuiltInLabelPattern = '^defa4170-0d19-0005-[0-9a-f]{4}-bc88714345d2$'

# The Microsoft Group.Unified directory-setting template, which is where
# EnableMIPLabels lives.
$script:PurviewGroupUnifiedTemplateId = '62375ab9-6b52-47ed-826b-58e47e0e304b'

# SKU part numbers recognized as entitlement evidence. These mirror
# Get-TenantPurviewLicenseTier in Deploy-PurviewBestPractice.ps1; the fixture
# Test-TenantConfigurationValidation.ps1 fails when the two lists drift apart.
$script:PurviewValidationE5Skus = @(
    'SPE_E5', 'SPE_E5_NOPSTNCONF', 'SPE_E5_CALLINGMINUTES',
    'SPE_E5_USGOV_GCCHIGH',
    'Microsoft_365_E5_(no_Teams)', 'Microsoft_365_E5_no_Teams', 'SPE_E5_NOPSTNCONF_no_Teams',
    'Microsoft_365_E5_EEA_(no_Teams)_with_Calling_Minutes',
    'Microsoft_365_E5_EEA_(no_Teams)_without_Audio_Conferencing',
    'ENTERPRISEPREMIUM', 'ENTERPRISEPREMIUM_NOPSTNCONF',
    'INFORMATION_PROTECTION_COMPLIANCE',
    'IDENTITY_THREAT_PROTECTION',
    'M365_E5_SUITE_COMPONENTS',
    'Microsoft_Purview_Suite',
    'INFORMATION_PROTECTION_AND_GOVERNANCE',
    'PURVIEW_SUITE_FOR_BUSINESS_PREMIUM',
    'PURVIEW_SUITE_FOR_BUSINESS_PREMIUM_NEW',
    'DEFENDER_AND_PURVIEW_SUITES_FOR_BUSINESS_PREMIUM',
    'DEFENDER_AND_PURVIEW_SUITES_FOR_BUSINESS_PREMIUM_NEW',
    'M365EDU_A5_FACULTY', 'M365EDU_A5_STUDENT', 'M365EDU_A5_STUUSEBNFT'
)
$script:PurviewValidationBpSkus = @(
    'SPB', 'BUSINESS_PREMIUM',
    'Microsoft_365_ Business_ Premium_(no Teams)',
    'Office_365_w/o_Teams_Bundle_Business_Premium',
    'Microsoft_365_Business_Premium_Donation_(Non_Profit_Pricing)'
)
$script:PurviewMicrosoft365CopilotLocationGuid =
    '470f2276-e011-4e9d-a6ec-20768be3a4b0'
$script:PurviewMicrosoft365CopilotLocationToken = 'Microsoft365Copilot'

function Get-PurviewValidationAdapterId {
    <#
        The adapter identifiers this file implements. Kept as a literal list so
        coverage can be asserted against the allowlist rather than inferred.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        'purview.tenant.audit-standard'
        'purview.tenant.spo-labels'
        'purview.tenant.pdf-labels'
        'purview.tenant.container-directory-setting'
        'purview.tenant.label-coauthoring'
        'purview.tenant.audit-premium'
        'purview.labels.taxonomy'
        'purview.labels.priority'
        'purview.labels.publish'
        'purview.labels.attachment-inheritance'
        'purview.labels.content-marking'
        'purview.labels.encryption'
        'purview.labels.container-scope'
        'purview.dlp.workload'
        'purview.retention.exchange'
        'purview.ai.copilot-dlp'
    )
}

function Get-PurviewValidationAdapterCapability {
    <#
        Session capabilities an adapter needs regardless of what the plan
        declares as its prerequisite.

        The container-label adapter, for example, declares a license
        prerequisite in the plan because entitlement is the operator-visible
        gate. It also needs the Graph beta directory-setting commands. Without
        this map a missing module would surface as a read failure rather than
        the 'Not evaluated' the contract requires.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $AdapterId)

    switch ($AdapterId) {
        'purview.tenant.spo-labels' { return 'SharePointOnlineSession' }
        'purview.tenant.pdf-labels' { return 'SharePointOnlineSession' }
        'purview.tenant.container-directory-setting' { return 'GraphDirectorySettings' }
        default { return '' }
    }
}

function Assert-PurviewValidationAdapterCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Allowlist
    )

    $declared = @(@($Allowlist['Adapters']) | ForEach-Object { [string]$_['Id'] } | Sort-Object)
    $implemented = @(Get-PurviewValidationAdapterId | Sort-Object)

    $difference = @(Compare-Object -ReferenceObject $declared -DifferenceObject $implemented)
    if ($difference.Count -gt 0) {
        $detail = ($difference | ForEach-Object {
            if ($_.SideIndicator -eq '<=') { "allowlisted but not implemented: $($_.InputObject)" }
            else { "implemented but not allowlisted: $($_.InputObject)" }
        }) -join '; '
        throw "Validation adapter coverage mismatch. $detail"
    }
}

function ConvertTo-PurviewValidationBoolean {
    [CmdletBinding()]
    param([Parameter()] [AllowNull()] [object] $Value)

    if ($Value -is [bool]) { return [bool]$Value }
    if ($Value -is [string]) {
        $parsed = $false
        if ([bool]::TryParse($Value.Trim(), [ref]$parsed)) { return $parsed }
        return '__invalid_boolean__'
    }
    if ($null -eq $Value) { return $false }
    return [bool]$Value
}

function Get-PurviewValidationLiveLabelSignature {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [AllowNull()] [object] $Label,
        [Parameter()] [AllowNull()] [object[]] $IntendedLabels = @(),
        [Parameter()] [AllowNull()] [hashtable] $LabelsById = $null
    )

    if (-not $Label) { return '' }
    $name = [string]$Label.Name
    if ([string]::IsNullOrWhiteSpace($name)) { return '' }

    $candidate = $name.Trim()
    if ($candidate -match '(?i)^(defa4170-0d19-0005-[0-9a-f]{4}-bc88714345d2)Group$') {
        $candidate = $Matches[1]
    }
    if ($candidate -match "(?i)$script:PurviewBuiltInLabelPattern") {
        return 'builtin:' + $candidate.ToLowerInvariant()
    }

    $parentKey = ''
    $parentHashName = ''
    if ($Label.PSObject.Properties['ParentId'] -and $Label.ParentId -and $LabelsById) {
        $parentId = [string]$Label.ParentId
        if ($LabelsById.ContainsKey($parentId)) {
            $parentLabel = $LabelsById[$parentId]
            $parentHashName = ([string]$parentLabel.Name).Trim()
            $parentKey = Get-PurviewValidationLiveLabelSignature `
                -Label $parentLabel `
                -IntendedLabels $IntendedLabels `
                -LabelsById $LabelsById
            $intendedParent = @($IntendedLabels | Where-Object {
                [string]$_.Key -eq $parentKey
            }) | Select-Object -First 1
            if ($intendedParent -and
                [string]$intendedParent.Name -and
                [string]$intendedParent.Name -notmatch '^\[REDACTED-') {
                $parentHashName = [string]$intendedParent.Name
            }
        }
    }

    foreach ($intended in @($IntendedLabels)) {
        if ($parentKey) {
            if ([string]$intended.ParentKey -eq $parentKey -and
                [string]$intended.Name -eq $candidate) {
                return [string]$intended.Key
            }
        } elseif (-not [string]$intended.ParentKey -and
            [string]$intended.Name -eq $candidate) {
            return [string]$intended.Key
        }
    }

    $hashInput = if ($parentHashName) {
        "$($parentHashName.Trim().ToLowerInvariant())/$($candidate.Trim().ToLowerInvariant())"
    } else {
        $candidate.Trim().ToLowerInvariant()
    }
    $digest = Get-PurviewValidationOpaqueDigest -Value $hashInput
    return 'custom:' + ($digest -replace '^sha256:', '')
}

function Test-PurviewValidationLabelUsable {
    <#
        Soft-deleted labels stay in Get-Label output with Mode='PendingDeletion'
        for about 30 days. Counting them would report a taxonomy as present
        when it is in fact a tombstone.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] [object] $Label
    )

    if (-not $Label) { return $false }
    if ($Label.PSObject.Properties['Mode'] -and [string]$Label.Mode -eq 'PendingDeletion') { return $false }
    if ($Label.PSObject.Properties['Disabled'] -and [bool]$Label.Disabled) { return $false }
    return $true
}

function Test-PurviewValidationManaged {
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] [object] $Object,
        [Parameter()] [string] $Tag
    )

    if (-not $Object) { return $false }
    if ([string]::IsNullOrWhiteSpace($Tag)) { return $true }
    if (-not $Object.PSObject.Properties['Comment']) { return $false }
    return ([string]$Object.Comment).Contains($Tag, [StringComparison]::OrdinalIgnoreCase)
}

function Get-PurviewValidationManagedLabel {
    <#
        Splits a tenant's labels into the ones this toolkit manages and the
        ones it does not.

        Scoring across every label in the tenant was the single largest source
        of false drift: a customer who had labels before onboarding, or who
        adds "Board Confidential" afterwards, would fail taxonomy, priority,
        encryption, content marking, and container scope on the next run. The
        toolkit stamps its own labels' Comment with the managed tag, so
        ownership is decidable.

        Soft-deleted labels stay in Get-Label output for about 30 days with
        Mode 'PendingDeletion'. Counting a tombstone as present would report a
        deleted taxonomy as healthy.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] [object] $Labels,
        [Parameter()] [string] $ManagedByTag = ''
    )

    $usable = @($Labels | Where-Object { Test-PurviewValidationLabelUsable -Label $_ })
    $tombstoned = @($Labels | Where-Object { $_ -and -not (Test-PurviewValidationLabelUsable -Label $_) })
    $managed = @($usable | Where-Object { Test-PurviewValidationManaged -Object $_ -Tag $ManagedByTag })
    $unmanaged = @($usable | Where-Object { -not (Test-PurviewValidationManaged -Object $_ -Tag $ManagedByTag) })

    return [pscustomobject]@{
        Managed = $managed
        Unmanaged = $unmanaged
        Tombstoned = $tombstoned
    }
}

function Get-PurviewValidationLabelById {
    [CmdletBinding()]
    param([Parameter()] [AllowNull()] [object] $Labels)

    $labelsById = @{}
    foreach ($label in @($Labels)) {
        if ($label -and $label.PSObject.Properties['Guid']) {
            $labelsById[[string]$label.Guid] = $label
        }
    }
    return $labelsById
}

function New-PurviewValidationLabelContextNote {
    <#
        Turns the labels outside the toolkit's ownership into unscored context
        so an operator can see them without the report failing them.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [psobject] $Partition)

    $notes = [Collections.Generic.List[object]]::new()
    if (@($Partition.Unmanaged).Count -gt 0) {
        $notes.Add([pscustomobject]@{
            Field = 'UnmanagedLabels'
            Expected = 'not scored'
            Observed = "$(@($Partition.Unmanaged).Count) label(s) not managed by the toolkit"
        })
    }
    if (@($Partition.Tombstoned).Count -gt 0) {
        $notes.Add([pscustomobject]@{
            Field = 'SoftDeletedLabels'
            Expected = 'none'
            Observed = "$(@($Partition.Tombstoned).Count) label(s) pending deletion"
        })
    }
    return $notes.ToArray()
}

function New-PurviewValidationContext {
    <#
        Holds per-run caches, resolved entitlement, and session capability
        state so a shared read such as Get-Label happens once for all seven
        label adapters.

        Capabilities come from the connection result, not from command
        availability. The SharePoint module is imported before the connection
        is attempted, so a failed Connect-SPOService still leaves Get-SPOTenant
        defined. Trusting command presence would report a read failure where
        the contract requires 'Not evaluated'.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [string] $ManagedByTag = '',
        [Parameter()] [AllowNull()] [psobject] $Entitlement = $null,
        [Parameter()] [System.Collections.IDictionary] $Capabilities = @{},
        [Parameter()] [object[]] $IntendedLabels = @()
    )

    return [pscustomobject]@{
        ManagedByTag = $ManagedByTag
        Entitlement = $Entitlement
        Capabilities = $Capabilities
        IntendedLabels = @($IntendedLabels)
        Cache = @{}
    }
}

function Invoke-PurviewValidationRead {
    <#
        Runs one tenant read through the shared retry boundary and reports how
        many attempts it took, so the report can distinguish a clean read from
        one that only succeeded after a transient failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Description,
        [Parameter(Mandatory)] [scriptblock] $Read,
        [Parameter()] [string] $Module = 'Test-PurviewTenantConfiguration'
    )

    $counter = [pscustomobject]@{ Attempts = 0 }
    $resultState = [pscustomobject]@{ Value = $null }
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $action = {
        $counter.Attempts++
        $attemptValue = @(& $Read)
        $resultState.Value = if ($attemptValue.Count -eq 0) {
            $null
        } elseif ($attemptValue.Count -eq 1) {
            $attemptValue[0]
        } else {
            $attemptValue
        }
    }.GetNewClosure()

    try {
        $null = Invoke-WithTransientRetry `
            -Description $Description `
            -Module $Module `
            -MaxAttempts $script:PurviewValidationReadAttempts `
            -BackoffSeconds $script:PurviewValidationReadBackoff `
            -Action $action
    } finally {
        $stopwatch.Stop()
    }

    return [pscustomobject]@{
        Value = $resultState.Value
        Attempts = [int]$counter.Attempts
        ElapsedMs = [int]$stopwatch.ElapsedMilliseconds
    }
}

function Get-PurviewValidationCachedRead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Context,
        [Parameter(Mandatory)] [string] $Key,
        [Parameter(Mandatory)] [string] $Description,
        [Parameter(Mandatory)] [scriptblock] $Read
    )

    if ($Context.Cache.ContainsKey($Key)) {
        $cached = $Context.Cache[$Key]
        if ($cached.Failure) { throw $cached.Failure }
        return $cached
    }

    try {
        $result = Invoke-PurviewValidationRead -Description $Description -Read $Read
        $entry = [pscustomobject]@{
            Value = $result.Value
            Attempts = $result.Attempts
            ElapsedMs = $result.ElapsedMs
            Failure = $null
        }
        $Context.Cache[$Key] = $entry
        return $entry
    } catch {
        $Context.Cache[$Key] = [pscustomobject]@{
            Value = $null
            Attempts = $script:PurviewValidationReadAttempts
            ElapsedMs = 0
            Failure = $_.Exception.Message
        }
        throw
    }
}

function Resolve-PurviewValidationCommand {
    <#
        Both Exchange Online and Security & Compliance PowerShell expose
        Get-AdminAuditLogConfig, but only Exchange Online reports the real
        UnifiedAuditLogIngestionEnabled value: the Security & Compliance copy
        always returns False. Because the toolkit connects Security &
        Compliance after Exchange Online, a bare call can bind to the wrong
        session and report drift on a correctly configured tenant.

        Reference: Get-AdminAuditLogConfig, Exchange PowerShell (verified
        2026-08-14).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter()] [string] $SiblingWriteCommand = ''
    )

    if ($SiblingWriteCommand) {
        $writeCommand = Get-Command -Name $SiblingWriteCommand -ErrorAction SilentlyContinue
        if ($writeCommand) {
            $matched = Get-Command -Name $Name -All -ErrorAction SilentlyContinue |
                Where-Object { $_.Source -eq $writeCommand.Source } |
                Select-Object -First 1
            if ($matched) { return $matched }
        }
        return $null
    }

    return Get-Command -Name $Name -ErrorAction SilentlyContinue
}

function Get-PurviewValidationEntitlement {
    <#
        Reads /subscribedSkus once and classifies the tenant.

        A tenant that cannot be classified is reported as 'Unknown'. The
        workload collector is still allowed to read because some services can
        prove support without license inventory. A tenant that is classified
        as not entitled is the only license state that blocks scoring.
    #>
    [CmdletBinding()]
    param()

    $result = [pscustomobject]@{
        Tier = 'Unknown'
        Reason = ''
        Available = $false
    }

    if (-not (Get-Command -Name 'Invoke-MgGraphRequest' -ErrorAction SilentlyContinue)) {
        $result.Reason = 'Microsoft Graph session is not available.'
        return $result
    }

    try {
        $read = Invoke-PurviewValidationRead -Description 'GET /subscribedSkus' -Read {
            Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' -ErrorAction Stop
        }
        $response = $read.Value
    } catch {
        $result.Reason = ConvertTo-PurviewValidationRedactedText -Text (
            'Subscribed SKU query failed: ' + $_.Exception.Message)
        return $result
    }

    if (-not $response -or -not $response.value) {
        $result.Reason = 'Subscribed SKU response was empty.'
        return $result
    }

    $partNumbers = @(
        $response.value |
            Where-Object { $_.capabilityStatus -ne 'Suspended' -and $_.capabilityStatus -ne 'Deleted' } |
            ForEach-Object { [string]$_.skuPartNumber } |
            Where-Object { $_ }
    )

    $result.Available = $true
    if (@($partNumbers | Where-Object { $_ -in $script:PurviewValidationE5Skus }).Count -gt 0) {
        $result.Tier = 'E5OrPurviewSuite'
        $result.Reason = 'A Microsoft 365 E5 or Purview Suite SKU is present.'
        return $result
    }
    if (@($partNumbers | Where-Object { $_ -in $script:PurviewValidationBpSkus }).Count -gt 0) {
        $result.Tier = 'BusinessPremium'
        $result.Reason = 'A Microsoft 365 Business Premium SKU is present.'
        return $result
    }

    $result.Tier = 'Other'
    $result.Reason = 'No recognized Business Premium, E5, or Purview Suite SKU is present.'
    return $result
}

function Test-PurviewValidationPrerequisite {
    <#
        Resolves a declared prerequisite to Satisfied, Unsatisfied, or Unknown.

        'Unsatisfied' produces 'Not evaluated'. 'Unknown' license inventory
        does not block collection, because a workload read can prove support
        without requiring license-assignment scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Context,
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter()] [string] $Id = ''
    )

    if ($Kind -eq 'None') {
        return [pscustomobject]@{ State = 'Satisfied'; Detail = 'No prerequisite declared.' }
    }

    if ($Kind -eq 'Capability') {
        # The connection result is authoritative. Command availability is only
        # a fallback for direct callers that supplied no capability state.
        $capabilities = if ($Context.PSObject.Properties['Capabilities'] -and $Context.Capabilities) {
            $Context.Capabilities
        } else {
            @{}
        }
        if ($capabilities.Contains($Id)) {
            if ([bool]$capabilities[$Id]) {
                return [pscustomobject]@{ State = 'Satisfied'; Detail = "The '$Id' session is available." }
            }
            return [pscustomobject]@{
                State = 'Unsatisfied'
                Detail = "The '$Id' session was not established, so this setting could not be read."
            }
        }

        switch ($Id) {
            'SharePointOnlineSession' {
                if (Get-Command -Name 'Get-SPOTenant' -ErrorAction SilentlyContinue) {
                    return [pscustomobject]@{ State = 'Satisfied'; Detail = 'SharePoint Online session is available.' }
                }
                return [pscustomobject]@{
                    State = 'Unsatisfied'
                    Detail = 'No SharePoint Online session is available, so the tenant setting could not be read.'
                }
            }
            'GraphDirectorySettings' {
                if (Get-Command -Name 'Get-MgBetaDirectorySetting' -ErrorAction SilentlyContinue) {
                    return [pscustomobject]@{ State = 'Satisfied'; Detail = 'Graph directory-setting commands are available.' }
                }
                return [pscustomobject]@{
                    State = 'Unsatisfied'
                    Detail = 'Graph directory-setting commands are not available in this session.'
                }
            }
            default {
                return [pscustomobject]@{ State = 'Unknown'; Detail = "Unrecognized capability prerequisite '$Id'." }
            }
        }
    }

    $entitlement = $Context.Entitlement
    $entitlementAvailable = $entitlement -and
        $entitlement.PSObject.Properties['Available'] -and
        [bool]$entitlement.Available
    if (-not $entitlementAvailable) {
        $detail = if ($entitlement -and $entitlement.Reason) { $entitlement.Reason } else { 'Entitlement could not be read.' }
        return [pscustomobject]@{
            State = 'Satisfied'
            Detail = "$detail Continuing with workload read because license inventory is unavailable."
        }
    }

    $tier = [string]$entitlement.Tier
    $satisfied = switch ($Id) {
        'BusinessPremiumOrHigher' { $tier -in @('BusinessPremium', 'E5OrPurviewSuite') }
        'E5OrPurviewSuite' { $tier -eq 'E5OrPurviewSuite' }
        'AuditPremium' { $tier -eq 'E5OrPurviewSuite' }
        default { $false }
    }

    if ($satisfied) {
        return [pscustomobject]@{ State = 'Satisfied'; Detail = $entitlement.Reason }
    }

    return [pscustomobject]@{
        State = 'Unsatisfied'
        Detail = "The '$Id' prerequisite is not satisfied. $($entitlement.Reason)"
    }
}

function Get-PurviewValidationLabelSet {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [psobject] $Context)

    return Get-PurviewValidationCachedRead -Context $Context -Key 'labels' `
        -Description 'Get-Label' -Read { Get-Label -ErrorAction Stop }
}

function Get-PurviewValidationLabelPolicySet {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [psobject] $Context)

    return Get-PurviewValidationCachedRead -Context $Context -Key 'label-policies' `
        -Description 'Get-LabelPolicy' -Read { Get-LabelPolicy -ErrorAction Stop }
}

function Get-PurviewValidationDlpPolicySet {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [psobject] $Context)

    return Get-PurviewValidationCachedRead -Context $Context -Key 'dlp-policies' `
        -Description 'Get-DlpCompliancePolicy' -Read { Get-DlpCompliancePolicy -ErrorAction Stop }
}

function Get-PurviewValidationDlpRuleSet {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [psobject] $Context)

    return Get-PurviewValidationCachedRead -Context $Context -Key 'dlp-rules' `
        -Description 'Get-DlpComplianceRule' -Read { Get-DlpComplianceRule -ErrorAction Stop }
}

function Get-PurviewValidationLabelAdvancedSetting {
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] [object] $Object,
        [Parameter(Mandatory)] [string] $Name
    )

    if (-not $Object -or -not $Object.PSObject.Properties['Settings']) { return '' }
    if ($Object.Settings -is [System.Collections.IDictionary]) {
        foreach ($key in @($Object.Settings.Keys)) {
            if ([string]$key -ieq $Name) { return [string]$Object.Settings[$key] }
        }
    }
    foreach ($setting in @($Object.Settings)) {
        if (-not $setting) { continue }
        if ($setting -is [System.Collections.IDictionary]) {
            $key = if ($setting.Contains('key')) { [string]$setting['key'] } elseif ($setting.Contains('Key')) { [string]$setting['Key'] } elseif ($setting.Contains('Name')) { [string]$setting['Name'] } else { '' }
            $value = if ($setting.Contains('value')) { [string]$setting['value'] } elseif ($setting.Contains('Value')) { [string]$setting['Value'] } else { '' }
            if ($key -ieq $Name) { return $value }
            continue
        }
        if ($setting.PSObject.Properties['Key'] -and ([string]$setting.Key) -ieq $Name) {
            return [string]$setting.Value
        }
        if ($setting.PSObject.Properties['Name'] -and ([string]$setting.Name) -ieq $Name) {
            return [string]$setting.Value
        }
        $rendered = [string]$setting
        if ($rendered -match '^\s*\[\s*([^,\]]+?)\s*,\s*(.*?)\s*\]\s*$') {
            if ([string]$Matches[1] -ieq $Name) { return [string]$Matches[2] }
            continue
        }
        $parts = @($rendered -split '\s*[:=]\s*', 2)
        if ($parts.Count -eq 2 -and [string]$parts[0] -ieq $Name) {
            return [string]$parts[1]
        }
    }
    return ''
}

function Measure-PurviewValidationRuleLabel {
    <#
        Counts sensitivity-label operands on a persisted DLP rule.

        Non-endpoint rules store them under ContentContainsSensitiveInformation;
        endpoint rules store the same operands inside AdvancedRule JSON. A
        persisted operand legitimately shows name and id as the same GUID.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter()] [AllowNull()] [object] $Rule
    )

    if (-not $Rule) { return 0 }

    $count = 0
    if ($Rule.PSObject.Properties['ContentContainsSensitiveInformation'] -and
        $Rule.ContentContainsSensitiveInformation) {
        foreach ($group in @($Rule.ContentContainsSensitiveInformation.groups)) {
            if (-not $group) { continue }
            $count += @($group.labels).Count
        }
    }

    if ($count -eq 0 -and $Rule.PSObject.Properties['AdvancedRule'] -and $Rule.AdvancedRule) {
        try {
            $advanced = [string]$Rule.AdvancedRule | ConvertFrom-Json -Depth 20
            foreach ($subCondition in @($advanced.Condition.SubConditions)) {
                foreach ($value in @($subCondition.Value)) {
                    foreach ($group in @($value.Groups)) {
                        $count += @($group.Labels).Count
                    }
                }
            }
        } catch {
            Write-Verbose "AdvancedRule could not be parsed: $($_.Exception.Message)"
        }
    }

    return [int]$count
}

function Get-PurviewValidationRuleLabelSignature {
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] [object] $Rule,
        [Parameter()] [AllowNull()] [hashtable] $LabelsById = $null,
        [Parameter()] [object[]] $IntendedLabels = @()
    )

    if (-not $Rule) { return @() }

    $ids = [Collections.Generic.List[string]]::new()
    if ($Rule.PSObject.Properties['ContentContainsSensitiveInformation'] -and
        $Rule.ContentContainsSensitiveInformation) {
        foreach ($group in @($Rule.ContentContainsSensitiveInformation.groups)) {
            if (-not $group) { continue }
            foreach ($label in @($group.labels)) {
                if (-not $label) { continue }
                $value = if ($label.PSObject.Properties['name']) {
                    [string]$label.name
                } elseif ($label.PSObject.Properties['id']) {
                    [string]$label.id
                } else { [string]$label }
                if ($value) { $ids.Add($value) }
            }
        }
    }
    if ($Rule.PSObject.Properties['AdvancedRule'] -and $Rule.AdvancedRule) {
        try {
            $advanced = [string]$Rule.AdvancedRule | ConvertFrom-Json -Depth 20
            foreach ($subCondition in @($advanced.Condition.SubConditions)) {
                foreach ($value in @($subCondition.Value)) {
                    foreach ($group in @($value.Groups)) {
                        foreach ($label in @($group.Labels)) {
                            $value = if ($label.PSObject.Properties['name']) {
                                [string]$label.name
                            } elseif ($label.PSObject.Properties['id']) {
                                [string]$label.id
                            } else { [string]$label }
                            if ($value) { $ids.Add($value) }
                        }
                    }
                }
            }
        } catch {
            Write-Verbose "AdvancedRule could not be parsed: $($_.Exception.Message)"
        }
    }

    return @(
        foreach ($id in @($ids | Sort-Object -Unique)) {
            if ($LabelsById -and $LabelsById.ContainsKey($id)) {
                Get-PurviewValidationLiveLabelSignature `
                    -Label $LabelsById[$id] `
                    -IntendedLabels $IntendedLabels `
                    -LabelsById $LabelsById
            } else {
                'unknown:' + ((Get-PurviewValidationOpaqueDigest -Value $id) -replace '^sha256:', '')
            }
        }
    )
}

function Select-PurviewValidationDlpPolicy {
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] [object] $Policies,
        [Parameter(Mandatory)] [string] $Selector,
        [Parameter()] [string] $ManagedByTag = ''
    )

    $workloadPattern = switch ($Selector) {
        'Exchange' { '(?i)exchange' }
        'SharePointOneDrive' { '(?i)sharepoint|onedrive' }
        'Endpoint' { '(?i)endpoint|devices' }
        default { '(?i)' + [regex]::Escape($Selector) }
    }

    $candidates = @(
        foreach ($policy in @($Policies)) {
            if (-not $policy) { continue }
            if (-not (Test-PurviewValidationManaged -Object $policy -Tag $ManagedByTag)) { continue }
            $workload = if ($policy.PSObject.Properties['Workload']) { [string]$policy.Workload } else { '' }
            if ($workload -match $workloadPattern) { $policy }
        }
    )

    foreach ($candidate in $candidates) { $candidate }
}

function Get-PurviewValidationOpaqueDigest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Value)

    $bytes = [Text.Encoding]::UTF8.GetBytes($Value.Trim().ToLowerInvariant())
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return 'sha256:' + ([Convert]::ToHexString($hash).ToLowerInvariant()).Substring(0, 24)
}

function Get-PurviewValidationIdentityClass {
    [CmdletBinding()]
    param([Parameter()][AllowEmptyString()][string] $Identity)

    if ([string]::IsNullOrWhiteSpace($Identity)) { return 'Empty' }
    if ($Identity -eq 'All') { return 'All' }
    return 'CustomPrincipal'
}

function ConvertTo-PurviewValidationPublicLocation {
    [CmdletBinding()]
    param([Parameter()][AllowEmptyString()][string] $Value)

    if ($Value -ieq $script:PurviewMicrosoft365CopilotLocationGuid) {
        return $script:PurviewMicrosoft365CopilotLocationToken
    }
    return $Value
}

function Get-PurviewValidationLocationIdentity {
    [CmdletBinding()]
    param([Parameter()][AllowEmptyString()][string] $Value)

    $candidate = $Value.Trim()
    $canonical = ConvertTo-PurviewValidationPublicLocation -Value $candidate
    if ($canonical -eq $script:PurviewMicrosoft365CopilotLocationToken) {
        return [pscustomobject]@{
            Value = $canonical
            Class = 'PublicProductLocation'
            Digest = ''
        }
    }
    if (-not $candidate) {
        return [pscustomobject]@{
            Value = ''
            Class = 'Empty'
            Digest = ''
        }
    }
    return [pscustomobject]@{
        Value = ''
        Class = 'CustomLocation'
        Digest = Get-PurviewValidationOpaqueDigest -Value $candidate
    }
}

function Get-PurviewValidationAiScopeSet {
    [CmdletBinding()]
    param([Parameter()][object[]] $Policies)

    $scopeItems = @(
        foreach ($policy in @($Policies)) {
            foreach ($location in @($policy.Locations)) {
                $workload = if ($location -is [System.Collections.IDictionary]) {
                    [string]$location['Workload']
                } elseif ($location.PSObject.Properties['Workload']) {
                    [string]$location.Workload
                } else { '' }
                $target = if ($location -is [System.Collections.IDictionary]) {
                    [string]$location['Location']
                } elseif ($location.PSObject.Properties['Location']) {
                    [string]$location.Location
                } else { '' }
                $locationClass = if ($location -is [System.Collections.IDictionary]) {
                    [string]$location['LocationClass']
                } elseif ($location.PSObject.Properties['LocationClass']) {
                    [string]$location.LocationClass
                } else { '' }
                $locationDigest = if ($location -is [System.Collections.IDictionary]) {
                    [string]$location['LocationDigest']
                } elseif ($location.PSObject.Properties['LocationDigest']) {
                    [string]$location.LocationDigest
                } else { '' }
                if (-not $locationClass) {
                    $identity = Get-PurviewValidationLocationIdentity -Value $target
                    $locationClass = [string]$identity.Class
                    $locationDigest = [string]$identity.Digest
                    $target = [string]$identity.Value
                } elseif ($locationClass -ne 'PublicProductLocation') {
                    $target = ''
                }
                $locationKey = "{0}|{1}|{2}|{3}" -f $workload.ToLowerInvariant(), $locationClass.ToLowerInvariant(), $locationDigest.ToLowerInvariant(), $target.ToLowerInvariant()
                $entryCount = 0
                foreach ($kind in @('Inclusions', 'Exclusions')) {
                    $scopeKind = if ($kind -eq 'Inclusions') { 'include' } else { 'exclude' }
                    $items = if ($location -is [System.Collections.IDictionary]) {
                        @($location[$kind])
                    } elseif ($location.PSObject.Properties[$kind]) {
                        @($location.$kind)
                    } else { @() }
                    $entryCount += @($items).Count
                    foreach ($item in @($items)) {
                        $type = if ($item -is [System.Collections.IDictionary]) {
                            [string]$item['Type']
                        } elseif ($item.PSObject.Properties['Type']) {
                            [string]$item.Type
                        } else { '' }
                        $identity = if ($item -is [System.Collections.IDictionary]) {
                            [string]$item['Identity']
                        } elseif ($item.PSObject.Properties['Identity']) {
                            [string]$item.Identity
                        } else { '' }
                        $class = Get-PurviewValidationIdentityClass -Identity $identity
                        $digest = if ($class -eq 'All' -or $class -eq 'Empty') {
                            ''
                        } else {
                            Get-PurviewValidationOpaqueDigest -Value $identity
                        }
                        "{0}|{1}|{2}|{3}|{4}" -f $scopeKind, $locationKey, $type, $class, $digest
                    }
                }
                if ($entryCount -eq 0) {
                    "scope|$locationKey"
                }
            }
        }
    )
    return @(
        $scopeItems |
            ForEach-Object { ([string]$_).ToLowerInvariant() } |
            Sort-Object -Unique
    )
}

function Invoke-PurviewValidationAdapter {
    <#
        The only dispatch point. The switch is hardcoded and exhaustive; the
        plan selects a branch by allowlisted identifier and nothing more.

        Every branch returns:
          Observed  hashtable of managed field name to normalized value
          Unscored  redacted differences that are recorded but not scored
          Query     the read attribution shown in the report
          Source    the PowerShell module that answered the read
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Context,
        [Parameter(Mandatory)] [string] $AdapterId,
        [Parameter()] [string] $Selector = ''
    )

    $tag = [string]$Context.ManagedByTag
    $intendedLabels = @($Context.IntendedLabels)
    $unscored = [Collections.Generic.List[object]]::new()

    switch ($AdapterId) {
        'purview.tenant.audit-standard' {
            $command = Resolve-PurviewValidationCommand -Name 'Get-AdminAuditLogConfig' `
                -SiblingWriteCommand 'Set-AdminAuditLogConfig'
            if (-not $command) { throw 'Get-AdminAuditLogConfig is not available in this session.' }
            $read = Invoke-PurviewValidationRead -Description 'Get-AdminAuditLogConfig' -Read {
                & $command -ErrorAction Stop
            }.GetNewClosure()
            $config = $read.Value
            return [pscustomobject]@{
                Observed = @{
                    UnifiedAuditLogIngestionEnabled = ConvertTo-PurviewValidationBoolean $config.UnifiedAuditLogIngestionEnabled
                }
                Unscored = @()
                Query = 'Get-AdminAuditLogConfig'
                Source = [string]$command.Source
                Attempts = $read.Attempts
                ElapsedMs = $read.ElapsedMs
            }
        }

        'purview.tenant.spo-labels' {
            $read = Get-PurviewValidationCachedRead -Context $Context -Key 'spo-tenant' `
                -Description 'Get-SPOTenant' -Read { Get-SPOTenant -ErrorAction Stop }
            $tenant = $read.Value
            return [pscustomobject]@{
                Observed = @{ EnableAIPIntegration = ConvertTo-PurviewValidationBoolean $tenant.EnableAIPIntegration }
                Unscored = @()
                Query = 'Get-SPOTenant'
                Source = 'Microsoft.Online.SharePoint.PowerShell'
                Attempts = $read.Attempts
                ElapsedMs = $read.ElapsedMs
            }
        }

        'purview.tenant.pdf-labels' {
            $read = Get-PurviewValidationCachedRead -Context $Context -Key 'spo-tenant' `
                -Description 'Get-SPOTenant' -Read { Get-SPOTenant -ErrorAction Stop }
            $tenant = $read.Value
            # Newer SharePoint Online builds removed the parameter because PDF
            # labelling became built in. An absent property is reported as
            # unscored context rather than silently treated as disabled.
            if (-not $tenant.PSObject.Properties['EnableSensitivityLabelforPDF']) {
                # Newer SharePoint Online builds removed the parameter because
                # PDF labelling became built in, but an absent property could
                # also mean something unexpected about this tenant or module
                # version. Reporting it as satisfied would be a guess, so the
                # action is left unevaluated with the reason recorded.
                return [pscustomobject]@{
                    Observed = @{}
                    Unscored = @([pscustomobject]@{
                        Field = 'EnableSensitivityLabelforPDF'
                        Expected = 'property present'
                        Observed = 'property absent from Get-SPOTenant'
                    })
                    NotEvaluated = $true
                    NotEvaluatedReason = 'Get-SPOTenant did not return EnableSensitivityLabelforPDF. Newer SharePoint Online builds removed the parameter because PDF labelling is built in; confirm the module version before treating this as drift.'
                    Query = 'Get-SPOTenant'
                    Source = 'Microsoft.Online.SharePoint.PowerShell'
                    Attempts = $read.Attempts
                    ElapsedMs = $read.ElapsedMs
                }
            }
            return [pscustomobject]@{
                Observed = @{
                    EnableSensitivityLabelForPDF = ConvertTo-PurviewValidationBoolean $tenant.EnableSensitivityLabelforPDF
                }
                Unscored = @()
                Query = 'Get-SPOTenant'
                Source = 'Microsoft.Online.SharePoint.PowerShell'
                Attempts = $read.Attempts
                ElapsedMs = $read.ElapsedMs
            }
        }

        'purview.tenant.container-directory-setting' {
            $read = Get-PurviewValidationCachedRead -Context $Context -Key 'directory-settings' `
                -Description 'Get-MgBetaDirectorySetting' -Read {
                    Get-MgBetaDirectorySetting -ErrorAction Stop
                }
            $settings = @($read.Value | Where-Object {
                $_ -and $_.Values -and (@($_.Values | ForEach-Object { [string]$_.Name }) -contains 'EnableMIPLabels')
            })
            # Prefer the documented Group.Unified template when it is present,
            # so an unrelated directory-setting object that happens to expose
            # the same value name cannot be read instead.
            $setting = $settings |
                Where-Object { [string]$_.TemplateId -eq $script:PurviewGroupUnifiedTemplateId } |
                Select-Object -First 1
            if (-not $setting) { $setting = $settings | Select-Object -First 1 }
            if (@($settings).Count -gt 1) {
                $unscored.Add([pscustomobject]@{
                    Field = 'DirectorySettings'
                    Expected = 'one setting exposing EnableMIPLabels'
                    Observed = "$(@($settings).Count) directory settings expose it"
                })
            }
            $value = if ($setting) {
                [string]($setting.Values | Where-Object { [string]$_.Name -eq 'EnableMIPLabels' } | Select-Object -First 1 -ExpandProperty Value)
            } else {
                ''
            }
            return [pscustomobject]@{
                Observed = @{ EnableMIPLabels = $value }
                Unscored = @($unscored)
                Query = 'Get-MgBetaDirectorySetting'
                Source = 'Microsoft.Graph.Beta.Identity.DirectoryManagement'
                Attempts = $read.Attempts
                ElapsedMs = $read.ElapsedMs
            }
        }

        'purview.tenant.label-coauthoring' {
            $read = Get-PurviewValidationCachedRead -Context $Context -Key 'policy-config' `
                -Description 'Get-PolicyConfig' -Read { Get-PolicyConfig -ErrorAction Stop }
            $policyConfig = $read.Value
            return [pscustomobject]@{
                Observed = @{ EnableLabelCoauth = ConvertTo-PurviewValidationBoolean $policyConfig.EnableLabelCoauth }
                Unscored = @()
                Query = 'Get-PolicyConfig'
                Source = 'ExchangeOnlineManagement (Security and Compliance)'
                Attempts = $read.Attempts
                ElapsedMs = $read.ElapsedMs
            }
        }

        'purview.tenant.audit-premium' {
            # User mailboxes only. System, arbitration, discovery, room, and
            # shared mailboxes do not carry SearchQueryInitiated by default,
            # and an unfiltered sample of the first 25 recipients routinely
            # includes them, which would report drift on a correctly
            # configured tenant.
            $read = Get-PurviewValidationCachedRead -Context $Context -Key 'mailbox-audit' `
                -Description 'Get-Mailbox (user mailbox audit sample)' -Read {
                    Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize 25 -ErrorAction Stop
                }
            $mailboxes = @($read.Value)
            $withEvent = @(
                foreach ($mailbox in $mailboxes) {
                    if (@($mailbox.AuditOwner) -contains 'SearchQueryInitiated') { $mailbox }
                }
            )
            $unscored.Add([pscustomobject]@{
                Field = 'MailboxSample'
                Expected = 'not scored'
                Observed = "$($withEvent.Count) of $($mailboxes.Count) sampled user mailboxes include the event"
            })
            return [pscustomobject]@{
                Observed = @{
                    AuditOwnerIncludesSearchQueryInitiated = ($mailboxes.Count -gt 0 -and $withEvent.Count -eq $mailboxes.Count)
                }
                Unscored = @($unscored)
                Query = 'Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize 25'
                Source = 'ExchangeOnlineManagement'
                Attempts = $read.Attempts
                ElapsedMs = $read.ElapsedMs
            }
        }

        'purview.labels.taxonomy' {
            $read = Get-PurviewValidationLabelSet -Context $Context
            $partition = Get-PurviewValidationManagedLabel -Labels $read.Value -ManagedByTag $tag
            $labels = @($partition.Managed)
            $labelsById = Get-PurviewValidationLabelById -Labels $read.Value
            $roots = @($labels | Where-Object { -not $_.ParentId })
            $subLabels = @($labels | Where-Object { $_.ParentId })
            return [pscustomobject]@{
                Observed = @{
                    RootLabelCount = [int]$roots.Count
                    SubLabelCount = [int]$subLabels.Count
                    LabelSignatures = @($labels | ForEach-Object {
                        Get-PurviewValidationLiveLabelSignature -Label $_ -IntendedLabels $intendedLabels -LabelsById $labelsById
                    })
                }
                Unscored = @(New-PurviewValidationLabelContextNote -Partition $partition)
                Query = 'Get-Label'
                Source = 'ExchangeOnlineManagement (Security and Compliance)'
                Attempts = $read.Attempts
                ElapsedMs = $read.ElapsedMs
            }
        }

        'purview.labels.priority' {
            $read = Get-PurviewValidationLabelSet -Context $Context
            $partition = Get-PurviewValidationManagedLabel -Labels $read.Value -ManagedByTag $tag
            $labels = @($partition.Managed)
            $labelsById = Get-PurviewValidationLabelById -Labels $read.Value
            # Purview orders labels by ascending priority within a hierarchy.
            # The plan expects roots in configured order, each followed by its
            # own sub-labels, which is the order the toolkit applies. Only
            # toolkit-managed labels take part, so a customer label inserted
            # between two of them does not reorder the comparison.
            $ordered = [Collections.Generic.List[object]]::new()
            foreach ($root in @($labels | Where-Object { -not $_.ParentId } | Sort-Object Priority)) {
                $ordered.Add($root)
                foreach ($child in @($labels | Where-Object { $_.ParentId -eq $root.Guid } | Sort-Object Priority)) {
                    $ordered.Add($child)
                }
            }
            return [pscustomobject]@{
                Observed = @{
                    PriorityOrder = @($ordered | ForEach-Object {
                        Get-PurviewValidationLiveLabelSignature -Label $_ -IntendedLabels $intendedLabels -LabelsById $labelsById
                    })
                }
                Unscored = @(New-PurviewValidationLabelContextNote -Partition $partition)
                Query = 'Get-Label'
                Source = 'ExchangeOnlineManagement (Security and Compliance)'
                Attempts = $read.Attempts
                ElapsedMs = $read.ElapsedMs
            }
        }

        'purview.labels.publish' {
            $policyRead = Get-PurviewValidationLabelPolicySet -Context $Context
            $labelRead = Get-PurviewValidationLabelSet -Context $Context
            $policy = $policyRead.Value | Where-Object {
                Test-PurviewValidationManaged -Object $_ -Tag $tag
            } | Select-Object -First 1

            $labelsById = @{}
            foreach ($label in @($labelRead.Value)) {
                if ($label -and $label.Guid) { $labelsById[[string]$label.Guid] = $label }
            }

            $publishedSignatures = @()
            $defaultSignature = ''
            $defaultEmailSignature = ''
            $mandatory = $false
            $downgrade = $false

            if ($policy) {
                $publishedSignatures = @(
                    foreach ($labelId in @($policy.Labels)) {
                        $key = [string]$labelId
                        if ($labelsById.ContainsKey($key)) {
                            Get-PurviewValidationLiveLabelSignature -Label $labelsById[$key] -IntendedLabels $intendedLabels -LabelsById $labelsById
                        } else {
                            ''
                        }
                    }
                )
                $defaultLabelId = Get-PurviewValidationLabelAdvancedSetting -Object $policy -Name 'defaultlabelid'
                if ($defaultLabelId -and $labelsById.ContainsKey($defaultLabelId)) {
                    $defaultSignature = Get-PurviewValidationLiveLabelSignature -Label $labelsById[$defaultLabelId] -IntendedLabels $intendedLabels -LabelsById $labelsById
                }
                $outlookDefault = Get-PurviewValidationLabelAdvancedSetting -Object $policy -Name 'outlookdefaultlabel'
                if ($outlookDefault -and $labelsById.ContainsKey($outlookDefault)) {
                    $defaultEmailSignature = Get-PurviewValidationLiveLabelSignature -Label $labelsById[$outlookDefault] -IntendedLabels $intendedLabels -LabelsById $labelsById
                }
                $mandatory = (Get-PurviewValidationLabelAdvancedSetting -Object $policy -Name 'mandatory') -ieq 'true'
                $downgrade = (Get-PurviewValidationLabelAdvancedSetting -Object $policy -Name 'requiredowngradejustification') -ieq 'true'

                $foreignPolicies = @($policyRead.Value | Where-Object {
                    -not (Test-PurviewValidationManaged -Object $_ -Tag $tag)
                })
                if ($foreignPolicies.Count -gt 0) {
                    $unscored.Add([pscustomobject]@{
                        Field = 'OtherLabelPolicies'
                        Expected = 'not scored'
                        Observed = "$($foreignPolicies.Count) label policy or policies not managed by the toolkit"
                    })
                }
                $managedPolicies = @($policyRead.Value | Where-Object {
                    Test-PurviewValidationManaged -Object $_ -Tag $tag
                })
                if ($managedPolicies.Count -gt 1) {
                    $unscored.Add([pscustomobject]@{
                        Field = 'ManagedLabelPolicies'
                        Expected = 'one toolkit-managed label policy'
                        Observed = "$($managedPolicies.Count) carry the managed tag; only the first is scored"
                    })
                }
            }

            return [pscustomobject]@{
                Observed = @{
                    PolicyPresent = [bool]$policy
                    PublishedLabelSignatures = @($publishedSignatures)
                    DefaultLabelSignature = $defaultSignature
                    DefaultLabelForEmailSignature = $defaultEmailSignature
                    MandatoryLabelling = $mandatory
                    DowngradeJustification = $downgrade
                }
                Unscored = @($unscored)
                Query = 'Get-LabelPolicy, Get-Label'
                Source = 'ExchangeOnlineManagement (Security and Compliance)'
                Attempts = [Math]::Max($policyRead.Attempts, $labelRead.Attempts)
                ElapsedMs = $policyRead.ElapsedMs + $labelRead.ElapsedMs
            }
        }

        'purview.labels.attachment-inheritance' {
            $policyRead = Get-PurviewValidationLabelPolicySet -Context $Context
            $policy = $policyRead.Value | Where-Object {
                Test-PurviewValidationManaged -Object $_ -Tag $tag
            } | Select-Object -First 1
            $attachmentAction = if ($policy) {
                Get-PurviewValidationLabelAdvancedSetting -Object $policy -Name 'attachmentaction'
            } else {
                ''
            }
            return [pscustomobject]@{
                Observed = @{ AttachmentAction = $attachmentAction }
                Unscored = @()
                Query = 'Get-LabelPolicy'
                Source = 'ExchangeOnlineManagement (Security and Compliance)'
                Attempts = $policyRead.Attempts
                ElapsedMs = $policyRead.ElapsedMs
            }
        }

        'purview.labels.content-marking' {
            $read = Get-PurviewValidationLabelSet -Context $Context
            $partition = Get-PurviewValidationManagedLabel -Labels $read.Value -ManagedByTag $tag
            $labelsById = Get-PurviewValidationLabelById -Labels $read.Value
            $marked = @(
                foreach ($label in @($partition.Managed)) {
                    $header = Get-PurviewValidationLabelAdvancedSetting -Object $label -Name 'applycontentmarkingheaderenabled'
                    $footer = Get-PurviewValidationLabelAdvancedSetting -Object $label -Name 'applycontentmarkingfooterenabled'
                    $watermark = Get-PurviewValidationLabelAdvancedSetting -Object $label -Name 'applywatermarkingenabled'
                    $applyMarking = $false
                    if ($label.PSObject.Properties['ApplyContentMarkingFooterEnabled'] -and
                        [bool]$label.ApplyContentMarkingFooterEnabled) { $applyMarking = $true }
                    if ($label.PSObject.Properties['ApplyContentMarkingHeaderEnabled'] -and
                        [bool]$label.ApplyContentMarkingHeaderEnabled) { $applyMarking = $true }
                    if ($label.PSObject.Properties['ApplyWaterMarkingEnabled'] -and
                        [bool]$label.ApplyWaterMarkingEnabled) { $applyMarking = $true }
                    if ($header -ieq 'true' -or $footer -ieq 'true' -or $watermark -ieq 'true') { $applyMarking = $true }
                    if ($applyMarking) {
                        Get-PurviewValidationLiveLabelSignature -Label $label -IntendedLabels $intendedLabels -LabelsById $labelsById
                    }
                }
            )
            return [pscustomobject]@{
                Observed = @{ ContentMarkedLabelSignatures = @($marked) }
                Unscored = @(New-PurviewValidationLabelContextNote -Partition $partition)
                Query = 'Get-Label'
                Source = 'ExchangeOnlineManagement (Security and Compliance)'
                Attempts = $read.Attempts
                ElapsedMs = $read.ElapsedMs
            }
        }

        'purview.labels.encryption' {
            $read = Get-PurviewValidationLabelSet -Context $Context
            $partition = Get-PurviewValidationManagedLabel -Labels $read.Value -ManagedByTag $tag
            $labelsById = Get-PurviewValidationLabelById -Labels $read.Value
            $encrypted = @()
            $offlineValues = [Collections.Generic.List[int]]::new()
            $expirationValues = [Collections.Generic.List[string]]::new()
            foreach ($label in @($partition.Managed)) {
                $enabled = $false
                if ($label.PSObject.Properties['EncryptionEnabled'] -and [bool]$label.EncryptionEnabled) { $enabled = $true }
                if ((Get-PurviewValidationLabelAdvancedSetting -Object $label -Name 'encryptionenabled') -ieq 'true') { $enabled = $true }
                if (-not $enabled) { continue }

                $encrypted += Get-PurviewValidationLiveLabelSignature -Label $label -IntendedLabels $intendedLabels -LabelsById $labelsById
                if ($label.PSObject.Properties['EncryptionOfflineAccessDays'] -and
                    $null -ne $label.EncryptionOfflineAccessDays) {
                    $offlineValues.Add([int]$label.EncryptionOfflineAccessDays)
                }
                if ($label.PSObject.Properties['EncryptionContentExpiredOnDateInDaysOrNever'] -and
                    $label.EncryptionContentExpiredOnDateInDaysOrNever) {
                    $expirationValues.Add([string]$label.EncryptionContentExpiredOnDateInDaysOrNever)
                }
            }

            # The plan carries one tenant-wide expectation for these two
            # settings. Taking whichever label the enumeration happened to
            # visit last would make the answer depend on Get-Label ordering,
            # so disagreement between labels is reported rather than resolved.
            $unscoredEncryption = [Collections.Generic.List[object]]::new()
            foreach ($note in @(New-PurviewValidationLabelContextNote -Partition $partition)) {
                $unscoredEncryption.Add($note)
            }
            $distinctOffline = @($offlineValues | Sort-Object -Unique)
            $offlineDays = if ($distinctOffline.Count -eq 1) { [int]$distinctOffline[0] } else { -1 }
            if ($distinctOffline.Count -gt 1) {
                $unscoredEncryption.Add([pscustomobject]@{
                    Field = 'EncryptionOfflineAccessDays'
                    Expected = 'one value across managed encrypted labels'
                    Observed = "$($distinctOffline.Count) different values"
                })
            }
            $distinctExpiration = @($expirationValues | Sort-Object -Unique)
            $expiration = if ($distinctExpiration.Count -eq 1) { [string]$distinctExpiration[0] } else { '' }
            if ($distinctExpiration.Count -gt 1) {
                $unscoredEncryption.Add([pscustomobject]@{
                    Field = 'EncryptionContentExpiration'
                    Expected = 'one value across managed encrypted labels'
                    Observed = "$($distinctExpiration.Count) different values"
                })
            }

            return [pscustomobject]@{
                Observed = @{
                    EncryptedLabelSignatures = @($encrypted)
                    EncryptionOfflineAccessDays = $offlineDays
                    EncryptionContentExpiration = $expiration
                }
                Unscored = @($unscoredEncryption.ToArray())
                Query = 'Get-Label'
                Source = 'ExchangeOnlineManagement (Security and Compliance)'
                Attempts = $read.Attempts
                ElapsedMs = $read.ElapsedMs
            }
        }

        'purview.labels.container-scope' {
            $read = Get-PurviewValidationLabelSet -Context $Context
            $partition = Get-PurviewValidationManagedLabel -Labels $read.Value -ManagedByTag $tag
            $labelsById = Get-PurviewValidationLabelById -Labels $read.Value
            $scoped = @(
                foreach ($label in @($partition.Managed)) {
                    $contentType = if ($label.PSObject.Properties['ContentType']) { [string]$label.ContentType } else { '' }
                    if ($contentType -match '(?i)\b(Site|UnifiedGroup)\b') {
                        Get-PurviewValidationLiveLabelSignature -Label $label -IntendedLabels $intendedLabels -LabelsById $labelsById
                    }
                }
            )
            return [pscustomobject]@{
                Observed = @{ ContainerScopedLabelSignatures = @($scoped) }
                Unscored = @(New-PurviewValidationLabelContextNote -Partition $partition)
                Query = 'Get-Label'
                Source = 'ExchangeOnlineManagement (Security and Compliance)'
                Attempts = $read.Attempts
                ElapsedMs = $read.ElapsedMs
            }
        }

        'purview.dlp.workload' {
            if (-not $Selector) { throw 'The DLP adapter requires a workload selector.' }
            $policyRead = Get-PurviewValidationDlpPolicySet -Context $Context
            $ruleRead = Get-PurviewValidationDlpRuleSet -Context $Context
            $labelRead = Get-PurviewValidationLabelSet -Context $Context
            $labelsById = Get-PurviewValidationLabelById -Labels $labelRead.Value
            $policies = @(Select-PurviewValidationDlpPolicy -Policies $policyRead.Value `
                -Selector $Selector -ManagedByTag $tag
            )

            $rules = [Collections.Generic.List[object]]::new()
            $policySignatures = [Collections.Generic.List[string]]::new()
            foreach ($policy in $policies) {
                # A real DLP policy commonly carries several rules. Only the
                # toolkit's own rule is scored; the rest are counted as
                # unscored context so a customer rule neither fails the check
                # nor hides behind a first-match.
                $policyRules = @($ruleRead.Value | Where-Object {
                    $_ -and $_.PSObject.Properties['ParentPolicyName'] -and
                    ([string]$_.ParentPolicyName -eq [string]$policy.Name)
                })
                $rule = $policyRules |
                    Where-Object { Test-PurviewValidationManaged -Object $_ -Tag $tag } |
                    Select-Object -First 1
                if ($rule) { $rules.Add($rule) }
                $ruleLabelSignatures = @(
                    Get-PurviewValidationRuleLabelSignature `
                        -Rule $rule `
                        -LabelsById $labelsById `
                        -IntendedLabels $intendedLabels |
                        ForEach-Object { ([string]$_).ToLowerInvariant() } |
                        Sort-Object -Unique
                )
                $ruleBlock = $rule -and
                    $rule.PSObject.Properties['BlockAccess'] -and
                    [bool]$rule.BlockAccess
                $policySignatures.Add((
                    'mode={0}|block={1}|labels={2}' -f (
                        [string]$policy.Mode
                    ).ToLowerInvariant(), (
                        [bool]$ruleBlock
                    ).ToString().ToLowerInvariant(), (
                        $ruleLabelSignatures -join ','
                    )
                ))
                $otherRules = @($policyRules | Where-Object {
                    -not (Test-PurviewValidationManaged -Object $_ -Tag $tag)
                })
                if ($otherRules.Count -gt 0) {
                    $unscored.Add([pscustomobject]@{
                        Field = 'OtherPolicyRules'
                        Expected = 'not scored'
                        Observed = "$($otherRules.Count) rule(s) on this policy not managed by the toolkit"
                    })
                }
                if ($rule -and $rule.PSObject.Properties['Disabled'] -and [bool]$rule.Disabled) {
                    $unscored.Add([pscustomobject]@{
                        Field = 'RuleDisabled'
                        Expected = 'not scored'
                        Observed = 'the matched rule is disabled'
                    })
                }
                if ($rule) {
                    foreach ($fieldName in @('NotifyUser', 'GenerateIncidentReport')) {
                        if (-not $rule.PSObject.Properties[$fieldName]) { continue }
                        $count = @($rule.$fieldName).Count
                        if ($count -le 0) { continue }
                        $unscored.Add([pscustomobject]@{
                            Field = $fieldName
                            Expected = 'not scored'
                            Observed = "$count privacy-safe principal value(s) configured"
                        })
                    }
                }
            }
            $policyModes = @(
                $policies |
                    ForEach-Object { [string]$_.Mode } |
                    Where-Object { $_ } |
                    Sort-Object -Unique
            )
            $labelPathCount = [int]@(
                $rules |
                    ForEach-Object { Measure-PurviewValidationRuleLabel -Rule $_ } |
                    Measure-Object -Sum
            ).Sum
            $labelSignatures = @(
                $rules |
                    ForEach-Object {
                        Get-PurviewValidationRuleLabelSignature `
                            -Rule $_ `
                            -LabelsById $labelsById `
                            -IntendedLabels $intendedLabels
                    } |
                    Sort-Object -Unique
            )

            return [pscustomobject]@{
                Observed = @{
                    PolicyPresent = $policies.Count -gt 0
                    PolicyMode = @($policyModes)
                    RulePresent = $policies.Count -gt 0 -and $rules.Count -eq $policies.Count
                    BlockAccess = $rules.Count -gt 0 -and @(
                        $rules |
                            Where-Object {
                                -not ($_.PSObject.Properties['BlockAccess'] -and [bool]$_.BlockAccess)
                            }
                    ).Count -eq 0
                    LabelPathCount = $labelPathCount
                    LabelSignatures = @($labelSignatures)
                    PolicySignatures = @($policySignatures | Sort-Object -Unique)
                }
                Unscored = @($unscored)
                Query = 'Get-DlpCompliancePolicy, Get-DlpComplianceRule'
                Source = 'ExchangeOnlineManagement (Security and Compliance)'
                Attempts = [Math]::Max($policyRead.Attempts, $ruleRead.Attempts)
                ElapsedMs = $policyRead.ElapsedMs + $ruleRead.ElapsedMs
            }
        }

        'purview.retention.exchange' {
            $policyRead = Get-PurviewValidationCachedRead -Context $Context -Key 'retention-policies' `
                -Description 'Get-RetentionCompliancePolicy' -Read {
                    Get-RetentionCompliancePolicy -DistributionDetail -ErrorAction Stop
                }
            $ruleRead = Get-PurviewValidationCachedRead -Context $Context -Key 'retention-rules' `
                -Description 'Get-RetentionComplianceRule' -Read {
                    Get-RetentionComplianceRule -ErrorAction Stop
                }
            $policy = $policyRead.Value | Where-Object {
                Test-PurviewValidationManaged -Object $_ -Tag $tag
            } | Select-Object -First 1
            $rule = $null
            if ($policy) {
                $rule = $ruleRead.Value | Where-Object {
                    $_ -and $_.PSObject.Properties['Policy'] -and
                    ([string]$_.Policy -eq [string]$policy.Guid -or [string]$_.Policy -eq [string]$policy.Name) -and
                    (Test-PurviewValidationManaged -Object $_ -Tag $tag)
                } | Select-Object -First 1
            }

            $durationDays = -1
            if ($rule -and $rule.PSObject.Properties['RetentionDuration'] -and
                $null -ne $rule.RetentionDuration) {
                $parsed = 0
                if ([int]::TryParse([string]$rule.RetentionDuration, [ref]$parsed)) { $durationDays = $parsed }
            }

            $locations = @()
            if ($policy -and $policy.PSObject.Properties['ExchangeLocation'] -and
                @($policy.ExchangeLocation).Count -gt 0) { $locations += 'exchange' }
            if ($policy -and $policy.PSObject.Properties['SharePointLocation'] -and
                @($policy.SharePointLocation).Count -gt 0) { $locations += 'sharepoint' }
            if ($policy -and $policy.PSObject.Properties['OneDriveLocation'] -and
                @($policy.OneDriveLocation).Count -gt 0) { $locations += 'onedrive' }

            return [pscustomobject]@{
                Observed = @{
                    PolicyPresent = [bool]$policy
                    RetentionDurationDays = $durationDays
                    RetentionAction = if ($rule -and $rule.PSObject.Properties['RetentionComplianceAction']) {
                        [string]$rule.RetentionComplianceAction
                    } else { '' }
                    ExpirationDateOption = if ($rule -and $rule.PSObject.Properties['ExpirationDateOption']) {
                        [string]$rule.ExpirationDateOption
                    } else { '' }
                    Locations = @($locations)
                }
                Unscored = @()
                Query = 'Get-RetentionCompliancePolicy -DistributionDetail, Get-RetentionComplianceRule'
                Source = 'ExchangeOnlineManagement (Security and Compliance)'
                Attempts = [Math]::Max($policyRead.Attempts, $ruleRead.Attempts)
                ElapsedMs = $policyRead.ElapsedMs + $ruleRead.ElapsedMs
            }
        }

        'purview.ai.copilot-dlp' {
            $policyRead = Get-PurviewValidationDlpPolicySet -Context $Context
            $ruleRead = Get-PurviewValidationDlpRuleSet -Context $Context
            $labelRead = Get-PurviewValidationLabelSet -Context $Context
            $labelsById = Get-PurviewValidationLabelById -Labels $labelRead.Value
            $policies = @(
                foreach ($policy in @($policyRead.Value)) {
                    if (-not (Test-PurviewValidationManaged -Object $policy -Tag $tag)) { continue }
                    $planes = if ($policy.PSObject.Properties['EnforcementPlanes']) {
                        @($policy.EnforcementPlanes)
                    } else { @() }
                    $isCopilot = @($planes | Where-Object { [string]$_ -match '(?i)copilot|agent' }).Count -gt 0
                    if (-not $isCopilot -and $policy.PSObject.Properties['Workload'] -and
                        [string]$policy.Workload -match '(?i)applications') {
                        $isCopilot = $true
                    }
                    if ($isCopilot) { $policy }
                }
            )

            $planes = @(
                foreach ($policy in $policies) {
                    if (-not $policy.PSObject.Properties['EnforcementPlanes']) { continue }
                    foreach ($plane in @($policy.EnforcementPlanes)) { ([string]$plane).ToLowerInvariant() }
                }
            ) | Select-Object -Unique
            $policyModes = @(
                $policies |
                    ForEach-Object { [string]$_.Mode } |
                    Where-Object { $_ } |
                    Sort-Object -Unique
            )
            $scopePrincipals = @(Get-PurviewValidationAiScopeSet -Policies $policies)

            $settings = [Collections.Generic.List[string]]::new()
            $policySignatures = [Collections.Generic.List[string]]::new()
            $labelCount = 0
            foreach ($policy in $policies) {
                $rules = @($ruleRead.Value | Where-Object {
                    $_ -and $_.PSObject.Properties['ParentPolicyName'] -and
                    ([string]$_.ParentPolicyName -eq [string]$policy.Name) -and
                    (Test-PurviewValidationManaged -Object $_ -Tag $tag)
                })
                foreach ($rule in $rules) {
                    $labelCount += Measure-PurviewValidationRuleLabel -Rule $rule
                    if (-not $rule.PSObject.Properties['RestrictAccess']) { continue }
                    foreach ($restriction in @($rule.RestrictAccess)) {
                        if (-not $restriction) { continue }
                        $setting = if ($restriction -is [System.Collections.IDictionary]) {
                            [string]$restriction['setting']
                        } elseif ($restriction.PSObject.Properties['setting']) {
                            [string]$restriction.setting
                        } else { '' }
                        $value = if ($restriction -is [System.Collections.IDictionary]) {
                            [string]$restriction['value']
                        } elseif ($restriction.PSObject.Properties['value']) {
                            [string]$restriction.value
                        } else { '' }
                        $settings.Add(("{0}={1}" -f $setting, $value).ToLowerInvariant())
                    }
                }
                $policyRuleLabelItems = @(
                    foreach ($rule in $rules) {
                        Get-PurviewValidationRuleLabelSignature `
                            -Rule $rule `
                            -LabelsById $labelsById `
                            -IntendedLabels $intendedLabels
                    }
                )
                $policyRuleLabelSignatures = @(
                    $policyRuleLabelItems |
                        ForEach-Object { ([string]$_).ToLowerInvariant() } |
                        Sort-Object -Unique
                )
                $policyRestrictionItems = @(
                    foreach ($rule in $rules) {
                        if ($rule.PSObject.Properties['RestrictAccess']) {
                            @($rule.RestrictAccess)
                        }
                    }
                )
                $policyRestrictions = @(
                    $policyRestrictionItems |
                        ForEach-Object {
                            if (-not $_) { return '' }
                            $setting = if ($_ -is [System.Collections.IDictionary]) { [string]$_['setting'] } elseif ($_.PSObject.Properties['setting']) { [string]$_.setting } else { '' }
                            $value = if ($_ -is [System.Collections.IDictionary]) { [string]$_['value'] } elseif ($_.PSObject.Properties['value']) { [string]$_.value } else { '' }
                            ("{0}={1}" -f $setting, $value).ToLowerInvariant()
                        } |
                        Where-Object { $_ } |
                        Sort-Object -Unique
                )
                $policyPlaneItems = if ($policy.PSObject.Properties['EnforcementPlanes']) {
                    @($policy.EnforcementPlanes)
                } else { @() }
                $policyPlanes = @(
                    $policyPlaneItems |
                        ForEach-Object { ([string]$_).ToLowerInvariant() } |
                        Sort-Object -Unique
                )
                $policyScope = @(Get-PurviewValidationAiScopeSet -Policies @($policy))
                $policySignatures.Add((
                    'mode={0}|planes={1}|restrictions={2}|scope={3}|labels={4}' -f (
                        [string]$policy.Mode
                    ).ToLowerInvariant(), (
                        $policyPlanes -join ','
                    ), (
                        $policyRestrictions -join ','
                    ), (
                        $policyScope -join ','
                    ), (
                        $policyRuleLabelSignatures -join ','
                    )
                ))
            }

            return [pscustomobject]@{
                Observed = @{
                    PolicyCount = [int]$policies.Count
                    PolicyMode = @($policyModes)
                    EnforcementPlanes = @($planes)
                    RestrictAccessSettings = @($settings | Select-Object -Unique)
                    ScopePrincipalSignatures = @($scopePrincipals)
                    LabelPathCount = [int]$labelCount
                    PolicySignatures = @($policySignatures | Sort-Object -Unique)
                }
                Unscored = @()
                Query = 'Get-DlpCompliancePolicy, Get-DlpComplianceRule'
                Source = 'ExchangeOnlineManagement (Security and Compliance)'
                Attempts = [Math]::Max($policyRead.Attempts, $ruleRead.Attempts)
                ElapsedMs = $policyRead.ElapsedMs + $ruleRead.ElapsedMs
            }
        }

        default {
            throw "Validation adapter '$AdapterId' has no collector implementation."
        }
    }
}

function Invoke-PurviewValidationCollection {
    <#
        Assesses every action in the plan and returns one result per action.

        A failure in one collector never stops the run: the action becomes
        'Collection failed' and the next action is assessed, so the operator
        still gets partial artifacts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Plan,
        [Parameter(Mandatory)] [psobject] $Context,
        [Parameter()] [scriptblock] $Progress = $null
    )

    $results = [Collections.Generic.List[object]]::new()
    if ($Plan.PSObject.Properties['IntendedState'] -and
        $Plan.IntendedState -and
        $Plan.IntendedState.PSObject.Properties['Labels']) {
        $Context.IntendedLabels = @($Plan.IntendedState.Labels)
    }

    foreach ($action in @($Plan.Actions)) {
        if ($Progress) { & $Progress $action }

        $validation = $action.Validation
        $adapterId = [string]$validation.AdapterId
        $selector = if ($validation.PSObject.Properties['Selector']) { [string]$validation.Selector } else { '' }

        if (-not [bool]$validation.Scored) {
            $results.Add((New-PurviewValidationResult -Action $action -Status 'Informational' `
                -Reason "The plan recorded this action as '$($action.Intent)', so tenant state is reported without scoring it." `
                -NextStep 'No action required unless the feature is intentionally brought into scope.' `
                -PrerequisiteDisposition 'Not applicable'))
            continue
        }

        $prerequisite = Test-PurviewValidationPrerequisite -Context $Context `
            -Kind ([string]$validation.Prerequisite.Kind) `
            -Id ([string]$validation.Prerequisite.Id)

        if ($prerequisite.State -ne 'Satisfied') {
            $results.Add((New-PurviewValidationResult -Action $action -Status 'Not evaluated' `
                -Reason $prerequisite.Detail `
                -NextStep 'Confirm the prerequisite before treating this action as drift.' `
                -PrerequisiteDisposition $prerequisite.State))
            continue
        }

        $requiredCapability = Get-PurviewValidationAdapterCapability -AdapterId $adapterId
        if ($requiredCapability) {
            $capability = Test-PurviewValidationPrerequisite -Context $Context `
                -Kind 'Capability' -Id $requiredCapability
            if ($capability.State -ne 'Satisfied') {
                $results.Add((New-PurviewValidationResult -Action $action -Status 'Not evaluated' `
                    -Reason $capability.Detail `
                    -NextStep 'Establish the required session and rerun validation for this action.' `
                    -PrerequisiteDisposition $capability.State))
                continue
            }
        }

        try {
            $observation = Invoke-PurviewValidationAdapter -Context $Context `
                -AdapterId $adapterId -Selector $selector
        } catch {
            $results.Add((New-PurviewValidationResult -Action $action -Status 'Collection failed' `
                -Reason 'The tenant read did not succeed after transient retries.' `
                -NextStep 'Check permissions, module availability, and service health, then rerun validation.' `
                -Query $adapterId `
                -Attempts $script:PurviewValidationReadAttempts `
                -ErrorText $_.Exception.Message `
                -PrerequisiteDisposition $prerequisite.State))
            continue
        }

        if ($observation.PSObject.Properties['NotEvaluated'] -and [bool]$observation.NotEvaluated) {
            $results.Add((New-PurviewValidationResult -Action $action -Status 'Not evaluated' `
                -Reason ([string]$observation.NotEvaluatedReason) `
                -NextStep 'Confirm the service or module capability before treating this action as drift.' `
                -UnscoredDifferences @($observation.Unscored) `
                -Query $observation.Query -Source $observation.Source `
                -Attempts $observation.Attempts -ElapsedMs $observation.ElapsedMs `
                -PrerequisiteDisposition 'Unknown'))
            continue
        }

        $comparisons = @(
            foreach ($field in @($validation.Expected)) {
                $fieldName = [string]$field.Field
                $observedValue = if ($observation.Observed.ContainsKey($fieldName)) {
                    $observation.Observed[$fieldName]
                } else {
                    $null
                }
                Compare-PurviewValidationField -Field $fieldName `
                    -Comparator ([string]$field.Comparator) `
                    -Expected $field.Value -Observed $observedValue
            }
        )

        $mismatches = @($comparisons | Where-Object { -not $_.Matched })
        if ($mismatches.Count -gt 0) {
            $fields = ($mismatches | ForEach-Object { $_.Field }) -join ', '
            $results.Add((New-PurviewValidationResult -Action $action -Status 'Drift' `
                -Reason "Managed field mismatch after transient retries: $fields." `
                -NextStep 'Review whether the deployment action failed or the setting changed afterward, then rerun the deployment for this action.' `
                -FieldComparisons $comparisons `
                -UnscoredDifferences @($observation.Unscored) `
                -Query $observation.Query -Source $observation.Source `
                -Attempts $observation.Attempts -ElapsedMs $observation.ElapsedMs `
                -PrerequisiteDisposition $prerequisite.State))
            continue
        }

        $results.Add((New-PurviewValidationResult -Action $action -Status 'Matched' `
            -Reason 'Every managed field matched the plan.' `
            -NextStep 'No action required.' `
            -FieldComparisons $comparisons `
            -UnscoredDifferences @($observation.Unscored) `
            -Query $observation.Query -Source $observation.Source `
            -Attempts $observation.Attempts -ElapsedMs $observation.ElapsedMs `
            -PrerequisiteDisposition $prerequisite.State))
    }

    return $results.ToArray()
}
