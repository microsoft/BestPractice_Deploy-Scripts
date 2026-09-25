#requires -Version 7.0
<#
.SYNOPSIS
    Canonical model, comparison, redaction, and exit-code rules for Purview
    configuration validation.

.DESCRIPTION
    This file is deliberately free of tenant calls. It parses and validates a
    Deployment Plan, normalizes values, compares managed fields, applies the
    documented result precedence, and computes the process exit code.

    Configuration validation is not a compliance assessment. It compares
    observable tenant settings with one specific Deployment Plan and says
    nothing about regulatory obligations, data-protection effectiveness, or
    user adoption.

    Result vocabulary defined by the configuration-validation contract:

        Matched            managed fields equal
        Drift              managed fields differ after transient retries
        Not evaluated      a documented prerequisite was unavailable
        Informational      the plan excluded or did not configure the action
        Collection failed  the read failed after transient retries

    Result precedence, highest first:

        1. fatal plan, identity, or connection error (no results are produced)
        2. Collection failed
        3. Not evaluated
        4. Informational
        5. Drift
        6. Matched

    EXPORTS (via dot-source):
      * Test-PurviewValidationPlan
      * ConvertTo-PurviewValidationRedactedText
      * ConvertTo-PurviewValidationComparable
      * Compare-PurviewValidationField
      * New-PurviewValidationResult
      * New-PurviewValidationModel
      * Get-PurviewValidationExitCode
#>

Set-StrictMode -Version Latest

$script:PurviewValidationStatuses = @(
    'Matched', 'Drift', 'Not evaluated', 'Informational', 'Collection failed'
)

# Exit codes are a bitmask so a single run can report both drift and a
# collection gap without hiding either one behind the other.
$script:PurviewValidationExitClean = 0
$script:PurviewValidationExitFatal = 1
$script:PurviewValidationExitDrift = 2
$script:PurviewValidationExitCollectionFailure = 4

$script:PurviewValidationRedactionTerms = @()

function Set-PurviewValidationRedactionTerm {
    <#
        Registers additional literal terms to strip from free text, normally
        the connected tenant's verified domains.

        The static patterns catch addresses, URLs, Microsoft-owned suffixes,
        and GUIDs. They cannot catch a custom verified domain such as
        contoso.com, because there is nothing in the string shape that
        distinguishes it from any other host name. Those come from the
        connected tenant at run start.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $Term = @()
    )

    $script:PurviewValidationRedactionTerms = @(
        $Term |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim() } |
            Select-Object -Unique |
            Sort-Object -Property Length -Descending
    )
}

function ConvertTo-PurviewValidationRedactedText {
    <#
        Removes tenant-identifying detail from free text before it reaches an
        artifact. Applied to unscored object differences, collector errors, and
        any other text a service returns.

        Managed expected and observed values are not routed through this
        function because the collectors normalize them to booleans, counts,
        enumeration strings, and Microsoft-global label signatures, none of
        which identify a tenant.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Text
    )

    if ([string]::IsNullOrEmpty($Text)) { return '' }

    $redacted = $Text
    $redacted = [regex]::Replace($redacted, '(?i)https?://\S+', '[redacted-url]')
    $redacted = [regex]::Replace($redacted, "(?i)[\w.\-+']+@[\w\-]+(\.[\w\-]+)+", '[redacted-address]')
    foreach ($term in $script:PurviewValidationRedactionTerms) {
        $redacted = [regex]::Replace($redacted, [regex]::Escape($term), '[redacted-domain]',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $redacted = [regex]::Replace(
        $redacted,
        '(?i)\b[a-z0-9-]+\.(onmicrosoft\.com|sharepoint\.com|microsoftonline\.com)\b',
        '[redacted-domain]')
    $redacted = [regex]::Replace(
        $redacted,
        '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
        '[redacted-guid]')

    return $redacted
}

function ConvertTo-PurviewValidationComparable {
    <#
        Normalizes a value into the shape the comparators expect: $null becomes
        an empty string, booleans and integers keep their type, everything else
        becomes a trimmed string, and collections become string arrays.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object] $Value
    )

    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [int] -or $Value -is [long]) { return [int]$Value }

    if ($Value -is [string]) { return $Value.Trim() }

    if ($Value -is [System.Collections.IEnumerable]) {
        return @(
            foreach ($item in $Value) {
                if ($null -eq $item) { continue }
                if ($item -is [bool]) { ([string]$item).ToLowerInvariant(); continue }
                ([string]$item).Trim()
            }
        )
    }

    return ([string]$Value).Trim()
}

function Format-PurviewValidationValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object] $Value
    )

    $normalized = ConvertTo-PurviewValidationComparable -Value $Value
    if ($normalized -is [bool]) { return ([string]$normalized).ToLowerInvariant() }
    if ($normalized -is [array]) {
        if ($normalized.Count -eq 0) { return '(empty)' }
        return ($normalized -join ', ')
    }
    if ([string]::IsNullOrEmpty([string]$normalized)) { return '(not set)' }
    return [string]$normalized
}

function Compare-PurviewValidationField {
    <#
        Applies one allowlisted comparator to one managed field.

        Comparators are deliberately narrow. A permissive comparator would let
        a real difference pass as a match, which is the failure mode this tool
        exists to prevent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Field,
        [Parameter(Mandatory)] [string] $Comparator,
        [Parameter()] [AllowNull()] [object] $Expected,
        [Parameter()] [AllowNull()] [object] $Observed
    )

    $expectedValue = ConvertTo-PurviewValidationComparable -Value $Expected
    $observedValue = ConvertTo-PurviewValidationComparable -Value $Observed

    $matched = switch ($Comparator) {
        'ExactBoolean' {
            $expectedBoolean = $null
            $observedBoolean = $null
            $expectedParsed = if ($expectedValue -is [bool]) {
                $expectedBoolean = [bool]$expectedValue
                $true
            } else {
                [bool]::TryParse([string]$expectedValue, [ref]$expectedBoolean)
            }
            $observedParsed = if ($observedValue -is [bool]) {
                $observedBoolean = [bool]$observedValue
                $true
            } else {
                [bool]::TryParse([string]$observedValue, [ref]$observedBoolean)
            }
            $expectedParsed -and $observedParsed -and
                $expectedBoolean -eq $observedBoolean
        }
        'ExactString' {
            [string]$expectedValue -ceq [string]$observedValue
        }
        'CaseInsensitiveString' {
            [string]$expectedValue -ieq [string]$observedValue
        }
        'ExactInt' {
            try { ([int]$expectedValue) -eq ([int]$observedValue) } catch { $false }
        }
        'SetEquality' {
            $expectedSet = @(@($expectedValue) | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
            $observedSet = @(@($observedValue) | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
            ($expectedSet -join "`u{001f}") -ceq ($observedSet -join "`u{001f}")
        }
        'OrderedSequence' {
            $expectedSequence = @(@($expectedValue) | ForEach-Object { ([string]$_).ToLowerInvariant() })
            $observedSequence = @(@($observedValue) | ForEach-Object { ([string]$_).ToLowerInvariant() })
            ($expectedSequence -join "`u{001f}") -ceq ($observedSequence -join "`u{001f}")
        }
        'Presence' {
            $present = if ($null -eq $Observed) {
                $false
            } elseif ($Observed -is [bool]) {
                [bool]$Observed
            } elseif ($Observed -is [string]) {
                -not [string]::IsNullOrWhiteSpace($Observed)
            } elseif ($Observed -is [System.Collections.IEnumerable]) {
                @($Observed).Count -gt 0
            } elseif ($Observed -is [byte] -or $Observed -is [sbyte] -or
                $Observed -is [int16] -or $Observed -is [uint16] -or
                $Observed -is [int32] -or $Observed -is [uint32] -or
                $Observed -is [int64] -or $Observed -is [uint64] -or
                $Observed -is [single] -or $Observed -is [double] -or
                $Observed -is [decimal]) {
                [decimal]$Observed -gt 0
            } else {
                $true
            }
            ([bool]$expectedValue) -eq $present
        }
        default {
            throw "Unsupported comparator '$Comparator' for field '$Field'."
        }
    }

    return [pscustomobject][ordered]@{
        Field = $Field
        Comparator = $Comparator
        Matched = [bool]$matched
        ExpectedText = Format-PurviewValidationValue -Value $expectedValue
        ObservedText = Format-PurviewValidationValue -Value $observedValue
    }
}

function Test-PurviewValidationExpectedType {
    <#
        Rejects an expected value whose type does not suit its comparator.

        PowerShell casts are permissive in exactly the direction that hides a
        defect: [bool]'false' is $true and [int]'1.5' is 2. A plan that carried
        the string "false" for an ExactBoolean field would therefore report a
        confident, wrong 'Matched'. Type is checked here, before anything
        connects, rather than being absorbed by a cast at comparison time.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ActionId,
        [Parameter(Mandatory)] [string] $Field,
        [Parameter(Mandatory)] [string] $Comparator,
        [Parameter()] [AllowNull()] [object] $Value
    )

    $describe = "Deployment Plan action '$ActionId' field '$Field'"

    switch ($Comparator) {
        { $_ -in @('ExactBoolean', 'Presence') } {
            if ($Value -isnot [bool]) {
                throw "$describe uses comparator '$Comparator' and must carry a boolean value."
            }
        }
        'ExactInt' {
            if ($Value -isnot [int] -and $Value -isnot [long]) {
                throw "$describe uses comparator 'ExactInt' and must carry an integer value."
            }
        }
        { $_ -in @('ExactString', 'CaseInsensitiveString') } {
            if ($null -ne $Value -and $Value -isnot [string]) {
                throw "$describe uses comparator '$Comparator' and must carry a string value."
            }
        }
        { $_ -in @('SetEquality', 'OrderedSequence') } {
            foreach ($item in @($Value)) {
                if ($null -eq $item) { continue }
                if ($item -isnot [string]) {
                    throw "$describe uses comparator '$Comparator' and must carry string members."
                }
            }
        }
    }
}

function Get-PurviewValidationSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Text)

    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
}

function Test-PurviewValidationJsonShape {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Raw)

    $document = [Text.Json.JsonDocument]::Parse($Raw)
    try {
        $root = $document.RootElement
        function RequireObject([Text.Json.JsonElement] $Element, [string] $Name) {
            if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
                throw "Deployment Plan JSON shape '$Name' must be an object."
            }
        }
        function RequireArray([Text.Json.JsonElement] $Element, [string] $Name) {
            if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Array) {
                throw "Deployment Plan JSON shape '$Name' must be an array."
            }
        }
        function GetRequiredProperty([Text.Json.JsonElement] $Element, [string] $Name, [string] $Path) {
            $value = [Text.Json.JsonElement]::new()
            if (-not $Element.TryGetProperty($Name, [ref]$value)) {
                throw "Deployment Plan JSON shape is missing required property '$Path'."
            }
            return $value
        }
        RequireObject $root 'root'
        $state = GetRequiredProperty $root 'IntendedState' 'IntendedState'
        RequireObject $state 'IntendedState'
        foreach ($name in @('TenantSettings', 'Labels', 'DlpPolicies', 'AIGovernance')) {
            RequireArray (GetRequiredProperty $state $name "IntendedState.$name") "IntendedState.$name"
        }
        $labelPolicy = GetRequiredProperty $state 'LabelPolicy' 'IntendedState.LabelPolicy'
        RequireObject $labelPolicy 'IntendedState.LabelPolicy'
        foreach ($name in @('PublishedLabelKeys', 'TenantDependentParentKeys')) {
            RequireArray (GetRequiredProperty $labelPolicy $name "IntendedState.LabelPolicy.$name") "IntendedState.LabelPolicy.$name"
        }
        $encryption = GetRequiredProperty $state 'Encryption' 'IntendedState.Encryption'
        RequireObject $encryption 'IntendedState.Encryption'
        $null = GetRequiredProperty $encryption 'OfflineAccessDays' 'IntendedState.Encryption.OfflineAccessDays'
        $null = GetRequiredProperty $encryption 'ContentExpiration' 'IntendedState.Encryption.ContentExpiration'
        $retention = GetRequiredProperty $state 'Retention' 'IntendedState.Retention'
        RequireObject $retention 'IntendedState.Retention'
        foreach ($name in @('Locations', 'UnsupportedLocations')) {
            RequireArray (GetRequiredProperty $retention $name "IntendedState.Retention.$name") "IntendedState.Retention.$name"
        }
        $null = GetRequiredProperty $retention 'LocationDisposition' 'IntendedState.Retention.LocationDisposition'
        foreach ($label in (GetRequiredProperty $state 'Labels' 'IntendedState.Labels').EnumerateArray()) {
            foreach ($name in @('ContentTypes')) {
                RequireArray (GetRequiredProperty $label $name "IntendedState.Labels[].$name") "IntendedState.Labels[].$name"
            }
            if ($label.TryGetProperty('Rights', [ref]$encryption)) {
                RequireArray (GetRequiredProperty $encryption 'Entries' 'IntendedState.Labels[].Rights.Entries') 'IntendedState.Labels[].Rights.Entries'
            }
        }
        foreach ($dlp in (GetRequiredProperty $state 'DlpPolicies' 'IntendedState.DlpPolicies').EnumerateArray()) {
            foreach ($name in @('LabelKeys', 'NotifyUser', 'GenerateIncidentReport')) {
                RequireArray (GetRequiredProperty $dlp $name "IntendedState.DlpPolicies[].$name") "IntendedState.DlpPolicies[].$name"
            }
        }
        foreach ($ai in (GetRequiredProperty $state 'AIGovernance' 'IntendedState.AIGovernance').EnumerateArray()) {
            foreach ($name in @('EnforcementPlanes', 'Locations', 'LabelKeys', 'Restrictions')) {
                RequireArray (GetRequiredProperty $ai $name "IntendedState.AIGovernance[].$name") "IntendedState.AIGovernance[].$name"
            }
            foreach ($location in (GetRequiredProperty $ai 'Locations' 'IntendedState.AIGovernance[].Locations').EnumerateArray()) {
                $null = GetRequiredProperty $location 'LocationClass' 'IntendedState.AIGovernance[].Locations[].LocationClass'
                $null = GetRequiredProperty $location 'LocationDigest' 'IntendedState.AIGovernance[].Locations[].LocationDigest'
            }
        }
    } finally {
        $document.Dispose()
    }
}

function Set-PurviewValidationFromIntendedState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject] $Plan)

    $state = $Plan.IntendedState
    $labels = @($state.Labels)
    $tenant = @($state.TenantSettings)
    function GetRequiredStateItem([object[]] $Items, [string] $Property, [string] $Value, [string] $ActionId) {
        $matches = @($Items | Where-Object { [string]$_.$Property -eq $Value })
        if ($matches.Count -ne 1) {
            throw "Deployment Plan intended state for '$ActionId' must contain exactly one $Property '$Value'."
        }
        return $matches[0]
    }
    function GetStateItemsByKey([object[]] $Items, [string[]] $Keys, [string] $Prefix, [string] $ActionId, [bool] $Required) {
        $allKeys = @(
            @($Keys) |
                ForEach-Object { [string]$_ } |
                Where-Object { $_ }
        )
        $requested = @(
            $allKeys |
                Where-Object { $_ -like "$Prefix*" }
        )
        if ($Required -and $requested.Count -eq 0) {
            throw "Deployment Plan action '$ActionId' has no intended-state keys with required prefix '$Prefix'."
        }
        $resolved = @(
            foreach ($fullKey in $requested) {
                $matches = @($Items | Where-Object {
                    $itemKey = [string]$_.Key
                    $canonicalKey = if ($itemKey -like "$Prefix*") {
                        $itemKey
                    } elseif ($Prefix -eq 'labels/') {
                        "$Prefix$itemKey"
                    } else {
                        $itemKey
                    }
                    $canonicalKey -eq $fullKey
                })
                if ($matches.Count -ne 1) {
                    throw "Deployment Plan intended-state key '$fullKey' for '$ActionId' does not resolve to exactly one record."
                }
                $matches[0]
            }
        )
        return $resolved
    }
    function GetStringSet([object] $Value) {
        return @(
            @($Value) |
                ForEach-Object { ([string]$_).Trim() } |
                Where-Object { $_ } |
                Sort-Object -Unique
        )
    }
    function TestKnownStateKeys([string[]] $Keys, [string] $ActionId) {
        foreach ($key in @($Keys)) {
            if ([string]::IsNullOrWhiteSpace($key)) { continue }
            if ($key -like 'labels/*' -or
                $key -like 'label-policy/*' -or
                $key -like 'encryption/*' -or
                $key -like 'dlp/*' -or
                $key -like 'retention/*' -or
                $key -like 'ai/*' -or
                $key -like 'tenant.*') {
                continue
            }
            throw "Deployment Plan action '$ActionId' has unsupported intended-state key '$key'."
        }
    }
    function GetRequiredSingletonByKey([object[]] $Items, [string[]] $Keys, [string] $Prefix, [string] $ActionId) {
        $matches = @(GetStateItemsByKey $Items $Keys $Prefix $ActionId $true)
        if ($matches.Count -ne 1) {
            throw "Deployment Plan action '$ActionId' must resolve exactly one intended-state key with prefix '$Prefix'."
        }
        return $matches[0]
    }
    function GetAiScopeSet([object[]] $Policies) {
        $scopeItems = @(
            foreach ($policy in @($Policies)) {
                foreach ($location in @($policy.Locations)) {
                    $locationClass = [string]$location.LocationClass
                    $locationValue = if ($locationClass -eq 'PublicProductLocation') {
                        [string]$location.Location
                    } else {
                        ''
                    }
                    $locationKey = "{0}|{1}|{2}|{3}" -f (
                        [string]$location.Workload
                    ).ToLowerInvariant(), $locationClass.ToLowerInvariant(), (
                        [string]$location.LocationDigest
                    ).ToLowerInvariant(), $locationValue.ToLowerInvariant()
                    foreach ($principal in @($location.Inclusions)) {
                        "include|$locationKey|$([string]$principal.Type)|$([string]$principal.IdentityClass)|$([string]$principal.Digest)"
                    }
                    foreach ($principal in @($location.Exclusions)) {
                        "exclude|$locationKey|$([string]$principal.Type)|$([string]$principal.IdentityClass)|$([string]$principal.Digest)"
                    }
                    if (@($location.Inclusions).Count -eq 0 -and @($location.Exclusions).Count -eq 0) {
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
    function GetAiExpectedLabelKeys([object] $Policy, [object[]] $AllLabels) {
        $keys = [Collections.Generic.List[string]]::new()
        foreach ($key in @($Policy.LabelKeys)) {
            $children = @(
                $AllLabels |
                    Where-Object { [string]$_.ParentKey -eq [string]$key } |
                    ForEach-Object { [string]$_.Key }
            )
            if ([string]$Policy.LabelResolution -eq 'ExpandLabelGroupsAtRuntime' -and
                $children.Count -gt 0) {
                foreach ($child in $children) { $keys.Add($child) }
            } else {
                $keys.Add([string]$key)
            }
        }
        return @($keys | Where-Object { $_ } | Sort-Object -Unique)
    }
    foreach ($action in @($Plan.Actions)) {
        $actionId = [string]$action.ActionId
        $stateKeys = @(
            if ($action.PSObject.Properties['IntendedStateKeys']) {
                @($action.IntendedStateKeys) | ForEach-Object { [string]$_ }
            }
        )
        TestKnownStateKeys $stateKeys $actionId
        $expected = [Collections.Generic.List[object]]::new()
        $adapterId = $actionId
        $selector = ''
        $prerequisite = [pscustomobject]@{ Kind = 'None'; Id = '' }
        $requiresStateKeys = [string]$action.Intent -in @('Included', 'Conditional')

        function AddExpected([string] $Field, [string] $Comparator, [object] $Value) {
            $expected.Add([pscustomobject]@{
                Field = $Field
                Comparator = $Comparator
                Value = $Value
            })
        }

        switch ($actionId) {
            'purview.tenant.audit-standard' {
                $item = GetRequiredStateItem $tenant 'Key' 'tenant.audit-standard' $actionId
                AddExpected 'UnifiedAuditLogIngestionEnabled' 'ExactBoolean' ([bool]$item.DesiredValue)
            }
            'purview.tenant.spo-labels' {
                $item = GetRequiredStateItem $tenant 'Key' 'tenant.spo-labels' $actionId
                AddExpected 'EnableAIPIntegration' 'ExactBoolean' ([bool]$item.DesiredValue)
                $prerequisite = [pscustomobject]@{ Kind = 'Capability'; Id = 'SharePointOnlineSession' }
            }
            'purview.tenant.pdf-labels' {
                $item = GetRequiredStateItem $tenant 'Key' 'tenant.pdf-labels' $actionId
                AddExpected 'EnableSensitivityLabelForPDF' 'ExactBoolean' ([bool]$item.DesiredValue)
                $prerequisite = [pscustomobject]@{ Kind = 'Capability'; Id = 'SharePointOnlineSession' }
            }
            'purview.tenant.container-directory-setting' {
                $item = GetRequiredStateItem $tenant 'Key' 'tenant.container-labels' $actionId
                AddExpected 'EnableMIPLabels' 'CaseInsensitiveString' ([string]$item.DesiredValue)
                $prerequisite = [pscustomobject]@{ Kind = 'License'; Id = 'BusinessPremiumOrHigher' }
            }
            'purview.tenant.label-coauthoring' {
                $item = GetRequiredStateItem $tenant 'Key' 'tenant.label-coauthoring' $actionId
                AddExpected 'EnableLabelCoauth' 'ExactBoolean' ([bool]$item.DesiredValue)
            }
            'purview.tenant.audit-premium' {
                AddExpected 'AuditOwnerIncludesSearchQueryInitiated' 'ExactBoolean' $true
                $prerequisite = [pscustomobject]@{ Kind = 'License'; Id = 'AuditPremium' }
            }
            'purview.labels.taxonomy' {
                $adapterId = 'purview.labels.taxonomy'
                $actionLabels = @(GetStateItemsByKey $labels $stateKeys 'labels/' $actionId $requiresStateKeys)
                AddExpected 'RootLabelCount' 'ExactInt' ([int]@($actionLabels | Where-Object { -not $_.ParentKey }).Count)
                AddExpected 'SubLabelCount' 'ExactInt' ([int]@($actionLabels | Where-Object ParentKey).Count)
                AddExpected 'LabelSignatures' 'SetEquality' @($actionLabels | ForEach-Object { [string]$_.Key })
            }
            'purview.labels.priority' {
                $adapterId = 'purview.labels.priority'
                $actionLabels = @(GetStateItemsByKey $labels $stateKeys 'labels/' $actionId $requiresStateKeys)
                AddExpected 'PriorityOrder' 'OrderedSequence' @(
                    $actionLabels | Sort-Object Priority | ForEach-Object { [string]$_.Key }
                )
            }
            'purview.labels.publish' {
                $policy = GetRequiredSingletonByKey @($state.LabelPolicy) $stateKeys 'label-policy/' $actionId
                AddExpected 'PolicyPresent' 'ExactBoolean' $true
                AddExpected 'PublishedLabelSignatures' 'SetEquality' @($policy.PublishedLabelKeys)
                AddExpected 'DefaultLabelSignature' 'ExactString' ([string]$policy.DefaultLabelKey)
                AddExpected 'DefaultLabelForEmailSignature' 'ExactString' ([string]$policy.EmailDefaultLabelKey)
                AddExpected 'MandatoryLabelling' 'ExactBoolean' ([bool]$policy.Mandatory)
                AddExpected 'DowngradeJustification' 'ExactBoolean' ([bool]$policy.RequireDowngradeJustification)
            }
            'purview.labels.attachment-inheritance' {
                $adapterId = 'purview.labels.attachment-inheritance'
                $policy = GetRequiredSingletonByKey @($state.LabelPolicy) $stateKeys 'label-policy/' $actionId
                AddExpected 'AttachmentAction' 'CaseInsensitiveString' ([string]$policy.AttachmentAction)
            }
            'purview.labels.content-marking' {
                $adapterId = 'purview.labels.content-marking'
                $actionLabels = @(GetStateItemsByKey $labels $stateKeys 'labels/' $actionId $requiresStateKeys)
                AddExpected 'ContentMarkedLabelSignatures' 'SetEquality' @(
                    $actionLabels | Where-Object ContentMark | ForEach-Object { [string]$_.Key }
                )
            }
            'purview.labels.encryption' {
                $adapterId = 'purview.labels.encryption'
                $actionLabels = @(GetStateItemsByKey $labels $stateKeys 'labels/' $actionId $requiresStateKeys)
                AddExpected 'EncryptedLabelSignatures' 'SetEquality' @(
                    $actionLabels | Where-Object Encrypt | ForEach-Object { [string]$_.Key }
                )
                $encryption = GetRequiredSingletonByKey @($state.Encryption) $stateKeys 'encryption/' $actionId
                AddExpected 'EncryptionOfflineAccessDays' 'ExactInt' ([int]$encryption.OfflineAccessDays)
                AddExpected 'EncryptionContentExpiration' 'CaseInsensitiveString' ([string]$encryption.ContentExpiration)
            }
            'purview.labels.container-scope' {
                $adapterId = 'purview.labels.container-scope'
                $actionLabels = @(GetStateItemsByKey $labels $stateKeys 'labels/' $actionId $requiresStateKeys)
                AddExpected 'ContainerScopedLabelSignatures' 'SetEquality' @(
                    $actionLabels |
                        Where-Object { 'Site' -in @($_.ContentTypes) -or 'UnifiedGroup' -in @($_.ContentTypes) } |
                        ForEach-Object { [string]$_.Key }
                )
                $prerequisite = [pscustomobject]@{ Kind = 'License'; Id = 'BusinessPremiumOrHigher' }
            }
            { $_ -in @('purview.dlp.exchange', 'purview.dlp.sharepoint-onedrive', 'purview.dlp.endpoint') } {
                $adapterId = 'purview.dlp.workload'
                $items = @(GetStateItemsByKey @($state.DlpPolicies) $stateKeys 'dlp/' $actionId $requiresStateKeys)
                $selector = switch ($actionId) {
                    'purview.dlp.exchange' { 'Exchange' }
                    'purview.dlp.sharepoint-onedrive' { 'SharePointOneDrive' }
                    'purview.dlp.endpoint' { 'Endpoint' }
                }
                $modes = @(GetStringSet ($items | ForEach-Object { $_.Mode }))
                AddExpected 'PolicyPresent' 'ExactBoolean' ($items.Count -gt 0)
                AddExpected 'PolicyMode' 'SetEquality' @($modes)
                AddExpected 'RulePresent' 'ExactBoolean' ($items.Count -gt 0)
                AddExpected 'BlockAccess' 'ExactBoolean' ($items.Count -gt 0 -and @($items | Where-Object { -not [bool]$_.BlockAccess }).Count -eq 0)
                AddExpected 'LabelPathCount' 'ExactInt' ([int]@($items | ForEach-Object { @($_.LabelKeys).Count } | Measure-Object -Sum).Sum)
                AddExpected 'LabelSignatures' 'SetEquality' @(
                    $items | ForEach-Object { @($_.LabelKeys) } | Sort-Object -Unique
                )
                AddExpected 'PolicySignatures' 'SetEquality' @(
                    $items |
                        ForEach-Object {
                            $labelSet = (
                                @($_.LabelKeys) |
                                    ForEach-Object { ([string]$_).ToLowerInvariant() } |
                                    Sort-Object -Unique
                            ) -join ','
                            'mode={0}|block={1}|labels={2}' -f (
                                [string]$_.Mode
                            ).ToLowerInvariant(), (
                                [bool]$_.BlockAccess
                            ).ToString().ToLowerInvariant(), $labelSet
                        } |
                        Sort-Object -Unique
                )
                if ($actionId -eq 'purview.dlp.endpoint') {
                    $prerequisite = [pscustomobject]@{ Kind = 'License'; Id = 'E5OrPurviewSuite' }
                }
            }
            'purview.retention.exchange' {
                $adapterId = 'purview.retention.exchange'
                $retention = GetRequiredSingletonByKey @($state.Retention) $stateKeys 'retention/' $actionId
                AddExpected 'PolicyPresent' 'ExactBoolean' $true
                AddExpected 'RetentionDurationDays' 'ExactInt' ([int]$retention.DurationDays)
                AddExpected 'RetentionAction' 'CaseInsensitiveString' ([string]$retention.Action)
                AddExpected 'ExpirationDateOption' 'CaseInsensitiveString' ([string]$retention.ExpirationDateOption)
                AddExpected 'Locations' 'SetEquality' @(
                    $retention.Locations | ForEach-Object { ([string]$_).ToLowerInvariant() }
                )
            }
            'purview.ai.copilot-dlp' {
                $adapterId = 'purview.ai.copilot-dlp'
                $items = @(GetStateItemsByKey @($state.AIGovernance) $stateKeys 'ai/' $actionId $requiresStateKeys)
                $modes = @(GetStringSet ($items | ForEach-Object { $_.Mode }))
                AddExpected 'PolicyCount' 'ExactInt' ([int]$items.Count)
                AddExpected 'PolicyMode' 'SetEquality' @($modes)
                AddExpected 'EnforcementPlanes' 'SetEquality' @(
                    $items | ForEach-Object { @($_.EnforcementPlanes) } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique
                )
                AddExpected 'RestrictAccessSettings' 'SetEquality' @(
                    $items | ForEach-Object { @($_.Restrictions) } | ForEach-Object { "$($_.Setting)=$($_.Value)".ToLowerInvariant() } | Sort-Object -Unique
                )
                AddExpected 'ScopePrincipalSignatures' 'SetEquality' @(GetAiScopeSet $items)
                AddExpected 'LabelPathCount' 'ExactInt' ([int]@($items | ForEach-Object {
                    @(GetAiExpectedLabelKeys $_ $labels).Count
                } | Measure-Object -Sum).Sum)
                AddExpected 'PolicySignatures' 'SetEquality' @(
                    $items |
                        ForEach-Object {
                            $planeSet = (
                                @($_.EnforcementPlanes) |
                                    ForEach-Object { ([string]$_).ToLowerInvariant() } |
                                    Sort-Object -Unique
                            ) -join ','
                            $restrictionSet = (
                                @($_.Restrictions) |
                                    ForEach-Object { "$($_.Setting)=$($_.Value)".ToLowerInvariant() } |
                                    Sort-Object -Unique
                            ) -join ','
                            $scopeSet = (
                                GetAiScopeSet @($_)
                            ) -join ','
                            $labelSet = (
                                @(GetAiExpectedLabelKeys $_ $labels) |
                                    ForEach-Object { ([string]$_).ToLowerInvariant() } |
                                    Sort-Object -Unique
                            ) -join ','
                            'mode={0}|planes={1}|restrictions={2}|scope={3}|labels={4}' -f (
                                [string]$_.Mode
                            ).ToLowerInvariant(), $planeSet, $restrictionSet, $scopeSet, $labelSet
                        } |
                        Sort-Object -Unique
                )
                $prerequisite = [pscustomobject]@{ Kind = 'License'; Id = 'E5OrPurviewSuite' }
            }
        }

        $validation = [pscustomobject]@{
            AdapterId = $adapterId
            Selector = $selector
            Scored = ([string]$action.Intent -in @('Included', 'Conditional') -and $expected.Count -gt 0)
            Prerequisite = $prerequisite
            Expected = $expected.ToArray()
        }
        if ($action.PSObject.Properties['Validation']) {
            $action.Validation = $validation
        } else {
            $action | Add-Member -NotePropertyName Validation -NotePropertyValue $validation
        }
    }
}

function Test-PurviewValidationUniqueKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Items,
        [Parameter(Mandatory)] [string] $Property,
        [Parameter(Mandatory)] [string] $Name
    )

    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in @($Items)) {
        $value = if ($item -and $item.PSObject.Properties[$Property]) {
            [string]$item.$Property
        } else {
            ''
        }
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "Deployment Plan intended state collection '$Name' contains a record without '$Property'."
        }
        if (-not $seen.Add($value)) {
            throw "Deployment Plan intended state collection '$Name' contains duplicate key '$value'."
        }
    }
}

function Test-PurviewValidationRequiredArray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $InputObject,
        [Parameter(Mandatory)] [string] $Property,
        [Parameter(Mandatory)] [string] $Name
    )

    if (-not $InputObject.PSObject.Properties[$Property]) {
        throw "Deployment Plan intended state is missing required collection '$Name'."
    }
    $value = $InputObject.PSObject.Properties[$Property].Value
    if ($null -eq $value) {
        throw "Deployment Plan intended state collection '$Name' is null."
    }
    if ($value -is [string] -or
        $value -is [System.Collections.IDictionary] -or
        $value -is [pscustomobject]) {
        throw "Deployment Plan intended state collection '$Name' must be an array."
    }
    return @($value)
}

function Test-PurviewValidationPlan {
    <#
        Validates an operator-supplied Deployment Plan before anything
        authenticates.

        Schema 1.0 is a readable plan but not a valid validation baseline: it
        carries intent without expected managed state, so accepting it would
        mean inventing a baseline. It is rejected with an instruction to
        regenerate rather than silently downgraded.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Allowlist,
        [Parameter()] [string] $SupportedSchemaVersion = '1.2'
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Deployment Plan JSON not found: $Path"
    }

    $raw = Get-Content -LiteralPath $Path -Raw
    try {
        $plan = $raw | ConvertFrom-Json -Depth 25
    } catch {
        throw "Deployment Plan JSON could not be parsed: $($_.Exception.Message)"
    }
    Test-PurviewValidationJsonShape -Raw $raw

    foreach ($property in @(
        'SchemaVersion', 'ArtifactType', 'Product', 'PlanId', 'PlanReference',
        'ManagedByTag', 'PlanInputSha256', 'IntendedStateSha256', 'IntendedState',
        'Actions', 'Handoff'
    )) {
        if (-not $plan.PSObject.Properties[$property]) {
            throw "Deployment Plan is missing required property '$property'."
        }
    }

    $planVersion = $null
    if (-not [version]::TryParse([string]$plan.SchemaVersion, [ref]$planVersion)) {
        throw "Deployment Plan schema '$($plan.SchemaVersion)' is not a version number."
    }
    $supported = [version]$SupportedSchemaVersion
    # Same major, at least the supported minor. A newer minor is additive by
    # contract, and anything it adds that this validator does not recognize is
    # rejected by the adapter and comparator allowlists below.
    if ($planVersion.Major -ne $supported.Major -or $planVersion.Minor -lt $supported.Minor) {
        throw (
            "Deployment Plan schema '$($plan.SchemaVersion)' cannot be used as a " +
            "validation baseline. Regenerate the plan with the current toolkit " +
            "so it carries schema $SupportedSchemaVersion validation baselines, " +
            'then rerun validation.')
    }

    if ([string]$plan.Product -ne 'Purview') {
        throw "Deployment Plan product '$($plan.Product)' is not Purview."
    }
    if ([string]$plan.ArtifactType -ne 'PurviewDeploymentPlan') {
        throw "Artifact type '$($plan.ArtifactType)' is not a Purview Deployment Plan."
    }
    if ([string]$plan.PlanReference -notmatch '^PUR-\d{8}-\d{6}-[0-9A-F]{8}$') {
        throw 'Deployment Plan reference is malformed.'
    }

    $requiredCapabilities = @(
        'IntendedState',
        'ManagedOwnership',
        'PublicationMode',
        'EncryptionSettings',
        'OpaquePrincipalDigests',
        'MultipleRecordsPerAction',
        'CanonicalPublicLocations',
        'RetentionLocationDisposition',
        'OpaqueLocationDigests'
    )
    $capabilities = @(
        if ($plan.Handoff.PSObject.Properties['Capabilities']) {
            @($plan.Handoff.Capabilities) | ForEach-Object { [string]$_ }
        }
    )
    foreach ($capability in $requiredCapabilities) {
        if ($capability -notin $capabilities) {
            throw "Deployment Plan handoff is missing required capability '$capability'."
        }
    }

    # Ownership is decided by the managed tag. Without it every policy in the
    # tenant would be treated as toolkit-managed, which turns a customer's own
    # objects into drift or, worse, into a false match.
    if (-not $plan.PSObject.Properties['ManagedByTag'] -or
        [string]::IsNullOrWhiteSpace([string]$plan.ManagedByTag)) {
        throw (
            'Deployment Plan carries no managed-object tag, so toolkit-owned ' +
            'objects cannot be told apart from customer-owned ones. Regenerate ' +
            'the plan from a configuration that sets ManagedByTag.')
    }

    $planGuid = [guid]::Empty
    if (-not [guid]::TryParse([string]$plan.PlanId, [ref]$planGuid)) {
        throw 'Deployment Plan PlanId is not a valid identifier.'
    }

    if ([string]$plan.PlanInputSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Deployment Plan input fingerprint is not a SHA-256 value.'
    }
    if ([string]$plan.IntendedStateSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Deployment Plan intended-state fingerprint is not a SHA-256 value.'
    }
    $intendedState = $plan.IntendedState
    $tenantState = @(Test-PurviewValidationRequiredArray $intendedState 'TenantSettings' 'TenantSettings')
    $labelState = @(Test-PurviewValidationRequiredArray $intendedState 'Labels' 'Labels')
    $dlpState = @(Test-PurviewValidationRequiredArray $intendedState 'DlpPolicies' 'DlpPolicies')
    $aiState = @(Test-PurviewValidationRequiredArray $intendedState 'AIGovernance' 'AIGovernance')
    foreach ($property in @('LabelPolicy', 'Encryption', 'Retention')) {
        if (-not $intendedState.PSObject.Properties[$property] -or
            $null -eq $intendedState.PSObject.Properties[$property].Value) {
            throw "Deployment Plan intended state is missing required record '$property'."
        }
    }
    Test-PurviewValidationUniqueKey -Items $tenantState -Property 'Key' -Name 'TenantSettings'
    Test-PurviewValidationUniqueKey -Items $labelState -Property 'Key' -Name 'Labels'
    Test-PurviewValidationUniqueKey -Items $dlpState -Property 'Key' -Name 'DlpPolicies'
    Test-PurviewValidationUniqueKey -Items $aiState -Property 'Key' -Name 'AIGovernance'
    foreach ($dlp in $dlpState) {
        foreach ($property in @('NotifyUser', 'GenerateIncidentReport', 'LabelKeys')) {
            if (-not $dlp.PSObject.Properties[$property]) {
                throw "Deployment Plan DLP intended-state record '$($dlp.Key)' is missing '$property'."
            }
            $null = @($dlp.PSObject.Properties[$property].Value)
        }
    }
    if ([string]::IsNullOrWhiteSpace([string]$intendedState.LabelPolicy.PublicationMode)) {
        throw 'Deployment Plan label policy intended state is missing PublicationMode.'
    }
    foreach ($property in @('PublishedLabelKeys', 'TenantDependentParentKeys')) {
        if (-not $intendedState.LabelPolicy.PSObject.Properties[$property]) {
            throw "Deployment Plan label policy intended state is missing '$property'."
        }
        $null = @($intendedState.LabelPolicy.PSObject.Properties[$property].Value)
    }
    foreach ($property in @('OfflineAccessDays', 'ContentExpiration')) {
        if (-not $intendedState.Encryption.PSObject.Properties[$property]) {
            throw "Deployment Plan encryption intended state is missing '$property'."
        }
    }
    foreach ($property in @('Locations', 'UnsupportedLocations')) {
        if (-not $intendedState.Retention.PSObject.Properties[$property]) {
            throw "Deployment Plan retention intended state is missing '$property'."
        }
        $value = $intendedState.Retention.PSObject.Properties[$property].Value
        if ($value -is [string] -or
            $value -is [System.Collections.IDictionary] -or
            $value -is [pscustomobject]) {
            throw "Deployment Plan retention intended-state '$property' must be an array."
        }
    }
    if ([string]$intendedState.Retention.LocationDisposition -notin @(
        'Supported',
        'Partial',
        'UnsupportedOnly',
        'Empty'
    )) {
        throw "Deployment Plan retention LocationDisposition '$($intendedState.Retention.LocationDisposition)' is not supported."
    }
    $actualIntendedHash = Get-PurviewValidationSha256 -Text (
        $plan.IntendedState | ConvertTo-Json -Depth 20 -Compress
    )
    if ($actualIntendedHash -cne [string]$plan.IntendedStateSha256) {
        throw 'Deployment Plan intended-state fingerprint does not match its content.'
    }

    $fingerprintInput = [ordered]@{
        Product = [string]$plan.Product
        ManagedByTag = [string]$plan.ManagedByTag
        EffectiveParameters = $plan.EffectiveParameters
        IntendedState = $plan.IntendedState
        Guide = [ordered]@{
            Id = [string]$plan.Guide.Id
            Edition = [string]$plan.Guide.Edition
            RevisionDate = [string]$plan.Guide.RevisionDate
            SourceModifiedDate = [string]$plan.Guide.SourceModifiedDate
            Publisher = [string]$plan.Guide.Publisher
            SourceClassification = [string]$plan.Guide.SourceClassification
            SourceFileName = [string]$plan.Guide.SourceFileName
            Levels = @($plan.Guide.Levels)
        }
        SupportingGuides = @(
            $plan.SupportingGuides | Sort-Object { $_.Guide.Id } | ForEach-Object {
                [pscustomobject][ordered]@{
                    Guide = [pscustomobject][ordered]@{
                        Id = [string]$_.Guide.Id
                        Edition = [string]$_.Guide.Edition
                        RevisionDate = [string]$_.Guide.RevisionDate
                        Publisher = [string]$_.Guide.Publisher
                        SourceClassification = [string]$_.Guide.SourceClassification
                        SourceUri = [string]$_.Guide.SourceUri
                        SourceCommit = [string]$_.Guide.SourceCommit
                    }
                    GuideControls = @($_.GuideControls | Sort-Object ControlId)
                }
            }
        )
        Modules = @($plan.Modules)
        Actions = @($plan.Actions | Sort-Object ActionId)
        GuideControls = @($plan.GuideControls | Sort-Object ControlId)
    }
    $actualPlanHash = Get-PurviewValidationSha256 -Text (
        $fingerprintInput | ConvertTo-Json -Depth 20 -Compress
    )
    if ($actualPlanHash -cne [string]$plan.PlanInputSha256) {
        throw 'Deployment Plan input fingerprint does not match its content.'
    }

    $actions = @($plan.Actions)
    if ($actions.Count -eq 0) {
        throw 'Deployment Plan contains no actions to assess.'
    }

    $supportedActionIds = @(
        'purview.tenant.audit-standard', 'purview.tenant.spo-labels',
        'purview.tenant.pdf-labels', 'purview.tenant.container-directory-setting',
        'purview.tenant.label-coauthoring', 'purview.tenant.audit-premium',
        'purview.labels.taxonomy', 'purview.labels.priority',
        'purview.labels.publish', 'purview.labels.attachment-inheritance',
        'purview.labels.content-marking', 'purview.labels.encryption',
        'purview.labels.container-scope', 'purview.dlp.exchange',
        'purview.dlp.sharepoint-onedrive', 'purview.dlp.endpoint',
        'purview.retention.exchange', 'purview.ai.copilot-dlp'
    )

    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($action in $actions) {
        $actionId = [string]$action.ActionId
        if ($actionId -notmatch '^purview\.[a-z0-9]+(\.[a-z0-9-]+)+$') {
            throw "Deployment Plan action ID '$actionId' is malformed."
        }
        if (-not $seen.Add($actionId)) {
            throw "Deployment Plan action ID '$actionId' is duplicated."
        }
        if ($actionId -notin $supportedActionIds -and
            [string]$action.Intent -notin @('Excluded', 'NotConfigured')) {
            throw (
                "Deployment Plan action '$actionId' is not supported by this validator. " +
                "The plan uses schema $($plan.SchemaVersion); update the toolkit before validating it."
            )
        }
        if ([string]$action.Intent -notin @('Included', 'Excluded', 'Conditional', 'NotConfigured')) {
            throw "Deployment Plan action '$actionId' has unsupported intent '$($action.Intent)'."
        }
        if ($action.PSObject.Properties['Validation'] -and $null -ne $action.Validation) {
            throw "Deployment Plan action '$actionId' carries unsupported validation instructions. Regenerate the plan with schema 1.2 intended state only."
        }
    }

    Set-PurviewValidationFromIntendedState -Plan $plan

    $adapterIds = @(@($Allowlist['Adapters']) | ForEach-Object { [string]$_['Id'] })
    $comparators = @($Allowlist['Comparators'])
    $prerequisiteKinds = @($Allowlist['PrerequisiteKinds'])
    $licensePrerequisites = @($Allowlist['LicensePrerequisites'])
    $capabilityPrerequisites = @($Allowlist['CapabilityPrerequisites'])
    foreach ($action in @($plan.Actions)) {
        $actionId = [string]$action.ActionId
        $validation = $action.Validation
        if (-not [bool]$validation.Scored -and $actionId -notin $supportedActionIds) {
            continue
        }
        if ([string]$validation.AdapterId -notin $adapterIds) {
            throw "Derived validation for action '$actionId' named unknown validation adapter '$($validation.AdapterId)'."
        }
        $selector = if ($validation.PSObject.Properties['Selector']) { [string]$validation.Selector } else { '' }
        if ($selector -and $selector -notmatch '^[A-Za-z0-9._-]{1,64}$') {
            throw "Derived validation for action '$actionId' has a malformed adapter selector."
        }

        $prerequisiteKind = [string]$validation.Prerequisite.Kind
        if ($prerequisiteKind -notin $prerequisiteKinds) {
            throw "Derived validation for action '$actionId' names unknown prerequisite kind '$prerequisiteKind'."
        }
        $prerequisiteId = [string]$validation.Prerequisite.Id
        if ($prerequisiteKind -eq 'License' -and $prerequisiteId -notin $licensePrerequisites) {
            throw "Derived validation for action '$actionId' names unknown license prerequisite '$prerequisiteId'."
        }
        if ($prerequisiteKind -eq 'Capability' -and $prerequisiteId -notin $capabilityPrerequisites) {
            throw "Derived validation for action '$actionId' names unknown capability prerequisite '$prerequisiteId'."
        }

        $adapter = @(@($Allowlist['Adapters']) | Where-Object { [string]$_['Id'] -eq [string]$validation.AdapterId })[0]
        $managedFields = @($adapter['ManagedFields'])
        foreach ($field in @($validation.Expected)) {
            if ([string]$field.Field -notin $managedFields) {
                throw "Derived validation for action '$actionId' expects unmanaged field '$($field.Field)'."
            }
            $comparator = [string]$field.Comparator
            if ($comparator -notin $comparators) {
                throw "Derived validation for action '$actionId' names unknown comparator '$comparator'."
            }
            Test-PurviewValidationExpectedType -ActionId $actionId -Field ([string]$field.Field) `
                -Comparator $comparator -Value $field.Value
        }

        if ([bool]$validation.Scored -and @($validation.Expected).Count -eq 0) {
            throw "Derived validation for action '$actionId' is scored but declares no expected managed fields."
        }
    }

    return $plan
}

function New-PurviewValidationResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Action,
        [Parameter(Mandatory)]
        [ValidateSet('Matched', 'Drift', 'Not evaluated', 'Informational', 'Collection failed')]
        [string] $Status,
        [Parameter(Mandatory)] [string] $Reason,
        [Parameter()] [string] $NextStep = '',
        [Parameter()] [object[]] $FieldComparisons = @(),
        [Parameter()] [object[]] $UnscoredDifferences = @(),
        [Parameter()] [string] $Query = '',
        [Parameter()] [string] $Source = '',
        [Parameter()] [string] $SourceVersion = '',
        [Parameter()] [int] $Attempts = 0,
        [Parameter()] [int] $ElapsedMs = 0,
        [Parameter()] [string] $ErrorText = '',
        [Parameter()] [string] $PrerequisiteDisposition = 'Not applicable'
    )

    $expectedText = ($FieldComparisons | ForEach-Object { '{0}={1}' -f $_.Field, $_.ExpectedText }) -join '; '
    $observedText = ($FieldComparisons | ForEach-Object { '{0}={1}' -f $_.Field, $_.ObservedText }) -join '; '

    return [pscustomobject][ordered]@{
        ActionId = [string]$Action.ActionId
        Module = [string]$Action.Module
        Title = [string]$Action.Title
        PlanIntent = [string]$Action.Intent
        AdapterId = [string]$Action.Validation.AdapterId
        Selector = if ($Action.Validation.PSObject.Properties['Selector']) { [string]$Action.Validation.Selector } else { '' }
        Scored = [bool]$Action.Validation.Scored
        Status = $Status
        Reason = $Reason
        NextStep = $NextStep
        ExpectedSummary = if ($expectedText) { $expectedText } else { '(not scored)' }
        ObservedSummary = if ($observedText) { $observedText } else { '(not collected)' }
        Fields = @($FieldComparisons)
        UnscoredDifferences = @($UnscoredDifferences)
        Query = $Query
        Source = $Source
        SourceVersion = $SourceVersion
        Attempts = $Attempts
        ElapsedMs = $ElapsedMs
        Error = ConvertTo-PurviewValidationRedactedText -Text $ErrorText
        PrerequisiteDisposition = $PrerequisiteDisposition
    }
}

function New-PurviewGuideAssessmentPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $GuideMapping
    )

    $definitions = [ordered]@{
        'purview.tenant.audit-standard' = [pscustomobject]@{ Adapter = 'purview.tenant.audit-standard'; Selector = ''; Fields = @(
            [pscustomobject]@{ Field = 'UnifiedAuditLogIngestionEnabled'; Comparator = 'Presence'; Value = $true }) }
        'purview.tenant.spo-labels' = [pscustomobject]@{ Adapter = 'purview.tenant.spo-labels'; Selector = ''; Fields = @(
            [pscustomobject]@{ Field = 'EnableAIPIntegration'; Comparator = 'Presence'; Value = $true }) }
        'purview.tenant.container-directory-setting' = [pscustomobject]@{ Adapter = 'purview.tenant.container-directory-setting'; Selector = ''; Fields = @(
            [pscustomobject]@{ Field = 'EnableMIPLabels'; Comparator = 'Presence'; Value = $true }) }
        'purview.labels.taxonomy' = [pscustomobject]@{ Adapter = 'purview.labels.taxonomy'; Selector = ''; Fields = @(
            [pscustomobject]@{ Field = 'RootLabelCount'; Comparator = 'Presence'; Value = $true }
            [pscustomobject]@{ Field = 'SubLabelCount'; Comparator = 'Presence'; Value = $true }) }
        'purview.labels.priority' = [pscustomobject]@{ Adapter = 'purview.labels.priority'; Selector = ''; Fields = @(
            [pscustomobject]@{ Field = 'PriorityOrder'; Comparator = 'Presence'; Value = $true }) }
        'purview.labels.publish' = [pscustomobject]@{ Adapter = 'purview.labels.publish'; Selector = ''; Fields = @(
            [pscustomobject]@{ Field = 'PolicyPresent'; Comparator = 'ExactBoolean'; Value = $true }) }
        'purview.labels.encryption' = [pscustomobject]@{ Adapter = 'purview.labels.encryption'; Selector = ''; Fields = @(
            [pscustomobject]@{ Field = 'EncryptedLabelSignatures'; Comparator = 'Presence'; Value = $true }) }
        'purview.labels.content-marking' = [pscustomobject]@{ Adapter = 'purview.labels.content-marking'; Selector = ''; Fields = @(
            [pscustomobject]@{ Field = 'ContentMarkedLabelSignatures'; Comparator = 'Presence'; Value = $true }) }
        'purview.labels.attachment-inheritance' = [pscustomobject]@{ Adapter = 'purview.labels.attachment-inheritance'; Selector = ''; Fields = @(
            [pscustomobject]@{ Field = 'AttachmentAction'; Comparator = 'Presence'; Value = $true }) }
        'purview.dlp.exchange' = [pscustomobject]@{ Adapter = 'purview.dlp.workload'; Selector = 'Exchange'; Fields = @(
            [pscustomobject]@{ Field = 'PolicyPresent'; Comparator = 'ExactBoolean'; Value = $true }
            [pscustomobject]@{ Field = 'RulePresent'; Comparator = 'ExactBoolean'; Value = $true }) }
        'purview.dlp.sharepoint-onedrive' = [pscustomobject]@{ Adapter = 'purview.dlp.workload'; Selector = 'SharePointOneDrive'; Fields = @(
            [pscustomobject]@{ Field = 'PolicyPresent'; Comparator = 'ExactBoolean'; Value = $true }
            [pscustomobject]@{ Field = 'RulePresent'; Comparator = 'ExactBoolean'; Value = $true }) }
        'purview.dlp.endpoint' = [pscustomobject]@{ Adapter = 'purview.dlp.workload'; Selector = 'Endpoint'; Fields = @(
            [pscustomobject]@{ Field = 'PolicyPresent'; Comparator = 'ExactBoolean'; Value = $true }
            [pscustomobject]@{ Field = 'RulePresent'; Comparator = 'ExactBoolean'; Value = $true }) }
    }
    $controlByAction = @{}
    foreach ($control in @($GuideMapping.Controls)) {
        foreach ($actionId in @($control.ActionIds)) {
            if (-not $controlByAction.ContainsKey([string]$actionId)) {
                $controlByAction[[string]$actionId] = [Collections.Generic.List[object]]::new()
            }
            $controlByAction[[string]$actionId].Add($control)
        }
    }

    $actions = foreach ($actionId in $controlByAction.Keys | Sort-Object) {
        if (-not $definitions.Contains($actionId)) { continue }
        $definition = $definitions[$actionId]
        $fields = @($definition.Fields)
        $prerequisite = if ($actionId -eq 'purview.dlp.endpoint') {
            [pscustomobject]@{ Kind = 'License'; Id = 'E5OrPurviewSuite' }
        } else {
            [pscustomobject]@{ Kind = 'None'; Id = '' }
        }
        [pscustomobject]@{
            ActionId = $actionId
            Module = [string](@($GuideMapping.Controls | Where-Object { $actionId -in @($_.ActionIds) })[0].Section)
            Title = [string](@($GuideMapping.Controls | Where-Object { $actionId -in @($_.ActionIds) })[0].Summary)
            Intent = 'GuideOnly'
            PrimaryGuideLevel = [string](@($controlByAction[$actionId])[0].Level)
            IntendedStateKeys = @()
            Validation = [pscustomobject]@{
                AdapterId = $definition.Adapter
                Selector = $definition.Selector
                Scored = $true
                Prerequisite = $prerequisite
                Expected = @($fields)
            }
        }
    }

    $guideControls = foreach ($control in @($GuideMapping.Controls)) {
        [pscustomobject]@{
            ControlId = [string]$control.Id
            Level = [string]$control.Level
            Summary = [string]$control.Summary
            ComparisonStatus = [string]$control.Status
            ActionIds = @($control.ActionIds)
            Rationale = [string]$control.Rationale
        }
    }
    return [pscustomobject]@{
        IsGuideOnly = $true
        SchemaVersion = ''
        PlanId = ''
        PlanReference = ''
        PlanInputSha256 = ''
        IntendedStateSha256 = ''
        ManagedByTag = '[Managed by SMBTool Purview Toolkit]'
        Guide = [pscustomobject]$GuideMapping.Guide
        GuideControls = @($guideControls)
        Actions = @($actions)
    }
}

function New-PurviewValidationModel {
    <#
        Assembles the one canonical model that both the HTML report and the
        JSON sidecar render. Neither renderer may compute a fact of its own.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Plan,
        [Parameter(Mandatory)] [object[]] $Results,
        [Parameter()] [string] $ToolkitVersion = 'unknown',
        [Parameter()] [guid] $ValidationRunId = [guid]::NewGuid(),
        [Parameter()] [datetime] $ObservedAt = [datetime]::UtcNow,
        [Parameter()] [int] $DurationSeconds = 0,
        [Parameter()] [string] $TenantDisplayName = '',
        [Parameter()] [string] $TenantIdentityCheck = 'Not verified',
        [Parameter()] [psobject] $ServiceStatus,
        [Parameter()] [object[]] $Diagnostics = @()
    )

    $isGuideOnly = $Plan.PSObject.Properties['IsGuideOnly'] -and [bool]$Plan.IsGuideOnly
    foreach ($result in $Results) {
        $observationState = switch ([string]$result.Status) {
            'Collection failed' { 'Unreadable' }
            'Not evaluated' {
                if ($result.PrerequisiteDisposition -eq 'Unsatisfied') { 'Unsupported' } else { 'Unreadable' }
            }
            'Informational' { 'Unsupported' }
            default {
                $presenceFields = @($result.Fields | Where-Object { [string]$_.Field -match 'Present$' })
                if ($presenceFields.Count -gt 0) {
                    $present = @($presenceFields | Where-Object {
                        $_.ObservedText -notin @('(not set)', 'false', '0', '(empty)')
                    }).Count -gt 0
                    if ($present) { 'Present' } else { 'Absent' }
                } else {
                    'Present'
                }
            }
        }
        $intendedState = if ($isGuideOnly) {
            'NotEvaluated'
        } else {
            switch ([string]$result.Status) {
                'Matched' { 'Match' }
                'Drift' { 'Mismatch' }
                'Informational' { 'NotInPlan' }
                default { 'NotEvaluated' }
            }
        }
        $baselineState = switch ([string]$result.Status) {
            'Matched' { 'Meets' }
            'Drift' { 'DoesNotMeet' }
            'Informational' { 'NotApplicable' }
            default { 'Indeterminate' }
        }
        $result | Add-Member -NotePropertyName Observation -NotePropertyValue $observationState -Force
        $result | Add-Member -NotePropertyName Intended -NotePropertyValue $intendedState -Force
        $result | Add-Member -NotePropertyName Baseline -NotePropertyValue $baselineState -Force
    }

    $counts = [ordered]@{}
    foreach ($status in $script:PurviewValidationStatuses) {
        $counts[$status] = @($Results | Where-Object Status -eq $status).Count
    }

    $moduleOrder = @($Results | ForEach-Object { $_.Module } | Select-Object -Unique)
    $modules = foreach ($module in $moduleOrder) {
        $moduleResults = @($Results | Where-Object Module -eq $module)
        [pscustomobject][ordered]@{
            Module = $module
            Total = $moduleResults.Count
            Matched = @($moduleResults | Where-Object Status -eq 'Matched').Count
            Drift = @($moduleResults | Where-Object Status -eq 'Drift').Count
            NotEvaluated = @($moduleResults | Where-Object Status -eq 'Not evaluated').Count
            Informational = @($moduleResults | Where-Object Status -eq 'Informational').Count
            CollectionFailed = @($moduleResults | Where-Object Status -eq 'Collection failed').Count
        }
    }

    $controlResults = foreach ($control in @($Plan.GuideControls)) {
        $mapped = @($Results | Where-Object { $_.ActionId -in @($control.ActionIds) })
        $baseline = if ([string]$control.ComparisonStatus -eq 'NotApplicable') {
            'NotApplicable'
        } elseif ($isGuideOnly -and
            [string]$control.Level -ne 'Good' -and
            [string]$control.ComparisonStatus -ne 'Aligned') {
            'Indeterminate'
        } elseif ([string]$control.ComparisonStatus -eq 'NotImplemented') {
            'Indeterminate'
        } elseif ($mapped.Count -eq 0) {
            'Indeterminate'
        } elseif (@($mapped | Where-Object Baseline -eq 'DoesNotMeet').Count -gt 0) {
            'DoesNotMeet'
        } elseif (@($mapped | Where-Object Baseline -eq 'Indeterminate').Count -gt 0) {
            'Indeterminate'
        } elseif (@($mapped | Where-Object Baseline -eq 'Meets').Count -eq $mapped.Count) {
            'Meets'
        } else {
            'Indeterminate'
        }
        [pscustomobject]@{
            ControlId = [string]$control.ControlId
            Level = [string]$control.Level
            Summary = [string]$control.Summary
            Baseline = $baseline
            ActionIds = @($control.ActionIds)
            ManualCheck = ($mapped.Count -eq 0)
            Rationale = [string]$control.Rationale
        }
    }
    $levelOrder = @('Good', 'Better', 'Best')
    $proven = 'None'
    $provisional = 'None'
    $blockers = [Collections.Generic.List[object]]::new()
    foreach ($level in $levelOrder) {
        $eligibleLevels = $levelOrder[0..[array]::IndexOf($levelOrder, $level)]
        $controls = @($controlResults | Where-Object { $_.Level -in $eligibleLevels })
        if (@($controls | Where-Object Baseline -eq 'DoesNotMeet').Count -eq 0) {
            $provisional = $level
        }
        if (@($controls | Where-Object { $_.Baseline -notin @('Meets', 'NotApplicable') }).Count -eq 0) {
            $proven = $level
        }
    }
    foreach ($control in @($controlResults | Where-Object { $_.Baseline -notin @('Meets', 'NotApplicable') })) {
        $blockers.Add([pscustomobject]@{
            ControlId = $control.ControlId
            Level = $control.Level
            Baseline = $control.Baseline
            Reason = if ($control.ManualCheck) { 'Manual verification required.' } else { 'Observed state did not prove this control.' }
        })
    }

    $recommendations = @(
        foreach ($result in @($Results | Where-Object Status -eq 'Drift')) {
            [pscustomobject][ordered]@{
                Priority = 'Review now'
                Title = $result.Title
                Detail = $result.NextStep
                ActionId = $result.ActionId
            }
        }
        foreach ($result in @($Results | Where-Object Status -eq 'Collection failed')) {
            [pscustomobject][ordered]@{
                Priority = 'Investigate read failure'
                Title = $result.Title
                Detail = $result.NextStep
                ActionId = $result.ActionId
            }
        }
        foreach ($result in @($Results | Where-Object Status -eq 'Not evaluated')) {
            [pscustomobject][ordered]@{
                Priority = 'Operator decision'
                Title = $result.Title
                Detail = $result.NextStep
                ActionId = $result.ActionId
            }
        }
        foreach ($blocker in @($blockers)) {
            [pscustomobject][ordered]@{
                Priority = 'Operator decision'
                Title = "Guide control $($blocker.ControlId)"
                Detail = $blocker.Reason
                ActionId = $blocker.ControlId
            }
        }
    )

    $safeServiceStatus = if ($ServiceStatus) {
        [pscustomobject][ordered]@{
            GraphConnected = if ($ServiceStatus.PSObject.Properties['GraphConnected']) {
                [bool]$ServiceStatus.GraphConnected
            } else { $false }
            ExchangeConnected = if ($ServiceStatus.PSObject.Properties['ExchangeOnlineConnected']) {
                [bool]$ServiceStatus.ExchangeOnlineConnected
            } elseif ($ServiceStatus.PSObject.Properties['ExchangeConnected']) {
                [bool]$ServiceStatus.ExchangeConnected
            } else { $false }
            SecurityComplianceConnected = if ($ServiceStatus.PSObject.Properties['SecurityComplianceConnected']) {
                [bool]$ServiceStatus.SecurityComplianceConnected
            } else { $false }
            SharePointConnected = if ($ServiceStatus.PSObject.Properties['SharePointConnected']) {
                [bool]$ServiceStatus.SharePointConnected
            } else { $false }
            SharePointUnavailable = if ($ServiceStatus.PSObject.Properties['SharePointUnavailable']) {
                [bool]$ServiceStatus.SharePointUnavailable
            } else { $false }
        }
    } else { $null }

    $controlActionIds = @($controlResults | ForEach-Object { @($_.ActionIds) })
    $reference = 'PUR-VAL-' + $ValidationRunId.ToString().Substring(0, 8).ToUpperInvariant()
    return [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        ArtifactType = 'PurviewTenantValidation'
        ArtifactReference = $reference
        Product = 'Purview'
        AssessmentMode = $(if ($isGuideOnly) { 'GuideOnly' } else { 'PlanComparison' })
        ToolkitVersion = $ToolkitVersion
        ValidationRunId = $ValidationRunId.ToString()
        ObservedAtUtc = $ObservedAt.ToUniversalTime().ToString('o')
        DurationSeconds = $DurationSeconds
        Disclaimer = 'This standalone report compares observable tenant settings with one Deployment Plan. It is separate from the deployment run report and does not assess regulatory compliance, data-protection effectiveness, or user adoption.'
        Plan = [pscustomobject][ordered]@{
            PlanId = [string]$Plan.PlanId
            PlanReference = if ($Plan.PSObject.Properties['PlanReference']) { [string]$Plan.PlanReference } else { '' }
            SchemaVersion = [string]$Plan.SchemaVersion
            PlanInputSha256 = [string]$Plan.PlanInputSha256
            IntendedStateSha256 = if ($Plan.PSObject.Properties['IntendedStateSha256']) { [string]$Plan.IntendedStateSha256 } else { '' }
            GeneratedAtUtc = if ($Plan.PSObject.Properties['GeneratedAtUtc']) { [string]$Plan.GeneratedAtUtc } else { '' }
            ConfigurationSha256 = if ($Plan.PSObject.Properties['Configuration']) { [string]$Plan.Configuration.Sha256 } else { '' }
        }
        Tenant = [pscustomobject][ordered]@{
            DisplayName = ''
            IdentityCheck = $TenantIdentityCheck
        }
        ServiceStatus = $safeServiceStatus
        Summary = [pscustomobject][ordered]@{
            TotalActions = @($Results).Count
            Matched = $counts['Matched']
            Drift = $counts['Drift']
            NotEvaluated = $counts['Not evaluated']
            Informational = $counts['Informational']
            CollectionFailed = $counts['Collection failed']
            # 'Not evaluated' covers two situations an operator answers
            # differently: a prerequisite the tenant genuinely does not meet
            # (nothing to do) and one that could not be read (investigate
            # connectivity, consent, or roles). The status vocabulary is fixed
            # at five values, so the distinction is surfaced as a count.
            PrerequisiteUnmet = @($Results | Where-Object {
                $_.Status -eq 'Not evaluated' -and $_.PrerequisiteDisposition -eq 'Unsatisfied'
            }).Count
            PrerequisiteUnknown = @($Results | Where-Object {
                $_.Status -eq 'Not evaluated' -and $_.PrerequisiteDisposition -eq 'Unknown'
            }).Count
            ScoredActions = @($Results | Where-Object Scored).Count
            ProvenLevel = $proven
            ProvisionalLevel = $provisional
        }
        Modules = @($modules)
        Results = @($Results)
        Guide = [pscustomobject]@{
            Id = [string]$Plan.Guide.Id
            Title = [string]$Plan.Guide.Title
            Levels = @($Plan.Guide.Levels)
            Controls = @($controlResults)
            Blockers = $blockers.ToArray()
        }
        Extensions = @($Results | Where-Object { $_.ActionId -notin $controlActionIds })
        ManualChecks = @($controlResults | Where-Object ManualCheck)
        Recommendations = @($recommendations)
        Diagnostics = @($Diagnostics)
    }
}

function Get-PurviewValidationExitCode {
    <#
        Maps a canonical model onto the documented exit codes:

            0  no drift and no collection failures
            2  drift present
            4  collection failure present
            6  both
            1  fatal input, schema, identity, or connection failure

        Exit code 1 is produced by the entry point before a model exists, so it
        is never returned from here.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [psobject] $Model
    )

    $code = $script:PurviewValidationExitClean
    if ([int]$Model.Summary.Drift -gt 0) { $code = $code -bor $script:PurviewValidationExitDrift }
    if ([int]$Model.Summary.CollectionFailed -gt 0) {
        $code = $code -bor $script:PurviewValidationExitCollectionFailure
    }
    return $code
}
