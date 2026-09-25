#requires -Version 7.0
# smb-quality-gate: read-only
<#
.SYNOPSIS
    Validates and normalizes local Purview configuration values.

.DESCRIPTION
    This helper is local-only. It imports no service module and performs no
    authentication, tenant read, or tenant write.
#>

$script:PurviewBuiltInLabelPattern =
    '^defa4170-0d19-0005-[0-9a-fA-F]{4}-bc88714345d2$'
$script:PurviewMicrosoft365CopilotLocationGuid =
    '470f2276-e011-4e9d-a6ec-20768be3a4b0'
$script:PurviewMicrosoft365CopilotLocationToken = 'Microsoft365Copilot'
$script:PurviewSupportedRetentionLocations = @(
    'Exchange',
    'OneDrive',
    'SharePoint'
)
$script:PurviewKnownRetentionLocationTokens = @(
    'DefenderForCloudApps',
    'Exchange',
    'OneDrive',
    'OnPremisesScanner',
    'PowerBI',
    'SharePoint',
    'Teams'
)

function Test-PurviewBuiltInLabelName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Value
    )

    return [string]::IsNullOrWhiteSpace($Value) -or
        $Value -match '^defa4170-0d19-0005-[0-9a-fA-F]{4}-bc88714345d2$'
}

function Assert-PurviewLabelIdentityConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Config
    )

    $labels = @(
        if ($Config.Contains('Labels')) { @($Config['Labels']) }
    )
    for ($rootIndex = 0; $rootIndex -lt $labels.Count; $rootIndex++) {
        $root = $labels[$rootIndex]
        if (-not $root) { continue }

        $rootBuiltInName = if ($root -is [System.Collections.IDictionary] -and
            $root.Contains('BuiltInName')) {
            [string]$root['BuiltInName']
        } else { '' }
        if (-not (Test-PurviewBuiltInLabelName -Value $rootBuiltInName)) {
            throw (
                "Configuration Labels[$rootIndex].BuiltInName is invalid. " +
                "Use a Microsoft built-in signature matching " +
                "'defa4170-0d19-0005-NNNN-bc88714345d2' or leave it empty for a custom label."
            )
        }

        $children = @(
            if ($root -is [System.Collections.IDictionary] -and
                $root.Contains('SubLabels')) {
                @($root['SubLabels'])
            }
        )
        for ($childIndex = 0; $childIndex -lt $children.Count; $childIndex++) {
            $child = $children[$childIndex]
            if (-not $child) { continue }

            $childBuiltInName = if ($child -is [System.Collections.IDictionary] -and
                $child.Contains('BuiltInName')) {
                [string]$child['BuiltInName']
            } else { '' }
            if (-not (Test-PurviewBuiltInLabelName -Value $childBuiltInName)) {
                throw (
                    "Configuration Labels[$rootIndex].SubLabels[$childIndex].BuiltInName is invalid. " +
                    "Use a Microsoft built-in signature matching " +
                    "'defa4170-0d19-0005-NNNN-bc88714345d2' or leave it empty for a custom label."
                )
            }
        }
    }
}

function ConvertTo-PurviewCanonicalPublicLocation {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Value
    )

    $candidate = $Value.Trim()
    if ($candidate -ieq $script:PurviewMicrosoft365CopilotLocationGuid -or
        $candidate -ieq $script:PurviewMicrosoft365CopilotLocationToken) {
        return $script:PurviewMicrosoft365CopilotLocationToken
    }
    return $candidate
}

function Get-PurviewLocationIdentity {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Value
    )

    $candidate = $Value.Trim()
    $canonical = ConvertTo-PurviewCanonicalPublicLocation -Value $candidate
    if ($canonical -eq $script:PurviewMicrosoft365CopilotLocationToken) {
        return [pscustomobject][ordered]@{
            Value = $canonical
            Class = 'PublicProductLocation'
            Digest = ''
        }
    }
    if (-not $candidate) {
        return [pscustomobject][ordered]@{
            Value = ''
            Class = 'Empty'
            Digest = ''
        }
    }

    $bytes = [Text.Encoding]::UTF8.GetBytes($candidate.ToLowerInvariant())
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    $protectedValue = Protect-PurviewConfigurationEvidenceText -Text $candidate
    if ($protectedValue -eq $candidate) {
        $protectedValue = '[REDACTED-LOCATION]'
    }
    return [pscustomobject][ordered]@{
        Value = $protectedValue
        Class = 'CustomLocation'
        Digest = 'sha256:' + (
            [Convert]::ToHexString($hash).ToLowerInvariant()
        ).Substring(0, 24)
    }
}

function Protect-PurviewConfigurationEvidenceText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $protected = $Text -replace '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '[REDACTED-UPN]'
    $protected = $protected -replace '(?i)\b[A-Z0-9-]+\.onmicrosoft\.com\b', '[REDACTED-DOMAIN]'
    $protected = $protected -replace '(?i)https?://\S+', '[REDACTED-URL]'
    $protected = $protected -replace '(?i)\b(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b', '[REDACTED-DOMAIN]'
    $protected = $protected -replace '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '[REDACTED-GUID]'
    if ($protected -match '(?i)(?:\b[A-Z]:\\|\\\\[^\\\s]+\\|/(?:home|Users)/)') {
        return '[REDACTED-LOCAL-PATH]'
    }
    return $protected
}

function Get-PurviewRetentionLocationClassification {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object] $Value
    )

    $values = if ($Value -is [string]) {
        @($Value -split ',')
    } else {
        @($Value)
    }
    $supported = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $unsupported = [Collections.Generic.List[string]]::new()
    $unsupportedEvidence = [Collections.Generic.List[string]]::new()

    foreach ($item in $values) {
        $candidate = ([string]$item).Trim()
        if (-not $candidate) { continue }

        $canonical = @(
            $script:PurviewSupportedRetentionLocations |
                Where-Object { $_ -ieq $candidate }
        ) | Select-Object -First 1
        if ($canonical) {
            $null = $supported.Add([string]$canonical)
            continue
        }

        $unsupported.Add($candidate)
        $knownToken = @(
            $script:PurviewKnownRetentionLocationTokens |
                Where-Object { $_ -ieq $candidate }
        ) | Select-Object -First 1
        $evidence = if ($knownToken) {
            [string]$knownToken
        } else {
            Protect-PurviewConfigurationEvidenceText -Text $candidate
        }
        if ($evidence -eq $candidate -and -not $knownToken) {
            $evidence = '[REDACTED-LOCATION]'
        }
        $unsupportedEvidence.Add($evidence)
    }

    return [pscustomobject][ordered]@{
        Supported = @($supported | Sort-Object)
        Unsupported = @($unsupported | Sort-Object -Unique)
        UnsupportedEvidence = @($unsupportedEvidence | Sort-Object -Unique)
    }
}
