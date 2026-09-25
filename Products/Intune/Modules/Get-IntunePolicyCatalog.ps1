#requires -Version 7.0

function Get-IntunePolicyContentHash {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Content)

    # Git may materialize text files with LF or CRLF depending on platform and
    # checkout settings. Hash the canonical LF representation so integrity is
    # stable across Windows, macOS, Linux, and public-repository promotion.
    $normalized = $Content.Replace("`r`n", "`n").Replace("`r", "`n")
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($normalized)
        )
    )
}

function Assert-IntunePolicyPayloadShape {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Payload,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Entry
    )

    $factoryResetAccounts = $Payload.PSObject.Properties[
        'factoryResetDeviceAdministratorEmails'
    ]
    if ($factoryResetAccounts -and @($factoryResetAccounts.Value).Count -gt 0) {
        throw "Intune policy catalog payload '$($Entry.Key)' contains environment-specific Factory Reset Protection accounts."
    }

    $requiredProperties = switch ([string] $Entry.Kind) {
        'SettingsCatalog' { @('name', 'platforms', 'technologies', 'settings') }
        'Compliance' { @('displayName') }
        'DeviceConfiguration' { @('displayName') }
    }
    foreach ($name in $requiredProperties) {
        $property = $Payload.PSObject.Properties[$name]
        if (-not $property -or $null -eq $property.Value) {
            throw "Intune policy catalog payload '$($Entry.Key)' must define '$name' for kind '$($Entry.Kind)'."
        }
        if ($property.Value -is [string] -and
            [string]::IsNullOrWhiteSpace([string] $property.Value)) {
            throw "Intune policy catalog payload '$($Entry.Key)' must define '$name' for kind '$($Entry.Kind)'."
        }
    }
    if ($Entry.Kind -eq 'SettingsCatalog' -and @($Payload.settings).Count -eq 0) {
        throw "Intune policy catalog payload '$($Entry.Key)' must contain settings."
    }
}

function Get-IntunePolicyCatalog {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [switch] $IncludePayload
    )

    if (-not $Config.ContainsKey('PolicyCatalog')) {
        throw 'Intune configuration must define a PolicyCatalog section.'
    }
    foreach ($name in @('ManifestPath', 'RequiredEntryCount')) {
        if (-not $Config.PolicyCatalog.ContainsKey($name)) {
            throw "PolicyCatalog must define '$name'."
        }
    }
    if ($Config.PolicyCatalog.RequiredEntryCount -isnot [int] -or
        $Config.PolicyCatalog.RequiredEntryCount -lt 1) {
        throw 'PolicyCatalog.RequiredEntryCount must be a positive integer.'
    }

    $productRoot = Split-Path -Parent $PSScriptRoot
    $productRootFull = [IO.Path]::GetFullPath($productRoot)
    $manifestPath = [IO.Path]::GetFullPath(
        (Join-Path $productRoot ([string] $Config.PolicyCatalog.ManifestPath))
    )
    $productPrefix = $productRootFull.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar
    if (-not $manifestPath.StartsWith(
            $productPrefix,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'PolicyCatalog.ManifestPath must remain inside Products/Intune.'
    }
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Intune policy catalog manifest not found: $manifestPath"
    }

    $manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
    foreach ($name in @(
            'CatalogVersion',
            'SourceName',
            'SourceReviewDate',
            'RequiredEntryCount',
            'Entries'
        )) {
        if (-not $manifest.ContainsKey($name)) {
            throw "Intune policy catalog manifest must define '$name'."
        }
    }
    if ($manifest.RequiredEntryCount -ne $Config.PolicyCatalog.RequiredEntryCount) {
        throw 'Policy catalog entry-count contract differs between configuration and manifest.'
    }

    $entries = @($manifest.Entries)
    if ($entries.Count -ne $manifest.RequiredEntryCount) {
        throw "Intune policy catalog expected $($manifest.RequiredEntryCount) entries but contains $($entries.Count)."
    }

    $catalogRoot = Split-Path -Parent $manifestPath
    $catalogRootFull = [IO.Path]::GetFullPath($catalogRoot)
    $catalogPrefix = $catalogRootFull.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar
    $keys = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $paths = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $result = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $entries) {
        foreach ($name in @(
                'Key',
                'RelativePath',
                'Tier',
                'Platform',
                'Kind',
                'ExpectedDiscriminator',
                'SourceApiProfile',
                'ApplyStatus',
                'SourceSha256',
                'Sha256'
            )) {
            if ([string]::IsNullOrWhiteSpace([string] $entry[$name])) {
                throw "Intune policy catalog entry must define '$name'."
            }
        }
        if ($entry.Key -notmatch '^[a-z0-9]+(?:-[a-z0-9]+)+$') {
            throw "Intune policy catalog key '$($entry.Key)' must be lowercase kebab-case."
        }
        if (-not $keys.Add([string] $entry.Key)) {
            throw "Duplicate Intune policy catalog key '$($entry.Key)'."
        }
        if ($entry.Tier -notin @('Baseline', 'Advanced', 'Windows')) {
            throw "Intune policy catalog entry '$($entry.Key)' has unsupported tier '$($entry.Tier)'."
        }
        if ($entry.Kind -notin @('Compliance', 'DeviceConfiguration', 'SettingsCatalog')) {
            throw "Intune policy catalog entry '$($entry.Key)' has unsupported kind '$($entry.Kind)'."
        }
        if ($entry.ApplyStatus -ne 'Blocked') {
            throw "Intune policy catalog entry '$($entry.Key)' must remain ApplyStatus Blocked."
        }
        foreach ($digestName in @('SourceSha256', 'Sha256')) {
            if ([string] $entry[$digestName] -notmatch '^[0-9A-F]{64}$') {
                throw "Intune policy catalog entry '$($entry.Key)' has an invalid $digestName."
            }
        }

        $payloadPath = [IO.Path]::GetFullPath(
            (Join-Path $catalogRoot ([string] $entry.RelativePath))
        )
        if (-not $payloadPath.StartsWith(
                $catalogPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Intune policy catalog path for '$($entry.Key)' leaves the catalog root."
        }
        if (-not $paths.Add($payloadPath)) {
            throw "Duplicate Intune policy catalog path '$($entry.RelativePath)'."
        }
        if (-not (Test-Path -LiteralPath $payloadPath -PathType Leaf)) {
            throw "Intune policy catalog payload not found for '$($entry.Key)'."
        }

        $payloadContent = [IO.File]::ReadAllText($payloadPath)
        $actualHash = Get-IntunePolicyContentHash -Content $payloadContent
        if (-not [string]::Equals(
                $actualHash,
                [string] $entry.Sha256,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Intune policy catalog payload hash mismatch for '$($entry.Key)'."
        }

        try {
            $payload = $payloadContent | ConvertFrom-Json -Depth 100
        }
        catch {
            throw "Intune policy catalog payload '$($entry.Key)' is not valid JSON."
        }
        Assert-IntunePolicyPayloadShape -Payload $payload -Entry $entry
        foreach ($forbidden in @(
                'id',
                'createdDateTime',
                'lastModifiedDateTime',
                'creationSource',
                'priorityMetaData',
                'settingCount',
                'version',
                'assignments',
                'groupId'
            )) {
            if ($payload.PSObject.Properties[$forbidden]) {
                throw "Intune policy catalog payload '$($entry.Key)' contains forbidden root property '$forbidden'."
            }
        }

        $typeProperty = $payload.PSObject.Properties['@odata.type']
        $contextProperty = $payload.PSObject.Properties['@odata.context']
        $discriminator = if (
            $typeProperty -and
            -not [string]::IsNullOrWhiteSpace([string] $typeProperty.Value)
        ) {
            [string] $typeProperty.Value
        }
        elseif ($contextProperty) {
            [string] $contextProperty.Value
        }
        else {
            $null
        }
        if (-not [string]::Equals(
                $discriminator,
                [string] $entry.ExpectedDiscriminator,
                [StringComparison]::Ordinal
            )) {
            throw "Intune policy catalog payload '$($entry.Key)' has an unexpected Graph discriminator."
        }

        $result.Add([pscustomobject] @{
                Key = [string] $entry.Key
                RelativePath = [string] $entry.RelativePath
                Tier = [string] $entry.Tier
                Platform = [string] $entry.Platform
                Kind = [string] $entry.Kind
                SourceApiProfile = [string] $entry.SourceApiProfile
                ApplyStatus = [string] $entry.ApplyStatus
                Sha256 = [string] $entry.Sha256
                Payload = if ($IncludePayload) { $payload } else { $null }
            })
    }

    $catalogFiles = @(
        Get-ChildItem -LiteralPath $catalogRoot -Recurse -File -Filter '*.json'
    )
    $unlistedFiles = @(
        $catalogFiles | Where-Object {
            -not $paths.Contains([IO.Path]::GetFullPath($_.FullName))
        }
    )
    if ($unlistedFiles.Count -gt 0) {
        throw "Intune policy catalog contains $($unlistedFiles.Count) unlisted JSON payload(s)."
    }

    return @($result)
}
