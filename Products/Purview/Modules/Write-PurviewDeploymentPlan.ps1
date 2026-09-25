#requires -Version 7.0
<#
.SYNOPSIS
    Builds and writes the offline Purview Deployment Plan.

.DESCRIPTION
    Creates one canonical intent model from local configuration, effective
    switches, and the versioned Microsoft guide mapping. The writer performs no
    authentication, service-module import, tenant read, or tenant write.
#>

. (Join-Path $PSScriptRoot 'PurviewConfigurationContract.ps1')

function Get-PurviewPlanSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return [Convert]::ToHexString($hash).ToLowerInvariant()
}

function Get-PurviewPlanWorkload {
    [CmdletBinding()]
    param(
        [Parameter()]
        [object] $Policy
    )

    if ($Policy -is [System.Collections.IDictionary] -and
        $Policy.Keys -contains 'Workload') {
        return [string]$Policy['Workload']
    }

    return ''
}

function Test-PurviewPlanParameter {
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.Collections.IDictionary] $Parameters,

        [Parameter(Mandatory)]
        [string] $Name
    )

    if (-not $Parameters -or -not ($Parameters.Keys -contains $Name)) {
        return $false
    }

    $value = $Parameters[$Name]
    if ($value -is [Management.Automation.SwitchParameter]) {
        return $value.IsPresent
    }

    return [bool]$value
}

function Get-PurviewPlanStatusLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Status
    )

    switch ($Status) {
        'NotConfigured' { return 'Not configured' }
        'NotImplemented' { return 'Not implemented' }
        'NotApplicable' { return 'Not applicable' }
        default { return $Status }
    }
}

function Get-PurviewPlanLevelLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Level
    )

    $labels = foreach ($value in ($Level -split ',')) {
        switch ($value.Trim()) {
            'Good' { 'Priority 1 (Good)' }
            'Better' { 'Priority 2 (Better)' }
            'Best' { 'Priority 3 (Best)' }
            'Extension' { 'Toolkit extension' }
            default { $value.Trim() }
        }
    }
    return $labels -join ', '
}

function New-PurviewPlanAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ActionId,
        [Parameter(Mandatory)] [string] $Module,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)]
        [ValidateSet('Included', 'Excluded', 'Conditional', 'NotConfigured')]
        [string] $Intent,
        [Parameter(Mandatory)] [string] $ConfigPath,
        [Parameter()] [string] $Gate = '',
        [Parameter()] [string] $RuntimeCondition = '',
        [Parameter()] [string] $Rationale = '',
        [Parameter()] [string] $SafeDefault = '',
        [Parameter()] [string] $TenantImpact = ''
    )

    return [pscustomobject][ordered]@{
        ActionId = $ActionId
        Module = $Module
        Title = $Title
        Intent = $Intent
        ConfigPath = $ConfigPath
        Gate = $Gate
        RuntimeCondition = $RuntimeCondition
        GuideControlIds = @()
        PrimaryGuideLevel = 'Extension'
        PrimaryGuideRecommendations = @()
        ComparisonStatus = 'Extended'
        SupportingGuideMappings = @()
        IntendedStateKeys = @()
        Rationale = $Rationale
        SafeDefault = $SafeDefault
        TenantImpact = $TenantImpact
    }
}

function Get-PurviewPlanComparisonStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]] $Controls
    )

    $statuses = @(
        $Controls |
            ForEach-Object { [string]$_.Status } |
            Select-Object -Unique
    )
    foreach ($status in @(
        'Conditional',
        'Aligned',
        'Extended',
        'NotImplemented',
        'NotApplicable'
    )) {
        if ($status -in $statuses) {
            return $status
        }
    }
    return 'Extended'
}

function New-PurviewPlanReference {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid] $PlanId,

        [Parameter(Mandatory)]
        [datetime] $GeneratedAt
    )

    $suffix = $PlanId.ToString('N').Substring(0, 8).ToUpperInvariant()
    return 'PUR-{0}-{1}' -f $GeneratedAt.ToUniversalTime().ToString('yyyyMMdd-HHmmss'), $suffix
}

function Get-PurviewPlanValue {
    [CmdletBinding()]
    param(
        [Parameter()] [object] $InputObject,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter()] [object] $Default = $null
    )

    if ($null -eq $InputObject) { return $Default }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            $value = $InputObject[$Name]
            if ($null -eq $value) { return $Default }
            return $value
        }
        return $Default
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property -and $null -ne $property.Value) { return $property.Value }
    return $Default
}

function Protect-PurviewPlanIntendedText {
    [CmdletBinding()]
    param([Parameter()] [AllowEmptyString()] [string] $Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $protected = $Text -replace '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '[REDACTED-UPN]'
    $protected = $protected -replace '(?i)\b[A-Z0-9-]+\.onmicrosoft\.com\b', '[REDACTED-DOMAIN]'
    $protected = $protected -replace '(?i)https?://\S+', '[REDACTED-URL]'
    $protected = $protected -replace '(?i)\b(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b', '[REDACTED-DOMAIN]'
    $protected = $protected -replace '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '[REDACTED-GUID]'
    if ($protected -match '(?i)(?:\b[A-Z]:\\|\\\\[^\\\s]+\\|/(?:home|Users)/)') {
        return '[REDACTED-LOCAL-PATH]'
    }
    $protected = $protected -replace '(?i)\b(password|secret|token|credential|api[-_]?key)\s*[:=]\s*\S+', '$1=[REDACTED]'
    return $protected
}

function Get-PurviewPlanOpaqueDigest {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Value)

    return 'sha256:' + (
        Get-PurviewPlanSha256 -Text $Value.Trim().ToLowerInvariant()
    ).Substring(0, 24)
}

function ConvertTo-PurviewPlanPrincipalSet {
    [CmdletBinding()]
    param(
        [Parameter()] [object] $Value,
        [Parameter()] [string[]] $AllowedRoles = @('SiteAdmin', 'LastModifier', 'Owner')
    )

    return @(
        ConvertTo-PurviewPlanStringSet -Value $Value |
            ForEach-Object {
                if ($_ -in $AllowedRoles) {
                    [pscustomobject][ordered]@{
                        Type = 'RoleToken'
                        Role = [string]$_
                        Digest = ''
                    }
                } else {
                    [pscustomobject][ordered]@{
                        Type = 'CustomPrincipal'
                        Role = ''
                        Digest = Get-PurviewPlanOpaqueDigest -Value ([string]$_)
                    }
                }
            } |
            Sort-Object Type, Role, Digest
    )
}

function Get-PurviewPlanConfiguredLabelPaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Policy,
        [Parameter(Mandatory)] [AllowEmptyCollection()]
        [Collections.Generic.List[string]] $Diagnostics,
        [Parameter(Mandatory)] [string] $PolicyKey,
        [Parameter()] [switch] $AllowSingular
    )

    $plural = @(
        @(Get-PurviewPlanValue $Policy 'LabelPaths' @()) |
            ForEach-Object { ([string]$_).Trim() } |
            Where-Object { $_ }
    )
    $singular = [string](Get-PurviewPlanValue $Policy 'LabelPath' '')
    if ($plural.Count -gt 0) {
        if (-not [string]::IsNullOrWhiteSpace($singular)) {
            $Diagnostics.Add(
                "Both LabelPaths and LabelPath are configured for $PolicyKey; LabelPaths takes precedence."
            )
        }
        return @($plural)
    }
    if ($AllowSingular -and -not [string]::IsNullOrWhiteSpace($singular)) {
        return @($singular.Trim())
    }
    if (-not $AllowSingular -and -not [string]::IsNullOrWhiteSpace($singular)) {
        $Diagnostics.Add(
            "LabelPath is not supported for $PolicyKey; configure LabelPaths."
        )
        return @()
    }
    $Diagnostics.Add("No label reference is configured for $PolicyKey.")
    return @()
}

function Protect-PurviewPlanIntendedValue {
    [CmdletBinding()]
    param(
        [Parameter()] [object] $Value,
        [Parameter()] [string] $PropertyName = ''
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        if ($PropertyName -in @(
            'Key',
            'ParentKey',
            'ActionId',
            'BuiltInName',
            'LabelKeys',
            'PublishedLabelKeys',
            'TenantDependentParentKeys',
            'DefaultLabelKey',
            'EmailDefaultLabelKey',
            'OverrideLabelKeys',
            'IntendedStateKeys'
        )) {
            return $Value
        }
        return Protect-PurviewPlanIntendedText $Value
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $protected = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $protected[[string]$key] = Protect-PurviewPlanIntendedValue `
                -Value $Value[$key] `
                -PropertyName ([string]$key)
        }
        return [pscustomobject]$protected
    }
    if ($Value -is [pscustomobject]) {
        $protected = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) {
            $protected[$property.Name] = Protect-PurviewPlanIntendedValue `
                -Value $property.Value `
                -PropertyName $property.Name
        }
        return [pscustomobject]$protected
    }
    if ($Value -is [System.Collections.IEnumerable] -and
        $Value -isnot [string]) {
        $protectedItems = [Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $protectedItem = Protect-PurviewPlanIntendedValue `
                -Value $item `
                -PropertyName $PropertyName
            $protectedItems.Add($protectedItem)
        }
        return ,([object[]]$protectedItems.ToArray())
    }
    return $Value
}

function ConvertTo-PurviewPlanStringSet {
    [CmdletBinding()]
    param(
        [Parameter()] [object] $Value,
        [Parameter()] [string[]] $Remove = @()
    )

    $values = if ($Value -is [string]) {
        @($Value -split ',')
    } else {
        @($Value)
    }
    return @(
        $values |
            ForEach-Object { ([string]$_).Trim() } |
            Where-Object { $_ -and $_ -notin $Remove } |
            Sort-Object -Unique
    )
}

function Get-PurviewPlanLabelKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Label,
        [Parameter()] [string] $ParentName = ''
    )

    $builtInName = [string](Get-PurviewPlanValue -InputObject $Label -Name 'BuiltInName')
    if ($builtInName -match '^defa4170-0d19-0005-[0-9a-fA-F]{4}-bc88714345d2$') {
        return "builtin:$($builtInName.Trim().ToLowerInvariant())"
    }
    if (-not [string]::IsNullOrWhiteSpace($builtInName)) {
        throw (
            "Configured BuiltInName is invalid. Use a Microsoft built-in signature matching " +
            "'defa4170-0d19-0005-NNNN-bc88714345d2' or leave it empty for a custom label."
        )
    }
    $name = [string](Get-PurviewPlanValue -InputObject $Label -Name 'Name')
    if ($ParentName) {
        $hash = Get-PurviewPlanSha256 -Text (
            "$($ParentName.Trim().ToLowerInvariant())/$($name.Trim().ToLowerInvariant())"
        )
        return "custom:$($hash.Substring(0, 24))"
    }
    $hash = Get-PurviewPlanSha256 -Text $name.Trim().ToLowerInvariant()
    return "custom:$($hash.Substring(0, 24))"
}

function Get-PurviewPlanRightsSnapshot {
    [CmdletBinding()]
    param([Parameter()] [string] $Definition)

    if ([string]::IsNullOrWhiteSpace($Definition)) {
        return [pscustomobject][ordered]@{
            Entries = @()
        }
    }
    $entries = foreach ($entry in @($Definition -split ';')) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        $parts = @($entry -split ':', 2)
        $principal = $parts[0].Trim()
        $audience = if ($principal -eq '{TenantDomain}') {
            'TenantDomainToken'
        } elseif ($principal -in @('{AuthenticatedUsers}', 'AuthenticatedUsers')) {
            'BroadAuthenticatedUsers'
        } elseif ($principal -match '@|\.[A-Za-z]{2,}$') {
            'CustomPrincipalRedacted'
        } else {
            'NamedPrincipalRedacted'
        }
        $rights = if ($parts.Count -gt 1) {
            @(
                ConvertTo-PurviewPlanStringSet -Value $parts[1] |
                    ForEach-Object {
                        if ($_ -match '^[A-Za-z][A-Za-z0-9_-]*$') {
                            $_.ToUpperInvariant()
                        } else {
                            '[REDACTED-RIGHT]'
                        }
                    } |
                    Sort-Object -Unique
            )
        } else {
            @()
        }
        [pscustomobject][ordered]@{
            Audience = $audience
            Digest = if ($audience -in @(
                'TenantDomainToken',
                'BroadAuthenticatedUsers'
            )) {
                ''
            } else {
                Get-PurviewPlanOpaqueDigest -Value $principal
            }
            Rights = @($rights)
        }
    }
    return [pscustomobject][ordered]@{
        Entries = @(
            $entries |
                Sort-Object Audience, Digest, {
                    @($_.Rights) -join ','
                }
        )
    }
}

function Get-PurviewPlanIntendedState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Config,
        [Parameter(Mandatory)] [object[]] $Actions,
        [Parameter(Mandatory)] [bool] $SkipContainerLabels,
        [Parameter(Mandatory)] [int] $PremiumAuditMailboxCount
    )

    $actionsById = @{}
    foreach ($action in $Actions) { $actionsById[[string]$action.ActionId] = $action }
    function ActionIntent([string] $ActionId) {
        if ($actionsById.ContainsKey($ActionId)) { return [string]$actionsById[$ActionId].Intent }
        return 'NotConfigured'
    }

    $tenantSettings = Get-PurviewPlanValue -InputObject $Config -Name 'TenantSettings' -Default @{}
    $tenantSnapshot = @(
        [pscustomobject][ordered]@{
            Key = 'tenant.audit-standard'
            ActionId = 'purview.tenant.audit-standard'
            Intent = ActionIntent 'purview.tenant.audit-standard'
            DesiredValue = [bool](Get-PurviewPlanValue $tenantSettings 'EnableUnifiedAuditLog' $false)
        }
        [pscustomobject][ordered]@{
            Key = 'tenant.spo-labels'
            ActionId = 'purview.tenant.spo-labels'
            Intent = ActionIntent 'purview.tenant.spo-labels'
            DesiredValue = [bool](Get-PurviewPlanValue $tenantSettings 'EnableAIPIntegrationInSPO' $false)
        }
        [pscustomobject][ordered]@{
            Key = 'tenant.pdf-labels'
            ActionId = 'purview.tenant.pdf-labels'
            Intent = ActionIntent 'purview.tenant.pdf-labels'
            DesiredValue = [bool](Get-PurviewPlanValue $tenantSettings 'EnableSensitivityLabelForPDF' $false)
        }
        [pscustomobject][ordered]@{
            Key = 'tenant.container-labels'
            ActionId = 'purview.tenant.container-directory-setting'
            Intent = ActionIntent 'purview.tenant.container-directory-setting'
            DesiredValue = -not $SkipContainerLabels
        }
        [pscustomobject][ordered]@{
            Key = 'tenant.label-coauthoring'
            ActionId = 'purview.tenant.label-coauthoring'
            Intent = ActionIntent 'purview.tenant.label-coauthoring'
            DesiredValue = (ActionIntent 'purview.tenant.label-coauthoring') -eq 'Included'
        }
        [pscustomobject][ordered]@{
            Key = 'tenant.audit-premium'
            ActionId = 'purview.tenant.audit-premium'
            Intent = ActionIntent 'purview.tenant.audit-premium'
            RequestedMailboxCount = $PremiumAuditMailboxCount
            ExactTargetsIncluded = $false
        }
    )

    $intendedDiagnostics = [Collections.Generic.List[string]]::new()
    $labels = [Collections.Generic.List[object]]::new()
    $labelKeyByPath = @{}
    $labelKeysByName = @{}
    function AddLabelNameCandidate([string] $Name, [string] $Key) {
        if ([string]::IsNullOrWhiteSpace($Name)) { return }
        $lookup = $Name.Trim().ToLowerInvariant()
        if (-not $labelKeysByName.ContainsKey($lookup)) {
            $labelKeysByName[$lookup] = [Collections.Generic.List[string]]::new()
        }
        if (-not $labelKeysByName[$lookup].Contains($Key)) {
            $labelKeysByName[$lookup].Add($Key)
        }
    }
    $priority = 0
    $contentMarkingEnabled = [bool](Get-PurviewPlanValue $Config 'EnableContentMarking' $false)
    foreach ($root in @(Get-PurviewPlanValue $Config 'Labels' @())) {
        $rootKey = Get-PurviewPlanLabelKey -Label $root
        $rootName = [string](Get-PurviewPlanValue $root 'Name')
        $rootBuiltInName = [string](Get-PurviewPlanValue $root 'BuiltInName')
        $rootEncrypt = [bool](Get-PurviewPlanValue $root 'Encrypt' $false)
        $rootProtectionType = if ($rootEncrypt) {
            $configuredProtectionType = [string](Get-PurviewPlanValue $root 'ProtectionType' 'Template')
            if ([string]::IsNullOrWhiteSpace($configuredProtectionType)) { 'Template' } else { $configuredProtectionType }
        } else { '' }
        $rootExplicitRights = [string](Get-PurviewPlanValue $root 'EncryptionRightsDefinitions' '')
        $rootRightsSource = if (-not $rootEncrypt -or $rootProtectionType -ne 'Template') {
            'NotApplicable'
        } elseif (-not [string]::IsNullOrWhiteSpace($rootExplicitRights)) {
            'PerLabelOverride'
        } else {
            'GlobalDefault'
        }
        $rootRights = if ($rootRightsSource -eq 'PerLabelOverride') {
            $rootExplicitRights
        } elseif ($rootRightsSource -eq 'GlobalDefault') {
            [string](Get-PurviewPlanValue $Config 'EncryptionRightsDefinitions' '')
        } else {
            ''
        }
        $rootChildren = @(Get-PurviewPlanValue $root 'SubLabels' @())
        $rootOriginalContentTypes = @(
            ConvertTo-PurviewPlanStringSet -Value (Get-PurviewPlanValue $root 'ContentType' '')
        )
        $rootConfiguredContentTypes = @(
            ConvertTo-PurviewPlanStringSet `
                -Value (Get-PurviewPlanValue $root 'ContentType' '') `
                -Remove $(if ($SkipContainerLabels) { @('Site', 'UnifiedGroup') } else { @() })
        )
        $rootContainerBitsStripped = $SkipContainerLabels -and
            @($rootOriginalContentTypes | Where-Object { $_ -in @('Site', 'UnifiedGroup') }).Count -gt 0
        $rootContentTypeSource = if ($rootOriginalContentTypes.Count -gt 0) {
            'Configured'
        } elseif ($rootChildren.Count -gt 0) {
            'RuntimeLabelScheme'
        } else {
            'ServiceDefault'
        }
        $rootContentTypes = if ($rootContentTypeSource -eq 'ServiceDefault') {
            @('Email', 'File')
        } else {
            @($rootConfiguredContentTypes)
        }
        $rootContentMark = $contentMarkingEnabled -and
            [bool](Get-PurviewPlanValue $root 'ContentMark' $false)
        $labels.Add([pscustomobject][ordered]@{
            Key = $rootKey
            ParentKey = ''
            Name = $rootName
            DisplayName = Protect-PurviewPlanIntendedText ([string](Get-PurviewPlanValue $root 'DisplayName'))
            BuiltInName = $rootBuiltInName
            Priority = $priority++
            ContentTypes = @($rootContentTypes)
            ContentTypeSource = $rootContentTypeSource
            ContentTypeSemantics = if ($rootContentTypeSource -eq 'RuntimeLabelScheme') {
                'RuntimeLabelScheme'
            } elseif ($rootContentTypeSource -eq 'Configured' -and $rootContentTypes.Count -gt 0) {
                'EnsureMinimumPreserveExisting'
            } else {
                'NewUsesServiceDefaultExistingPreserved'
            }
            ContainerBitsStripped = $rootContainerBitsStripped
            Color = ([string](Get-PurviewPlanValue $root 'Color')).ToUpperInvariant()
            Encrypt = $rootEncrypt
            ProtectionType = $rootProtectionType
            OutlookBehavior = if ($rootEncrypt) {
                [string](Get-PurviewPlanValue $root 'UserDefinedOutlookBehavior')
            } else { '' }
            RightsSource = $rootRightsSource
            Rights = Get-PurviewPlanRightsSnapshot -Definition $rootRights
            ContentMark = $rootContentMark
            HeaderText = if ($rootContentMark) {
                Protect-PurviewPlanIntendedText ([string](Get-PurviewPlanValue $root 'HeaderText'))
            } else { '' }
            FooterText = if ($rootContentMark) {
                Protect-PurviewPlanIntendedText ([string](Get-PurviewPlanValue $root 'FooterText'))
            } else { '' }
            WatermarkText = if ($rootContentMark) {
                Protect-PurviewPlanIntendedText ([string](Get-PurviewPlanValue $root 'WatermarkText'))
            } else { '' }
        })
        $labelKeyByPath[$rootName.ToLowerInvariant()] = $rootKey
        AddLabelNameCandidate -Name $rootName -Key $rootKey
        foreach ($child in $rootChildren) {
            $childKey = Get-PurviewPlanLabelKey -Label $child -ParentName $rootName
            $childName = [string](Get-PurviewPlanValue $child 'Name')
            $childBuiltInName = [string](Get-PurviewPlanValue $child 'BuiltInName')
            $childEncrypt = [bool](Get-PurviewPlanValue $child 'Encrypt' $false)
            $childProtectionType = if ($childEncrypt) {
                $configuredProtectionType = [string](Get-PurviewPlanValue $child 'ProtectionType' 'Template')
                if ([string]::IsNullOrWhiteSpace($configuredProtectionType)) { 'Template' } else { $configuredProtectionType }
            } else { '' }
            $childExplicitRights = [string](Get-PurviewPlanValue $child 'EncryptionRightsDefinitions' '')
            $childRightsSource = if (-not $childEncrypt -or $childProtectionType -ne 'Template') {
                'NotApplicable'
            } elseif (-not [string]::IsNullOrWhiteSpace($childExplicitRights)) {
                'PerLabelOverride'
            } else {
                'GlobalDefault'
            }
            $childRights = if ($childRightsSource -eq 'PerLabelOverride') {
                $childExplicitRights
            } elseif ($childRightsSource -eq 'GlobalDefault') {
                [string](Get-PurviewPlanValue $Config 'EncryptionRightsDefinitions' '')
            } else {
                ''
            }
            $childOriginalContentTypes = @(
                ConvertTo-PurviewPlanStringSet -Value (Get-PurviewPlanValue $child 'ContentType' '')
            )
            $childConfiguredContentTypes = @(
                ConvertTo-PurviewPlanStringSet `
                    -Value (Get-PurviewPlanValue $child 'ContentType' '') `
                    -Remove $(if ($SkipContainerLabels) { @('Site', 'UnifiedGroup') } else { @() })
            )
            $childContainerBitsStripped = $SkipContainerLabels -and
                @($childOriginalContentTypes | Where-Object { $_ -in @('Site', 'UnifiedGroup') }).Count -gt 0
            $childContentTypeSource = if ($childOriginalContentTypes.Count -gt 0) {
                'Configured'
            } else {
                'ServiceDefault'
            }
            $childContentTypes = if ($childContentTypeSource -eq 'ServiceDefault') {
                @('Email', 'File')
            } else {
                @($childConfiguredContentTypes)
            }
            $childContentMark = $contentMarkingEnabled -and
                [bool](Get-PurviewPlanValue $child 'ContentMark' $false)
            $labels.Add([pscustomobject][ordered]@{
                Key = $childKey
                ParentKey = $rootKey
                Name = $childName
                DisplayName = Protect-PurviewPlanIntendedText ([string](Get-PurviewPlanValue $child 'DisplayName'))
                BuiltInName = $childBuiltInName
                Priority = $priority++
                ContentTypes = @($childContentTypes)
                ContentTypeSource = $childContentTypeSource
                ContentTypeSemantics = if ($childContentTypeSource -eq 'Configured' -and
                    $childContentTypes.Count -gt 0) {
                    'EnsureMinimumPreserveExisting'
                } else {
                    'NewUsesServiceDefaultExistingPreserved'
                }
                ContainerBitsStripped = $childContainerBitsStripped
                Color = ([string](Get-PurviewPlanValue $child 'Color')).ToUpperInvariant()
                Encrypt = $childEncrypt
                ProtectionType = $childProtectionType
                OutlookBehavior = if ($childEncrypt) {
                    [string](Get-PurviewPlanValue $child 'UserDefinedOutlookBehavior')
                } else { '' }
                RightsSource = $childRightsSource
                Rights = Get-PurviewPlanRightsSnapshot -Definition $childRights
                ContentMark = $childContentMark
                HeaderText = if ($childContentMark) {
                    Protect-PurviewPlanIntendedText ([string](Get-PurviewPlanValue $child 'HeaderText'))
                } else { '' }
                FooterText = if ($childContentMark) {
                    Protect-PurviewPlanIntendedText ([string](Get-PurviewPlanValue $child 'FooterText'))
                } else { '' }
                WatermarkText = if ($childContentMark) {
                    Protect-PurviewPlanIntendedText ([string](Get-PurviewPlanValue $child 'WatermarkText'))
                } else { '' }
            })
            $labelKeyByPath[("$rootName/$childName").ToLowerInvariant()] = $childKey
            AddLabelNameCandidate -Name $childName -Key $childKey
        }
    }

    $duplicateLabelKeys = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($group in @($labels | Group-Object Key | Where-Object Count -gt 1)) {
        $null = $duplicateLabelKeys.Add([string]$group.Name)
        $safeKey = Protect-PurviewPlanIntendedText ([string]$group.Name)
        $intendedDiagnostics.Add(
            "Duplicate configured label key: $safeKey appears $($group.Count) times"
        )
    }
    $labelsForSnapshot = @(
        $labels |
            Where-Object { -not $duplicateLabelKeys.Contains([string]$_.Key) } |
            Sort-Object Priority, Key
    )

    function ResolveLabelKey([string] $Path) {
        if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
        $lookup = $Path.Trim().Replace('\', '/').ToLowerInvariant()
        if ($labelKeyByPath.ContainsKey($lookup)) {
            $resolvedKey = [string]$labelKeyByPath[$lookup]
            if (-not $duplicateLabelKeys.Contains($resolvedKey)) { return $resolvedKey }
            $safePath = Protect-PurviewPlanIntendedText $Path
            $diagnostic = "Ambiguous configured label reference: $safePath resolves to a duplicate key"
            if (-not $intendedDiagnostics.Contains($diagnostic)) {
                $intendedDiagnostics.Add($diagnostic)
            }
            return ''
        }
        if ($lookup -notmatch '/' -and $labelKeysByName.ContainsKey($lookup)) {
            $candidates = @($labelKeysByName[$lookup] | Sort-Object -Unique)
            if ($candidates.Count -eq 1 -and
                -not $duplicateLabelKeys.Contains([string]$candidates[0])) {
                return [string]$candidates[0]
            }
            $safePath = Protect-PurviewPlanIntendedText $Path
            $diagnostic = "Ambiguous configured label reference: $safePath matches $($candidates.Count) labels"
            if (-not $intendedDiagnostics.Contains($diagnostic)) {
                $intendedDiagnostics.Add($diagnostic)
            }
            return ''
        }
        $safePath = Protect-PurviewPlanIntendedText $Path
        $diagnostic = "Unresolved configured label reference: $safePath"
        if (-not $intendedDiagnostics.Contains($diagnostic)) {
            $intendedDiagnostics.Add($diagnostic)
        }
        return ''
    }

    $labelPolicyConfig = Get-PurviewPlanValue $Config 'LabelPolicy' @{}
    $publishedLabelNames = @(Get-PurviewPlanValue $labelPolicyConfig 'PublishedLabels' @())
    $publicationMode = if (@($publishedLabelNames | Where-Object { $_ }).Count -gt 0) {
        'ExplicitList'
    } else {
        'AllConfigured'
    }
    if ($publicationMode -eq 'AllConfigured') {
        $publishedLabelKeys = @(
            $labelsForSnapshot |
                ForEach-Object Key |
                Sort-Object -Unique
        )
    } else {
        $publishKeySet = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        foreach ($publishedName in $publishedLabelNames) {
            $publishedKey = ResolveLabelKey ([string]$publishedName)
            if (-not $publishedKey) { continue }
            $null = $publishKeySet.Add($publishedKey)
            $labelRecord = @(
                $labelsForSnapshot |
                    Where-Object Key -eq $publishedKey |
                    Select-Object -First 1
            )
            if ($labelRecord.Count -eq 1 -and $labelRecord[0].ParentKey) {
                $null = $publishKeySet.Add([string]$labelRecord[0].ParentKey)
            }
        }
        $publishedLabelKeys = @($publishKeySet | Sort-Object)
    }
    $defaultLabelName = [string](Get-PurviewPlanValue $labelPolicyConfig 'DefaultLabel')
    $defaultLabelKey = ResolveLabelKey $defaultLabelName
    $emailDefaultLabelName = [string](Get-PurviewPlanValue $labelPolicyConfig 'DefaultLabelForEmail')
    $emailDefaultLabelKey = ResolveLabelKey $emailDefaultLabelName
    $labelPolicyUnresolvedCount = @(
        @($publishedLabelNames) + @($defaultLabelName, $emailDefaultLabelName) |
            Where-Object { $_ -and -not (ResolveLabelKey ([string]$_)) }
    ).Count
    $labelPolicy = [pscustomobject][ordered]@{
        Key = 'label-policy/main'
        ActionId = 'purview.labels.publish'
        Intent = ActionIntent 'purview.labels.publish'
        Name = Protect-PurviewPlanIntendedText ([string](Get-PurviewPlanValue $labelPolicyConfig 'Name'))
        PublicationMode = $publicationMode
        PublishedLabelKeys = @($publishedLabelKeys)
        TenantDependentParentKeys = @(
            $labelsForSnapshot |
                Where-Object {
                    $_.ContentTypeSource -eq 'RuntimeLabelScheme' -and
                    $_.Key -in $publishedLabelKeys
                } |
                ForEach-Object Key |
                Sort-Object -Unique
        )
        DefaultLabelKey = $defaultLabelKey
        EmailDefaultLabelKey = $emailDefaultLabelKey
        UnresolvedLabelReferenceCount = $labelPolicyUnresolvedCount
        Mandatory = [bool](Get-PurviewPlanValue $labelPolicyConfig 'MandatoryLabelling' $false)
        RequireDowngradeJustification = [bool](Get-PurviewPlanValue $labelPolicyConfig 'DowngradeJustification' $false)
        AttachmentAction = [string](Get-PurviewPlanValue $labelPolicyConfig 'AttachmentAction')
    }

    $startInSimulation = [bool](Get-PurviewPlanValue $Config 'DlpStartInSimulation' $true)
    $dlpPolicies = [Collections.Generic.List[object]]::new()
    $dlpIndex = 0
    $customDlpIndex = 0
    $supportedDlpWorkloads = @('Exchange', 'SharePointOneDrive', 'Endpoint')
    foreach ($policy in @(Get-PurviewPlanValue $Config 'DlpPolicies' @())) {
        $workload = [string](Get-PurviewPlanValue $policy 'Workload')
        $actionId = switch ($workload) {
            'Exchange' { 'purview.dlp.exchange' }
            'SharePointOneDrive' { 'purview.dlp.sharepoint-onedrive' }
            'Endpoint' { 'purview.dlp.endpoint' }
            default {
                $customDlpIndex++
                "purview.dlp.custom-$customDlpIndex"
            }
        }
        if ($workload -notin $supportedDlpWorkloads) {
            $safeWorkload = Protect-PurviewPlanIntendedText $workload
            $intendedDiagnostics.Add(
                "Unsupported DLP workload omitted from intended state: $safeWorkload"
            )
            $dlpIndex++
            continue
        }
        $rawPolicyName = [string](Get-PurviewPlanValue $policy 'Name')
        $rawRuleName = [string](Get-PurviewPlanValue $policy 'RuleName')
        $safePolicyName = Protect-PurviewPlanIntendedText $rawPolicyName
        $safeRuleName = Protect-PurviewPlanIntendedText $rawRuleName
        $policyKeyHash = (
            Get-PurviewPlanSha256 -Text (
                "$actionId|$($rawPolicyName.Trim().ToLowerInvariant())|$($rawRuleName.Trim().ToLowerInvariant())"
            )
        ).Substring(0, 16)
        $policyKey = "dlp/$actionId/$policyKeyHash"
        $configuredLabelPaths = @(
            Get-PurviewPlanConfiguredLabelPaths `
                -Policy $policy `
                -Diagnostics $intendedDiagnostics `
                -PolicyKey $policyKey `
                -AllowSingular
        )
        $locations = switch ($workload) {
            'Exchange' { @('Exchange:All') }
            'SharePointOneDrive' { @('OneDrive:All', 'SharePoint:All') }
            'Endpoint' { @('Endpoint:All') }
            default { @() }
        }
        $restrictions = @(
            @(Get-PurviewPlanValue $policy 'EndpointDlpRestrictions' @()) |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        Setting = [string](Get-PurviewPlanValue $_ 'Setting')
                        Value = [string](Get-PurviewPlanValue $_ 'Value' (
                            Get-PurviewPlanValue $_ 'Action'
                        ))
                    }
                } |
                Sort-Object Setting, Value
        )
        $dlpPolicies.Add([pscustomobject][ordered]@{
            Key = $policyKey
            ActionId = $actionId
            Intent = ActionIntent $actionId
            Name = $safePolicyName
            RuleName = $safeRuleName
            Workload = $workload
            Mode = if ($startInSimulation) { 'TestWithoutNotifications' } else { 'Enable' }
            Locations = @($locations)
            LabelKeys = @(
                $configuredLabelPaths |
                    ForEach-Object { ResolveLabelKey ([string]$_) } |
                    Where-Object { $_ } |
                    Sort-Object -Unique
            )
            UnresolvedLabelReferenceCount = @(
                $configuredLabelPaths |
                    Where-Object { -not (ResolveLabelKey ([string]$_)) }
            ).Count
            BlockAccess = [bool](Get-PurviewPlanValue $policy 'BlockAccess' $false)
            BlockAccessScope = [string](Get-PurviewPlanValue $policy 'BlockAccessScope')
            EndpointRestrictions = @($restrictions)
            EnforcePortalAccess = [bool](Get-PurviewPlanValue $policy 'EnforcePortalAccess' $false)
            ReportSeverityLevel = [string](Get-PurviewPlanValue $policy 'ReportSeverityLevel')
            GenerateAlert = [bool](Get-PurviewPlanValue $policy 'GenerateAlert' $false)
            NotifyUser = @(
                ConvertTo-PurviewPlanPrincipalSet (
                    Get-PurviewPlanValue $policy 'NotifyUser' @()
                )
            )
            GenerateIncidentReport = @(
                ConvertTo-PurviewPlanPrincipalSet (
                    Get-PurviewPlanValue $policy 'GenerateIncidentReport' @()
                )
            )
        })
        $dlpIndex++
    }

    $retentionConfig = Get-PurviewPlanValue $Config 'Retention' @{}
    $retentionLocations = Get-PurviewRetentionLocationClassification -Value (
        Get-PurviewPlanValue $retentionConfig 'Locations' @()
    )
    foreach ($unsupportedLocation in @($retentionLocations.UnsupportedEvidence)) {
        $intendedDiagnostics.Add(
            "Unsupported retention location omitted from deployment intent: $unsupportedLocation"
        )
    }
    if ($retentionLocations.Supported.Count -eq 0 -and
        $retentionLocations.Unsupported.Count -gt 0) {
        $intendedDiagnostics.Add(
            'Retention has no supported locations and cannot be deployed.'
        )
    } elseif ($retentionLocations.Supported.Count -eq 0) {
        $intendedDiagnostics.Add(
            'Retention has no configured locations and cannot be deployed.'
        )
    }
    $retention = [pscustomobject][ordered]@{
        Key = 'retention/main'
        ActionId = 'purview.retention.exchange'
        Intent = ActionIntent 'purview.retention.exchange'
        Name = Protect-PurviewPlanIntendedText ([string](Get-PurviewPlanValue $retentionConfig 'Name'))
        RuleName = Protect-PurviewPlanIntendedText ([string](Get-PurviewPlanValue $retentionConfig 'RuleName'))
        Locations = @($retentionLocations.Supported)
        UnsupportedLocations = @($retentionLocations.UnsupportedEvidence)
        LocationDisposition = if ($retentionLocations.Supported.Count -eq 0 -and
            $retentionLocations.Unsupported.Count -gt 0) {
            'UnsupportedOnly'
        } elseif ($retentionLocations.Supported.Count -eq 0) {
            'Empty'
        } elseif ($retentionLocations.Unsupported.Count -eq 0) {
            'Supported'
        } else {
            'Partial'
        }
        DurationDays = [int](Get-PurviewPlanValue $retentionConfig 'DurationDays' 0)
        DurationDisplayHint = [string](Get-PurviewPlanValue $retentionConfig 'DurationDisplayHint')
        Action = [string](Get-PurviewPlanValue $retentionConfig 'Action')
        ExpirationDateOption = [string](Get-PurviewPlanValue $retentionConfig 'ExpirationDateOption')
    }

    $contentExpiration = [string](
        Get-PurviewPlanValue $Config 'EncryptionContentExpiredOnDateInDaysOrNever' 'Never'
    )
    if ([string]::IsNullOrWhiteSpace($contentExpiration)) {
        $contentExpiration = 'Never'
    }
    $encryption = [pscustomobject][ordered]@{
        Key = 'encryption/global'
        ActionId = 'purview.labels.encryption'
        Intent = ActionIntent 'purview.labels.encryption'
        OfflineAccessDays = [int](Get-PurviewPlanValue $Config 'EncryptionOfflineAccessDays' 0)
        ContentExpiration = $contentExpiration
        DefaultRights = Get-PurviewPlanRightsSnapshot -Definition (
            [string](Get-PurviewPlanValue $Config 'EncryptionRightsDefinitions' '')
        )
        OverrideLabelKeys = @(
            $labelsForSnapshot |
                Where-Object {
                    $_.Encrypt -and $_.RightsSource -eq 'PerLabelOverride'
                } |
                ForEach-Object Key |
                Sort-Object -Unique
        )
    }

    $aiPolicies = [Collections.Generic.List[object]]::new()
    $aiConfig = Get-PurviewPlanValue $Config 'AIGovernance' @{}
    $aiIndex = 0
    foreach ($policy in @(Get-PurviewPlanValue $aiConfig 'DlpPolicies' @())) {
        $configuredAiLabelPaths = @(
            Get-PurviewPlanConfiguredLabelPaths `
                -Policy $policy `
                -Diagnostics $intendedDiagnostics `
                -PolicyKey "ai/purview.ai.copilot-dlp/$aiIndex"
        )
        $locations = @(
            @(Get-PurviewPlanValue $policy 'Locations' @()) |
                ForEach-Object {
                    $locationIdentity = Get-PurviewLocationIdentity -Value (
                        [string](Get-PurviewPlanValue $_ 'Location')
                    )
                    $inclusions = @(
                        @(Get-PurviewPlanValue $_ 'Inclusions' @()) |
                            ForEach-Object {
                                $identity = [string](Get-PurviewPlanValue $_ 'Identity')
                                [pscustomobject][ordered]@{
                                    Type = [string](Get-PurviewPlanValue $_ 'Type')
                                    IdentityClass = if ($identity -eq 'All') { 'All' } else { 'CustomPrincipal' }
                                    Digest = if ($identity -eq 'All') { '' } else {
                                        Get-PurviewPlanOpaqueDigest -Value $identity
                                    }
                                }
                            } |
                            Sort-Object Type, IdentityClass, Digest
                    )
                    $exclusions = @(
                        @(Get-PurviewPlanValue $_ 'Exclusions' @()) |
                            ForEach-Object {
                                [pscustomobject][ordered]@{
                                    Type = [string](Get-PurviewPlanValue $_ 'Type')
                                    IdentityClass = 'CustomPrincipal'
                                    Digest = Get-PurviewPlanOpaqueDigest -Value (
                                        [string](Get-PurviewPlanValue $_ 'Identity')
                                    )
                                }
                            } |
                            Sort-Object Type, IdentityClass, Digest
                    )
                    [pscustomobject][ordered]@{
                        Workload = [string](Get-PurviewPlanValue $_ 'Workload')
                        Location = $locationIdentity.Value
                        LocationClass = $locationIdentity.Class
                        LocationDigest = $locationIdentity.Digest
                        Inclusions = @($inclusions)
                        Exclusions = @($exclusions)
                    }
                } |
                Sort-Object Workload, LocationClass, LocationDigest, Location
        )
        $restrictions = @(
            @(Get-PurviewPlanValue $policy 'RestrictAccess' @()) |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        Setting = [string](Get-PurviewPlanValue $_ 'setting')
                        Value = [string](Get-PurviewPlanValue $_ 'value')
                    }
                } |
                Sort-Object Setting, Value
        )
        $rawAiPolicyName = [string](Get-PurviewPlanValue $policy 'Name')
        $rawAiRuleName = [string](Get-PurviewPlanValue $policy 'RuleName')
        $safeAiPolicyName = Protect-PurviewPlanIntendedText $rawAiPolicyName
        $safeAiRuleName = Protect-PurviewPlanIntendedText $rawAiRuleName
        $aiKeyHash = (
            Get-PurviewPlanSha256 -Text (
                "purview.ai.copilot-dlp|$($rawAiPolicyName.Trim().ToLowerInvariant())|$($rawAiRuleName.Trim().ToLowerInvariant())"
            )
        ).Substring(0, 16)
        $aiPolicies.Add([pscustomobject][ordered]@{
            Key = "ai/purview.ai.copilot-dlp/$aiKeyHash"
            ActionId = 'purview.ai.copilot-dlp'
            Intent = ActionIntent 'purview.ai.copilot-dlp'
            Name = $safeAiPolicyName
            RuleName = $safeAiRuleName
            Mode = if ($startInSimulation) { 'TestWithoutNotifications' } else {
                [string](Get-PurviewPlanValue $policy 'Mode' 'Enable')
            }
            EnforcementPlanes = @(
                ConvertTo-PurviewPlanStringSet (Get-PurviewPlanValue $policy 'EnforcementPlanes' @())
            )
            Locations = @($locations)
            LabelKeys = @(
                $configuredAiLabelPaths |
                    ForEach-Object { ResolveLabelKey ([string]$_) } |
                    Where-Object { $_ } |
                    Sort-Object -Unique
            )
            UnresolvedLabelReferenceCount = @(
                $configuredAiLabelPaths |
                    Where-Object { -not (ResolveLabelKey ([string]$_)) }
            ).Count
            LabelResolution = 'ExpandLabelGroupsAtRuntime'
            Restrictions = @($restrictions)
        })
        $aiIndex++
    }

    $duplicateDlpKeys = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($group in @($dlpPolicies | Group-Object Key | Where-Object Count -gt 1)) {
        $null = $duplicateDlpKeys.Add([string]$group.Name)
        $intendedDiagnostics.Add(
            "Duplicate configured DLP identity omitted from intended state: $($group.Name)"
        )
    }
    $dlpPoliciesForSnapshot = @(
        $dlpPolicies |
            Where-Object { -not $duplicateDlpKeys.Contains([string]$_.Key) } |
            Sort-Object Key
    )

    $duplicateAiKeys = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($group in @($aiPolicies | Group-Object Key | Where-Object Count -gt 1)) {
        $null = $duplicateAiKeys.Add([string]$group.Name)
        $intendedDiagnostics.Add(
            "Duplicate configured AI governance identity omitted from intended state: $($group.Name)"
        )
    }
    $aiPoliciesForSnapshot = @(
        $aiPolicies |
            Where-Object { -not $duplicateAiKeys.Contains([string]$_.Key) } |
            Sort-Object Key
    )

    $state = [pscustomobject][ordered]@{
        TenantSettings = @($tenantSnapshot)
        Labels = @($labelsForSnapshot)
        LabelPolicy = $labelPolicy
        DlpPolicies = @($dlpPoliciesForSnapshot)
        Retention = $retention
        Encryption = $encryption
        AIGovernance = @($aiPoliciesForSnapshot)
        Diagnostics = @($intendedDiagnostics | Sort-Object -Unique)
    }
    return Protect-PurviewPlanIntendedValue $state
}

function Test-PurviewDeploymentPlanMapping {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $GuideMapping,

        [Parameter(Mandatory)]
        [object[]] $Actions,

        [Parameter(Mandatory)]
        [ValidateSet('Primary', 'Supporting')]
        [string] $ExpectedRole
    )

    $requiredGuideFields = @(
        'Id', 'Title', 'RevisionDate', 'VerifiedDate', 'Publisher',
        'SourceClassification', 'Owner'
    )
    if (-not $GuideMapping.Contains('Guide') -or
        $GuideMapping.Guide -isnot [System.Collections.IDictionary]) {
        throw 'Guide mapping must contain a Guide dictionary.'
    }

    foreach ($field in $requiredGuideFields) {
        if (-not $GuideMapping.Guide.Contains($field) -or
            [string]::IsNullOrWhiteSpace([string]$GuideMapping.Guide[$field])) {
            throw "Guide mapping is missing required metadata '$field'."
        }
    }

    $role = if ($GuideMapping.Contains('Role')) {
        [string]$GuideMapping.Role
    } else {
        'Primary'
    }
    if ($role -notin @('Primary', 'Supporting')) {
        throw "Guide mapping role '$role' is not supported."
    }
    if ($role -ne $ExpectedRole) {
        throw "Guide mapping role '$role' cannot be used as '$ExpectedRole'."
    }
    if ($role -eq 'Primary') {
        foreach ($primaryField in @('Edition', 'SourceModifiedDate', 'SourceFileName', 'Levels')) {
            if (-not $GuideMapping.Guide.Contains($primaryField) -or
                $null -eq $GuideMapping.Guide[$primaryField]) {
                throw "Primary guide mapping is missing required metadata '$primaryField'."
            }
        }
        $levels = @($GuideMapping.Guide.Levels)
        $levelIds = @($levels | ForEach-Object { [string]$_.Id })
        if ($levelIds.Count -ne 3 -or
            (@($levelIds | Sort-Object) -join ',') -ne 'Best,Better,Good') {
            throw 'Primary guide mapping must define Good, Better, and Best levels exactly once.'
        }
    } else {
        foreach ($supportingField in @('SourceUri', 'SourceCommit')) {
            if (-not $GuideMapping.Guide.Contains($supportingField) -or
                [string]::IsNullOrWhiteSpace([string]$GuideMapping.Guide[$supportingField])) {
                throw "Supporting guide mapping is missing required metadata '$supportingField'."
            }
        }
    }

    if (-not $GuideMapping.Contains('Controls')) {
        throw 'Guide mapping must contain Controls.'
    }

    $allowed = @('Aligned', 'Conditional', 'Extended', 'NotImplemented', 'NotApplicable')
    $controlIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $actionIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($action in $Actions) {
        if (-not $actionIds.Add([string]$action.ActionId)) {
            throw "Deployment Plan action ID '$($action.ActionId)' is duplicated."
        }
    }

    foreach ($control in @($GuideMapping.Controls)) {
        foreach ($field in @('Id', 'Section', 'Summary', 'Status', 'ActionIds', 'ConfigPaths', 'Rationale', 'ReferenceUris')) {
            if (-not $control.Contains($field)) {
                throw "Guide control is missing required field '$field'."
            }
        }
        if ($role -eq 'Primary') {
            foreach ($primaryControlField in @('Level', 'SourceSection')) {
                if (-not $control.Contains($primaryControlField) -or
                    [string]::IsNullOrWhiteSpace([string]$control[$primaryControlField])) {
                    throw "Primary guide control is missing required field '$primaryControlField'."
                }
            }
            if ([string]$control.Level -notin @('Good', 'Better', 'Best')) {
                throw "Primary guide control '$($control.Id)' has unknown level '$($control.Level)'."
            }
        }
        if (-not $controlIds.Add([string]$control.Id)) {
            throw "Guide control ID '$($control.Id)' is duplicated."
        }
        if ([string]$control.Status -notin $allowed) {
            throw "Guide control '$($control.Id)' has unknown status '$($control.Status)'."
        }
        if ($control.Status -ne 'Aligned' -and
            [string]::IsNullOrWhiteSpace([string]$control.Rationale)) {
            throw "Guide control '$($control.Id)' requires a rationale for status '$($control.Status)'."
        }
        foreach ($actionId in @($control.ActionIds)) {
            if (-not $actionIds.Contains([string]$actionId)) {
                throw "Guide control '$($control.Id)' references undefined action '$actionId'."
            }
        }
    }
}

function Get-PurviewDeploymentPlanModel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $Config,

        [Parameter(Mandatory)]
        [string] $ConfigPath,

        [Parameter()]
        [System.Collections.IDictionary] $Parameters,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary] $GuideMapping,

        [Parameter()]
        [object[]] $SupportingGuideMappings = @(),

        [Parameter()]
        [string] $ScriptVersion = 'unknown',

        [Parameter()]
        [guid] $PlanId = [guid]::NewGuid(),

        [Parameter()]
        [string] $PlanReference,

        [Parameter()]
        [datetime] $GeneratedAt = [datetime]::UtcNow
    )

    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw "Configuration file not found: $ConfigPath"
    }
    Assert-PurviewLabelIdentityConfiguration -Config $Config

    $managedByTag = [string](Get-PurviewPlanValue $Config 'ManagedByTag' '')
    if ([string]::IsNullOrWhiteSpace($managedByTag)) {
        throw 'Configuration ManagedByTag must be a non-empty string.'
    }
    if ((Protect-PurviewPlanIntendedText $managedByTag) -ne $managedByTag) {
        throw 'Configuration ManagedByTag must not contain tenant identities, GUIDs, URLs, secrets, or local paths.'
    }

    $skipTenant = Test-PurviewPlanParameter -Parameters $Parameters -Name 'SkipTenantSettings'
    $skipLabels = Test-PurviewPlanParameter -Parameters $Parameters -Name 'SkipLabels'
    $skipDlp = Test-PurviewPlanParameter -Parameters $Parameters -Name 'SkipDLP'
    $applyRetention = Test-PurviewPlanParameter -Parameters $Parameters -Name 'ApplyRetention'
    $skipAi = Test-PurviewPlanParameter -Parameters $Parameters -Name 'SkipAIControls'
    $skipContainers = Test-PurviewPlanParameter -Parameters $Parameters -Name 'SkipContainerLabels'
    $premiumAudit = Test-PurviewPlanParameter -Parameters $Parameters -Name 'EnablePremiumAudit'
    $coauthoring = Test-PurviewPlanParameter -Parameters $Parameters -Name 'EnableLabelCoAuthoring'
    $bpOnly = Test-PurviewPlanParameter -Parameters $Parameters -Name 'BPOnly'
    $noLicenseDetect = Test-PurviewPlanParameter -Parameters $Parameters -Name 'NoLicenseAutoDetect'

    $actions = [Collections.Generic.List[object]]::new()
    $tenantSettings = if ($Config.Contains('TenantSettings') -and
        $Config.TenantSettings -is [System.Collections.IDictionary]) {
        $Config.TenantSettings
    } else {
        @{}
    }

    $standardAuditIntent = if ($skipTenant) {
        'Excluded'
    } elseif ($tenantSettings.Contains('EnableUnifiedAuditLog') -and
        [bool]$tenantSettings.EnableUnifiedAuditLog) {
        'Included'
    } else {
        'NotConfigured'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.tenant.audit-standard' `
        -Module 'Setup-TenantSettings' `
        -Title 'Standard audit logging' `
        -Intent $standardAuditIntent `
        -ConfigPath 'TenantSettings.EnableUnifiedAuditLog' `
        -Gate $(if ($skipTenant) { '-SkipTenantSettings' } else { 'Configuration value' }) `
        -Rationale 'Tracks user and administrator activity across Microsoft 365.' `
        -SafeDefault 'Included when configured.' `
        -TenantImpact 'May enable unified audit ingestion.'))

    $spoIntent = if ($skipTenant) {
        'Excluded'
    } elseif ($tenantSettings.Contains('EnableAIPIntegrationInSPO') -and
        [bool]$tenantSettings.EnableAIPIntegrationInSPO) {
        'Included'
    } else {
        'NotConfigured'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.tenant.spo-labels' `
        -Module 'Setup-TenantSettings' `
        -Title 'Sensitivity-label support for SharePoint and OneDrive' `
        -Intent $spoIntent `
        -ConfigPath 'TenantSettings.EnableAIPIntegrationInSPO' `
        -Gate $(if ($skipTenant) { '-SkipTenantSettings' } else { 'Configuration value' }) `
        -Rationale 'Allows Purview to recognize labels on stored Office files.' `
        -SafeDefault 'Included when configured.' `
        -TenantImpact 'Changes a tenant-wide SharePoint setting.'))

    $pdfIntent = if ($skipTenant) {
        'Excluded'
    } elseif ($tenantSettings.Contains('EnableSensitivityLabelForPDF') -and
        [bool]$tenantSettings.EnableSensitivityLabelForPDF) {
        'Included'
    } else {
        'NotConfigured'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.tenant.pdf-labels' `
        -Module 'Setup-TenantSettings' `
        -Title 'Sensitivity labels for PDF files' `
        -Intent $pdfIntent `
        -ConfigPath 'TenantSettings.EnableSensitivityLabelForPDF' `
        -Gate $(if ($skipTenant) { '-SkipTenantSettings' } else { 'Configuration value' }) `
        -Rationale 'Extends label handling to PDF content.' `
        -SafeDefault 'Configuration controlled.' `
        -TenantImpact 'Changes tenant-wide PDF label behavior.'))

    $containerDirectoryIntent = if ($skipTenant -or $skipContainers) {
        'Excluded'
    } elseif ($bpOnly) {
        'Included'
    } else {
        'Conditional'
    }
    $containerRuntimeCondition = if ($bpOnly) {
        'Business Premium includes the Entra ID P1 prerequisite for container labels.'
    } elseif ($noLicenseDetect) {
        'Operator must confirm Entra ID P1 entitlement because auto-detection is disabled.'
    } else {
        'Runtime license detection must confirm a recognized Business Premium, E5, or Purview Suite SKU.'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.tenant.container-directory-setting' `
        -Module 'Setup-TenantSettings' `
        -Title 'Container label directory setting' `
        -Intent $containerDirectoryIntent `
        -ConfigPath 'TenantSettings' `
        -Gate $(if ($skipContainers) { '-SkipContainerLabels' } elseif ($skipTenant) { '-SkipTenantSettings' } else { 'Default on' }) `
        -RuntimeCondition $containerRuntimeCondition `
        -Rationale 'Enables labels for Microsoft 365 groups and sites.' `
        -SafeDefault 'Default on with an explicit opt-out.' `
        -TenantImpact 'May enable Group.Unified EnableMIPLabels.'))

    $coauthorIntent = if ($skipTenant -or -not $coauthoring) {
        'Excluded'
    } else {
        'Included'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.tenant.label-coauthoring' `
        -Module 'Setup-TenantSettings' `
        -Title 'Label co-authoring metadata format' `
        -Intent $coauthorIntent `
        -ConfigPath 'TenantSettings.EnableLabelCoAuth' `
        -Gate $(if ($coauthoring) { '-EnableLabelCoAuthoring' } else { 'Explicit opt-in not selected' }) `
        -Rationale 'Enables co-authoring behavior for encrypted labeled Office files.' `
        -SafeDefault 'Excluded because the tenant switch has one-way compatibility effects.' `
        -TenantImpact 'Changes the tenant-wide sensitivity-label metadata format.'))

    $premiumIntent = if ($skipTenant -or -not $premiumAudit) {
        'Excluded'
    } elseif ($bpOnly) {
        'Excluded'
    } else {
        'Conditional'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.tenant.audit-premium' `
        -Module 'Setup-TenantSettings' `
        -Title 'Premium Audit mailbox events' `
        -Intent $premiumIntent `
        -ConfigPath 'TenantSettings' `
        -Gate $(if ($premiumAudit) { '-EnablePremiumAudit' } else { 'Explicit opt-in not selected' }) `
        -RuntimeCondition 'Requires Microsoft 365 E5 or Audit Premium entitlement.' `
        -Rationale 'Adds SearchQueryInitiated to selected mailbox audit settings.' `
        -SafeDefault 'Excluded unless explicitly requested.' `
        -TenantImpact 'Changes mailbox audit event selection.'))

    $labels = @(
        if ($Config.Contains('Labels') -and $Config.Labels) {
            $Config.Labels
        }
    )
    $subLabelCount = 0
    foreach ($label in $labels) {
        if ($label -is [System.Collections.IDictionary] -and
            $label.Contains('SubLabels') -and $label.SubLabels) {
            $subLabelCount += @($label.SubLabels).Count
        }
    }
    $labelsIntent = if ($skipLabels) {
        'Excluded'
    } elseif ($labels.Count -gt 0) {
        'Included'
    } else {
        'NotConfigured'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.labels.taxonomy' `
        -Module 'Setup-SensitivityLabels' `
        -Title "Sensitivity-label taxonomy ($($labels.Count) roots, $subLabelCount sub-labels)" `
        -Intent $labelsIntent `
        -ConfigPath 'Labels' `
        -Gate $(if ($skipLabels) { '-SkipLabels' } else { 'Configured label collection' }) `
        -Rationale 'Creates or reconciles the configured classification taxonomy.' `
        -SafeDefault 'Uses stable built-in signatures and managed-object collision checks.' `
        -TenantImpact 'Labels can appear in Office and Purview after publication.'))

    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.labels.priority' `
        -Module 'Setup-SensitivityLabels' `
        -Title 'Sensitivity-label priority order' `
        -Intent $labelsIntent `
        -ConfigPath 'Labels' `
        -Gate $(if ($skipLabels) { '-SkipLabels' } else { 'Configured label order' }) `
        -Rationale 'Uses config order as the intended label priority.' `
        -SafeDefault 'Preserves the configured least-to-most-sensitive order.' `
        -TenantImpact 'May change label priority.'))

    $labelPolicy = if ($Config.Contains('LabelPolicy') -and
        $Config.LabelPolicy -is [System.Collections.IDictionary]) {
        $Config.LabelPolicy
    } else {
        @{}
    }
    $labelPolicyIntent = if ($skipLabels) {
        'Excluded'
    } elseif ($labelPolicy.Count -gt 0) {
        'Included'
    } else {
        'NotConfigured'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.labels.publish' `
        -Module 'Setup-SensitivityLabels' `
        -Title 'Publish labels and set defaults' `
        -Intent $labelPolicyIntent `
        -ConfigPath 'LabelPolicy' `
        -Gate $(if ($skipLabels) { '-SkipLabels' } else { 'Configured label policy' }) `
        -Rationale 'Publishes the configured label set and defaults.' `
        -SafeDefault 'Uses the configured policy scope and defaults.' `
        -TenantImpact 'Changes labels available to users and default labeling.'))

    $attachmentIntent = if ($skipLabels) {
        'Excluded'
    } elseif ($labelPolicy.Contains('AttachmentAction')) {
        'Included'
    } else {
        'NotConfigured'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.labels.attachment-inheritance' `
        -Module 'Setup-SensitivityLabels' `
        -Title 'Email label inheritance from attachments' `
        -Intent $attachmentIntent `
        -ConfigPath 'LabelPolicy.AttachmentAction' `
        -Gate $(if ($skipLabels) { '-SkipLabels' } else { 'Configuration value' }) `
        -Rationale 'Applies the configured attachment-based label behavior to email.' `
        -SafeDefault 'Configuration controlled.' `
        -TenantImpact 'May cause email to inherit a sensitivity label.'))

    $contentMarkIntent = if ($skipLabels) {
        'Excluded'
    } elseif ($Config.Contains('EnableContentMarking') -and
        [bool]$Config.EnableContentMarking) {
        'Included'
    } else {
        'Excluded'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.labels.content-marking' `
        -Module 'Setup-SensitivityLabels' `
        -Title 'Label content marking' `
        -Intent $contentMarkIntent `
        -ConfigPath 'EnableContentMarking' `
        -Gate $(if ($skipLabels) { '-SkipLabels' } else { 'Configuration value' }) `
        -Rationale 'Applies configured headers, footers, or watermarks.' `
        -SafeDefault 'Disabled in the shipped configuration.' `
        -TenantImpact 'May add visible markings to labeled documents.'))

    $encryptedLabels = @(
        foreach ($label in $labels) {
            if ($label -isnot [System.Collections.IDictionary]) { continue }
            if ($label.Contains('Encrypt') -and [bool]$label.Encrypt) { $label }
            if ($label.Contains('SubLabels') -and $label.SubLabels) {
                foreach ($subLabel in @($label.SubLabels)) {
                    if ($subLabel -is [System.Collections.IDictionary] -and
                        $subLabel.Contains('Encrypt') -and [bool]$subLabel.Encrypt) {
                        $subLabel
                    }
                }
            }
        }
    )
    $encryptionIntent = if ($skipLabels) {
        'Excluded'
    } elseif ($encryptedLabels.Count -gt 0) {
        'Included'
    } else {
        'NotConfigured'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.labels.encryption' `
        -Module 'Setup-SensitivityLabels' `
        -Title "Label encryption ($($encryptedLabels.Count) configured labels)" `
        -Intent $encryptionIntent `
        -ConfigPath 'Labels[].Encrypt' `
        -Gate $(if ($skipLabels) { '-SkipLabels' } else { 'Configured label protection' }) `
        -RuntimeCondition 'Tenant-scoped rights resolve only after tenant identity verification.' `
        -Rationale 'Protects configured high-sensitivity labels.' `
        -SafeDefault 'Tenant-bound rights fail closed if identity cannot be resolved.' `
        -TenantImpact 'May restrict access to labeled content.'))

    $containerScopeIntent = if ($skipLabels -or $skipContainers) {
        'Excluded'
    } elseif ($labels.Count -gt 0) {
        if ($bpOnly) { 'Included' } else { 'Conditional' }
    } else {
        'NotConfigured'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.labels.container-scope' `
        -Module 'Setup-SensitivityLabels' `
        -Title 'Container scope on published labels' `
        -Intent $containerScopeIntent `
        -ConfigPath 'Labels[].ContentType' `
        -Gate $(if ($skipContainers) { '-SkipContainerLabels' } elseif ($skipLabels) { '-SkipLabels' } else { 'Default on' }) `
        -RuntimeCondition $containerRuntimeCondition `
        -Rationale 'Makes selected labels available for sites and Microsoft 365 groups.' `
        -SafeDefault 'Default on with an explicit opt-out.' `
        -TenantImpact 'May expose labels in container scope pickers.'))

    $dlpPolicies = @(
        if ($Config.Contains('DlpPolicies') -and $Config.DlpPolicies) {
            $Config.DlpPolicies
        }
    )
    $baselineDlp = @(
        @{ Workload = 'Exchange'; ActionId = 'purview.dlp.exchange'; Title = 'Exchange DLP policy'; ConfigPath = 'DlpPolicies[Workload=Exchange]' }
        @{ Workload = 'SharePointOneDrive'; ActionId = 'purview.dlp.sharepoint-onedrive'; Title = 'SharePoint and OneDrive DLP policy'; ConfigPath = 'DlpPolicies[Workload=SharePointOneDrive]' }
        @{ Workload = 'Endpoint'; ActionId = 'purview.dlp.endpoint'; Title = 'Endpoint DLP policy'; ConfigPath = 'DlpPolicies[Workload=Endpoint]' }
    )
    $dlpSimulationConfigured = [bool](Get-PurviewPlanValue $Config 'DlpStartInSimulation' $true)
    foreach ($definition in $baselineDlp) {
        $policyMatches = @(
            $dlpPolicies |
                Where-Object {
                    (Get-PurviewPlanWorkload -Policy $_) -eq $definition.Workload
                }
        )
        $intent = if ($skipDlp) {
            'Excluded'
        } elseif ($policyMatches.Count -eq 0) {
            'NotConfigured'
        } elseif ($definition.Workload -eq 'Endpoint' -and $bpOnly) {
            'Excluded'
        } elseif ($definition.Workload -eq 'Endpoint') {
            'Conditional'
        } else {
            'Included'
        }
        $condition = if ($definition.Workload -eq 'Endpoint') {
            if ($noLicenseDetect) {
                'Operator must confirm E5 or Microsoft Purview Suite entitlement because auto-detection is disabled.'
            } else {
                'Runtime license detection must confirm E5 or Microsoft Purview Suite entitlement.'
            }
        } else {
            'Requires the workload permissions and service availability documented for DLP.'
        }
        $actions.Add((New-PurviewPlanAction `
            -ActionId $definition.ActionId `
            -Module 'Setup-DLP' `
            -Title $definition.Title `
            -Intent $intent `
            -ConfigPath $definition.ConfigPath `
            -Gate $(if ($skipDlp) { '-SkipDLP' } elseif ($bpOnly -and $definition.Workload -eq 'Endpoint') { '-BPOnly' } else { 'Configured policy' }) `
            -RuntimeCondition $condition `
            -Rationale 'Uses configured label-based conditions and workload scope.' `
            -SafeDefault $(if ($dlpSimulationConfigured) { 'Simulation mode is configured.' } else { 'Enforcement mode is configured or simulation is not configured.' }) `
            -TenantImpact 'May create or reconcile a DLP policy after tenant state is read.'))
    }

    $customIndex = 0
    $policyIndex = -1
    foreach ($policy in $dlpPolicies) {
        $policyIndex++
        $workload = Get-PurviewPlanWorkload -Policy $policy
        if ($workload -in @('Exchange', 'SharePointOneDrive', 'Endpoint')) {
            continue
        }
        $customIndex++
        $customIntent = 'Excluded'
        $actions.Add((New-PurviewPlanAction `
            -ActionId "purview.dlp.custom-$customIndex" `
            -Module 'Setup-DLP' `
            -Title "Additional configured DLP policy $customIndex" `
            -Intent $customIntent `
            -ConfigPath "DlpPolicies[$policyIndex]" `
            -Gate $(if ($skipDlp) { '-SkipDLP' } else { 'Unsupported by Setup-DLP' }) `
            -RuntimeCondition 'Setup-DLP supports only Exchange, SharePointOneDrive, and Endpoint workloads.' `
            -Rationale 'The configured workload is outside the current Setup-DLP implementation and would otherwise terminate that module.' `
            -SafeDefault 'Excluded because no supported deployment path exists.' `
            -TenantImpact 'No tenant change is planned for this unsupported workload.'))
    }

    $retentionLocations = Get-PurviewRetentionLocationClassification -Value $(
        if ($Config.Contains('Retention') -and $Config.Retention) {
            Get-PurviewPlanValue $Config.Retention 'Locations' @()
        } else {
            @()
        }
    )
    $retentionIntent = if (-not $Config.Contains('Retention') -or -not $Config.Retention) {
        'NotConfigured'
    } elseif (-not $applyRetention) {
        'Excluded'
    } elseif ($retentionLocations.Supported.Count -eq 0) {
        'Excluded'
    } else {
        'Included'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.retention.exchange' `
        -Module 'Setup-Retention' `
        -Title 'Exchange retention policy' `
        -Intent $retentionIntent `
        -ConfigPath 'Retention' `
        -Gate $(if (-not $applyRetention) {
            'Explicit opt-in not selected'
        } elseif ($retentionLocations.Supported.Count -eq 0) {
            'No supported Retention.Locations'
        } else {
            '-ApplyRetention'
        }) `
        -Rationale $(if ($applyRetention -and
            $retentionLocations.Supported.Count -eq 0 -and
            $retentionLocations.Unsupported.Count -gt 0) {
            'Configured retention destinations are unsupported, so no deployable retention action is planned.'
        } elseif ($applyRetention -and $retentionLocations.Supported.Count -eq 0) {
            'No retention destinations are configured, so no deployable retention action is planned.'
        } else {
            'Applies the configured retain-then-delete policy only after explicit opt-in.'
        }) `
        -SafeDefault $(if ($applyRetention -and $retentionLocations.Supported.Count -eq 0) {
            'Excluded because creating a locationless retention policy is unsafe.'
        } else {
            'Excluded because retention can be destructive and difficult to reverse.'
        }) `
        -TenantImpact $(if ($retentionLocations.Supported.Count -gt 0) {
            'May retain and later delete content in the supported configured locations.'
        } else {
            'No tenant change is planned until a supported retention location is configured.'
        })))

    $aiPolicies = @(
        if ($Config.Contains('AIGovernance') -and
            $Config.AIGovernance -is [System.Collections.IDictionary] -and
            $Config.AIGovernance.Contains('DlpPolicies')) {
            $Config.AIGovernance.DlpPolicies
        }
    )
    $aiIntent = if ($skipAi -or $bpOnly) {
        'Excluded'
    } elseif ($aiPolicies.Count -eq 0) {
        'NotConfigured'
    } else {
        'Conditional'
    }
    $aiCondition = if ($noLicenseDetect) {
        'Operator must confirm E5 or Microsoft Purview Suite entitlement because auto-detection is disabled.'
    } else {
        'Runtime license detection must confirm E5 or Microsoft Purview Suite entitlement.'
    }
    $actions.Add((New-PurviewPlanAction `
        -ActionId 'purview.ai.copilot-dlp' `
        -Module 'Setup-AIGovernance' `
        -Title "Copilot DLP policies ($($aiPolicies.Count) configured)" `
        -Intent $aiIntent `
        -ConfigPath 'AIGovernance.DlpPolicies' `
        -Gate $(if ($skipAi) { '-SkipAIControls' } elseif ($bpOnly) { '-BPOnly' } else { 'Default on when entitled' }) `
        -RuntimeCondition $aiCondition `
        -Rationale 'Restricts Copilot grounding on configured high-sensitivity content.' `
        -SafeDefault 'License-gated and subject to simulation configuration.' `
        -TenantImpact 'May create or reconcile Microsoft 365 Copilot DLP policies.'))

    Test-PurviewDeploymentPlanMapping `
        -GuideMapping $GuideMapping `
        -Actions $actions `
        -ExpectedRole 'Primary'
    foreach ($supportingMapping in $SupportingGuideMappings) {
        if ($supportingMapping -isnot [System.Collections.IDictionary]) {
            throw 'Supporting guide mappings must be dictionaries.'
        }
        Test-PurviewDeploymentPlanMapping `
            -GuideMapping $supportingMapping `
            -Actions $actions `
            -ExpectedRole 'Supporting'
    }

    $controlsByAction = @{}
    foreach ($control in @($GuideMapping.Controls)) {
        foreach ($actionId in @($control.ActionIds)) {
            if (-not $controlsByAction.ContainsKey([string]$actionId)) {
                $controlsByAction[[string]$actionId] = [Collections.Generic.List[object]]::new()
            }
            $controlsByAction[[string]$actionId].Add($control)
        }
    }

    foreach ($action in $actions) {
        if (-not $controlsByAction.ContainsKey($action.ActionId)) {
            continue
        }
        $mappedControls = @($controlsByAction[$action.ActionId])
        $action.GuideControlIds = @($mappedControls | ForEach-Object { [string]$_.Id } | Sort-Object)
        $action.PrimaryGuideRecommendations = @(
            $mappedControls |
                Sort-Object @{
                    Expression = {
                        switch ([string]$_.Level) {
                            'Good' { 1 }
                            'Better' { 2 }
                            'Best' { 3 }
                        }
                    }
                }, Id |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        ControlId = [string]$_.Id
                        Level = [string]$_.Level
                        Summary = [string]$_.Summary
                    }
                }
        )
        $mappedLevels = @(
            $mappedControls |
                ForEach-Object { [string]$_.Level } |
                Select-Object -Unique
        )
        $action.PrimaryGuideLevel = if ($mappedLevels.Count -eq 1) {
            [string]$mappedLevels[0]
        } elseif ($mappedLevels.Count -gt 1) {
            $mappedLevels -join ', '
        } else {
            'Extension'
        }
        $action.ComparisonStatus = Get-PurviewPlanComparisonStatus -Controls $mappedControls
    }

    foreach ($supportingMapping in $SupportingGuideMappings) {
        $supportingControlsByAction = @{}
        foreach ($control in @($supportingMapping.Controls)) {
            foreach ($actionId in @($control.ActionIds)) {
                if (-not $supportingControlsByAction.ContainsKey([string]$actionId)) {
                    $supportingControlsByAction[[string]$actionId] =
                        [Collections.Generic.List[object]]::new()
                }
                $supportingControlsByAction[[string]$actionId].Add($control)
            }
        }
        foreach ($action in $actions) {
            if (-not $supportingControlsByAction.ContainsKey($action.ActionId)) {
                continue
            }
            $mappedControls = @($supportingControlsByAction[$action.ActionId])
            $action.SupportingGuideMappings = @(
                @($action.SupportingGuideMappings) +
                [pscustomobject][ordered]@{
                    GuideId = [string]$supportingMapping.Guide.Id
                    GuideTitle = [string]$supportingMapping.Guide.Title
                    ControlIds = @(
                        $mappedControls |
                            ForEach-Object { [string]$_.Id } |
                            Sort-Object
                    )
                    ComparisonStatus = Get-PurviewPlanComparisonStatus -Controls $mappedControls
                }
            )
            $action.SupportingGuideMappings = @(
                $action.SupportingGuideMappings |
                    ForEach-Object {
                        $_.ControlIds = @($_.ControlIds | Sort-Object -Unique)
                        $_
                    } |
                    Sort-Object GuideId
            )
        }
    }

    $moduleOrder = @(
        'Setup-TenantSettings',
        'Setup-SensitivityLabels',
        'Setup-DLP',
        'Setup-Retention',
        'Setup-AIGovernance'
    )
    $moduleSummaries = foreach ($module in $moduleOrder) {
        $moduleActions = @($actions | Where-Object Module -eq $module)
        $intent = if (@($moduleActions | Where-Object Intent -eq 'Included').Count -gt 0) {
            'Included'
        } elseif (@($moduleActions | Where-Object Intent -eq 'Conditional').Count -gt 0) {
            'Conditional'
        } elseif (@($moduleActions | Where-Object Intent -eq 'Excluded').Count -gt 0) {
            'Excluded'
        } else {
            'NotConfigured'
        }
        [pscustomobject][ordered]@{
            Module = $module
            Intent = $intent
            Included = @($moduleActions | Where-Object Intent -eq 'Included').Count
            Conditional = @($moduleActions | Where-Object Intent -eq 'Conditional').Count
            Excluded = @($moduleActions | Where-Object Intent -eq 'Excluded').Count
            NotConfigured = @($moduleActions | Where-Object Intent -eq 'NotConfigured').Count
        }
    }

    $actionsById = @{}
    foreach ($action in $actions) {
        $actionsById[$action.ActionId] = $action
    }
    $guideControls = foreach ($control in @($GuideMapping.Controls)) {
        $related = @(
            foreach ($actionId in @($control.ActionIds)) {
                if ($actionsById.ContainsKey([string]$actionId)) {
                    $actionsById[[string]$actionId]
                }
            }
        )
        $intent = if ($related.Count -eq 0) {
            'NotConfigured'
        } elseif (@($related | Where-Object Intent -eq 'Included').Count -gt 0) {
            'Included'
        } elseif (@($related | Where-Object Intent -eq 'Conditional').Count -gt 0) {
            'Conditional'
        } elseif (@($related | Where-Object Intent -eq 'Excluded').Count -gt 0) {
            'Excluded'
        } else {
            'NotConfigured'
        }
        [pscustomobject][ordered]@{
            ControlId = [string]$control.Id
            Level = [string]$control.Level
            Section = [string]$control.Section
            SourceSection = [string]$control.SourceSection
            Summary = [string]$control.Summary
            ComparisonStatus = [string]$control.Status
            Intent = $intent
            ActionIds = @($control.ActionIds | Sort-Object -Unique)
            ConfigPaths = @($control.ConfigPaths | Sort-Object -Unique)
            Rationale = [string]$control.Rationale
            ReferenceUris = @($control.ReferenceUris | Sort-Object -Unique)
        }
    }

    $supportingGuides = foreach ($supportingMapping in @(
        $SupportingGuideMappings | Sort-Object { [string]$_.Guide.Id }
    )) {
        $supportingControls = foreach ($control in @(
            $supportingMapping.Controls | Sort-Object { [string]$_.Id }
        )) {
            $related = @(
                foreach ($actionId in @($control.ActionIds)) {
                    if ($actionsById.ContainsKey([string]$actionId)) {
                        $actionsById[[string]$actionId]
                    }
                }
            )
            $intent = if ($related.Count -eq 0) {
                'NotConfigured'
            } elseif (@($related | Where-Object Intent -eq 'Included').Count -gt 0) {
                'Included'
            } elseif (@($related | Where-Object Intent -eq 'Conditional').Count -gt 0) {
                'Conditional'
            } elseif (@($related | Where-Object Intent -eq 'Excluded').Count -gt 0) {
                'Excluded'
            } else {
                'NotConfigured'
            }
            [pscustomobject][ordered]@{
                ControlId = [string]$control.Id
                Section = [string]$control.Section
                Summary = [string]$control.Summary
                ComparisonStatus = [string]$control.Status
                Intent = $intent
                ActionIds = @($control.ActionIds | Sort-Object -Unique)
                ConfigPaths = @($control.ConfigPaths | Sort-Object -Unique)
                Rationale = [string]$control.Rationale
                ReferenceUris = @($control.ReferenceUris | Sort-Object -Unique)
            }
        }
        [pscustomobject][ordered]@{
            Guide = [pscustomobject][ordered]@{
                Id = [string]$supportingMapping.Guide.Id
                Title = [string]$supportingMapping.Guide.Title
                Edition = [string]$supportingMapping.Guide.Edition
                RevisionDate = [string]$supportingMapping.Guide.RevisionDate
                VerifiedDate = [string]$supportingMapping.Guide.VerifiedDate
                Publisher = [string]$supportingMapping.Guide.Publisher
                SourceClassification = [string]$supportingMapping.Guide.SourceClassification
                SourceUri = [string]$supportingMapping.Guide.SourceUri
                SourceCommit = [string]$supportingMapping.Guide.SourceCommit
                Owner = [string]$supportingMapping.Guide.Owner
            }
            GuideControls = @($supportingControls | Sort-Object ControlId)
        }
    }

    $effectiveParameters = [ordered]@{}
    foreach ($name in @(
        'SkipTenantSettings', 'SkipLabels', 'SkipDLP', 'ApplyRetention',
        'SkipAIControls', 'SkipContainerLabels', 'EnablePremiumAudit',
        'AdoptExisting', 'EnableLabelCoAuthoring', 'NonInteractive',
        'AutoInstallModules', 'BPOnly', 'NoLicenseAutoDetect'
    )) {
        $effectiveParameters[$name] = Test-PurviewPlanParameter -Parameters $Parameters -Name $name
    }

    $premiumAuditMailboxCount = 0
    if ($premiumAudit -and $Parameters -and
        $Parameters.Keys -contains 'PremiumAuditMailbox') {
        $premiumAuditMailboxCount = @(
            @($Parameters['PremiumAuditMailbox']) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
        ).Count
    }
    $intendedState = Get-PurviewPlanIntendedState `
        -Config $Config `
        -Actions $actions `
        -SkipContainerLabels $skipContainers `
        -PremiumAuditMailboxCount $premiumAuditMailboxCount

    $intendedKeysByAction = @{}
    function AddIntendedKey([string] $ActionId, [string] $Key) {
        if (-not $intendedKeysByAction.ContainsKey($ActionId)) {
            $intendedKeysByAction[$ActionId] = [Collections.Generic.List[string]]::new()
        }
        if (-not $intendedKeysByAction[$ActionId].Contains($Key)) {
            $intendedKeysByAction[$ActionId].Add($Key)
        }
    }
    foreach ($item in $intendedState.TenantSettings) {
        AddIntendedKey -ActionId $item.ActionId -Key $item.Key
    }
    foreach ($item in $intendedState.Labels) {
        foreach ($actionId in @(
            'purview.labels.taxonomy',
            'purview.labels.priority',
            'purview.labels.content-marking',
            'purview.labels.encryption',
            'purview.labels.container-scope'
        )) {
            AddIntendedKey -ActionId $actionId -Key "labels/$($item.Key)"
        }
    }
    foreach ($actionId in @(
        'purview.labels.publish',
        'purview.labels.attachment-inheritance'
    )) {
        AddIntendedKey -ActionId $actionId -Key $intendedState.LabelPolicy.Key
    }
    foreach ($item in $intendedState.DlpPolicies) {
        AddIntendedKey -ActionId $item.ActionId -Key $item.Key
    }
    AddIntendedKey -ActionId $intendedState.Retention.ActionId -Key $intendedState.Retention.Key
    AddIntendedKey -ActionId $intendedState.Encryption.ActionId -Key $intendedState.Encryption.Key
    foreach ($item in $intendedState.AIGovernance) {
        AddIntendedKey -ActionId $item.ActionId -Key $item.Key
    }
    foreach ($action in $actions) {
        $action.IntendedStateKeys = if ($intendedKeysByAction.ContainsKey($action.ActionId)) {
            @($intendedKeysByAction[$action.ActionId] | Sort-Object)
        } else {
            @()
        }
    }
    $intendedStateJson = $intendedState | ConvertTo-Json -Depth 20 -Compress
    $intendedStateFingerprint = Get-PurviewPlanSha256 -Text $intendedStateJson

    $configHash = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $defaultConfigPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config\PurviewConfig.psd1'
    $configIdentity = if (
        [IO.Path]::GetFullPath($ConfigPath) -eq [IO.Path]::GetFullPath($defaultConfigPath)
    ) {
        'BuiltInDefault'
    } else {
        'OperatorProvided'
    }
    $resolvedPlanReference = if ([string]::IsNullOrWhiteSpace($PlanReference)) {
        New-PurviewPlanReference -PlanId $PlanId -GeneratedAt $GeneratedAt
    } else {
        $PlanReference
    }
    if ($resolvedPlanReference -notmatch '^PUR-\d{8}-\d{6}-[0-9A-F]{8}$') {
        throw "Plan reference '$resolvedPlanReference' is not valid."
    }

    $fingerprintInput = [ordered]@{
        Product = 'Purview'
        ManagedByTag = $managedByTag
        EffectiveParameters = $effectiveParameters
        IntendedState = $intendedState
        Guide = [ordered]@{
            Id = [string]$GuideMapping.Guide.Id
            Edition = [string]$GuideMapping.Guide.Edition
            RevisionDate = [string]$GuideMapping.Guide.RevisionDate
            SourceModifiedDate = [string]$GuideMapping.Guide.SourceModifiedDate
            Publisher = [string]$GuideMapping.Guide.Publisher
            SourceClassification = [string]$GuideMapping.Guide.SourceClassification
            SourceFileName = [string]$GuideMapping.Guide.SourceFileName
            Levels = @(
                $GuideMapping.Guide.Levels |
                    Sort-Object {
                        switch ([string]$_.Id) {
                            'Good' { 1 }
                            'Better' { 2 }
                            'Best' { 3 }
                        }
                    } |
                    ForEach-Object {
                        [pscustomobject][ordered]@{
                            Id = [string]$_.Id
                            Title = [string]$_.Title
                            Summary = [string]$_.Summary
                            Inherits = @($_.Inherits | Sort-Object -Unique)
                        }
                    }
            )
        }
        SupportingGuides = @(
            $supportingGuides |
                Sort-Object { $_.Guide.Id } |
                ForEach-Object {
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
        Modules = @($moduleSummaries)
        Actions = @($actions | Sort-Object ActionId)
        GuideControls = @($guideControls | Sort-Object ControlId)
    }
    $planFingerprint = Get-PurviewPlanSha256 -Text (
        $fingerprintInput | ConvertTo-Json -Depth 20 -Compress
    )

    return [pscustomobject][ordered]@{
        SchemaVersion = '1.2'
        ArtifactType = 'PurviewDeploymentPlan'
        Product = 'Purview'
        ToolkitVersion = $ScriptVersion
        ManagedByTag = $managedByTag
        PlanId = $PlanId.ToString()
        PlanReference = $resolvedPlanReference
        GeneratedAtUtc = $GeneratedAt.ToUniversalTime().ToString('o')
        IntentOnly = $true
        Disclaimer = 'This offline plan describes configuration intent only. It does not inspect tenant state, predict changes, or declare compliance.'
        Configuration = [pscustomobject][ordered]@{
            Identity = $configIdentity
            Sha256 = $configHash
        }
        PlanInputSha256 = $planFingerprint
        IntendedStateSha256 = $intendedStateFingerprint
        IntendedState = $intendedState
        Handoff = [pscustomobject][ordered]@{
            MinimumValidatorSchema = '1.0'
            Capabilities = @(
                'IntendedState',
                'ManagedOwnership',
                'PublicationMode',
                'EncryptionSettings',
                'OpaquePrincipalDigests',
                'CanonicalPublicLocations',
                'OpaqueLocationDigests',
                'RetentionLocationDisposition',
                'MultipleRecordsPerAction'
            )
        }
        EffectiveParameters = [pscustomobject]$effectiveParameters
        Guide = [pscustomobject][ordered]@{
            Id = [string]$GuideMapping.Guide.Id
            Title = [string]$GuideMapping.Guide.Title
            Edition = [string]$GuideMapping.Guide.Edition
            RevisionDate = [string]$GuideMapping.Guide.RevisionDate
            SourceModifiedDate = [string]$GuideMapping.Guide.SourceModifiedDate
            VerifiedDate = [string]$GuideMapping.Guide.VerifiedDate
            Publisher = [string]$GuideMapping.Guide.Publisher
            SourceClassification = [string]$GuideMapping.Guide.SourceClassification
            SourceFileName = [string]$GuideMapping.Guide.SourceFileName
            SourceUri = ''
            SourceCommit = ''
            Owner = [string]$GuideMapping.Guide.Owner
            Levels = @(
                $GuideMapping.Guide.Levels |
                    Sort-Object {
                        switch ([string]$_.Id) {
                            'Good' { 1 }
                            'Better' { 2 }
                            'Best' { 3 }
                        }
                    } |
                    ForEach-Object {
                        [pscustomobject][ordered]@{
                            Id = [string]$_.Id
                            Title = [string]$_.Title
                            Summary = [string]$_.Summary
                            Inherits = @($_.Inherits | Sort-Object -Unique)
                        }
                    }
            )
        }
        Modules = @($moduleSummaries)
        Actions = @($actions)
        GuideControls = @($guideControls)
        SupportingGuides = @($supportingGuides)
        Diagnostics = @($intendedState.Diagnostics)
    }
}

function ConvertTo-PurviewDeploymentPlanHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject] $Model
    )

    function Encode([object] $Value) {
        return [Net.WebUtility]::HtmlEncode([string]$Value)
    }

    $includedCount = @($Model.Actions | Where-Object Intent -eq 'Included').Count
    $conditionalCount = @($Model.Actions | Where-Object Intent -eq 'Conditional').Count
    $excludedCount = @($Model.Actions | Where-Object Intent -eq 'Excluded').Count
    $notConfiguredCount = @($Model.Actions | Where-Object Intent -eq 'NotConfigured').Count
    $selectedCount = $includedCount + $conditionalCount
    $mappedCount = @($Model.Actions | Where-Object PrimaryGuideLevel -ne 'Extension').Count
    $intendedStateJson = $Model.IntendedState | ConvertTo-Json -Depth 20

    $decisionActionIds = @(
        'purview.dlp.exchange',
        'purview.retention.exchange',
        'purview.tenant.label-coauthoring',
        'purview.dlp.endpoint'
    )
    $decisionActions = @(
        foreach ($actionId in $decisionActionIds) {
            $Model.Actions | Where-Object ActionId -eq $actionId | Select-Object -First 1
        }
    )

    $sb = [Text.StringBuilder]::new()
    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $sb.AppendLine('<title>Microsoft Purview Deployment Plan</title>')
    $null = $sb.AppendLine(@'
<script>
  (() => {
    const param = new URLSearchParams(window.location.search).get("scoutTheme");
    const theme =
      param || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", theme);
  })();
</script>
<style>
:root {
  color-scheme: light;
  --cp-bg: #f7f4ef;
  --cp-bg-elevated: #fcfbf8;
  --cp-surface: #ffffff;
  --cp-surface-soft: #f5f5f5;
  --cp-border: #dedede;
  --cp-border-strong: #919191;
  --cp-text: #242424;
  --cp-text-muted: #5c5c5c;
  --cp-text-soft: #6f6f6f;
  --cp-accent: #b11f4b;
  --cp-accent-hover: #9a1a41;
  --cp-accent-soft: rgba(177, 31, 75, 0.08);
  --cp-accent-fg: #ffffff;
  --cp-success: #16a34a;
  --cp-danger: #dc2626;
  --cp-warning: #f59e0b;
  --cp-link: #0078d4;
  --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.12);
  --cp-overlay: rgba(255, 255, 255, 0.8);
  --cp-panel: rgba(255, 255, 255, 0.86);
  --cp-panel-strong: rgba(255, 255, 255, 0.96);
  --cp-sheen: rgba(255, 255, 255, 0.55);
  --cp-highlight: rgba(177, 31, 75, 0.12);
}
html[data-theme="dark"] {
  color-scheme: dark;
  --cp-bg: #3d3b3a;
  --cp-bg-elevated: #343231;
  --cp-surface: #292929;
  --cp-surface-soft: #2e2e2e;
  --cp-border: #474747;
  --cp-border-strong: #5f5f5f;
  --cp-text: #dedede;
  --cp-text-muted: #919191;
  --cp-text-soft: #b0b0b0;
  --cp-accent: #fd8ea1;
  --cp-accent-hover: #fb7b91;
  --cp-accent-soft: rgba(253, 142, 161, 0.14);
  --cp-accent-fg: #1a1a1a;
  --cp-success: #4ade80;
  --cp-danger: #f87171;
  --cp-warning: #fbbf24;
  --cp-link: #4da6ff;
  --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.32);
  --cp-overlay: rgba(41, 41, 41, 0.88);
  --cp-panel: rgba(41, 41, 41, 0.72);
  --cp-panel-strong: rgba(41, 41, 41, 0.96);
  --cp-sheen: rgba(255, 255, 255, 0.04);
  --cp-highlight: rgba(253, 142, 161, 0.12);
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--cp-bg); color: var(--cp-text); font: 14px/1.5 "Segoe UI", Aptos, Calibri, -apple-system, BlinkMacSystemFont, sans-serif; }
a { color: var(--cp-link); }
button, summary { font: inherit; }
code { font-family: Consolas, "Courier New", Courier, monospace; font-size: .86rem; overflow-wrap: anywhere; }
.shell { width: min(1220px, calc(100% - 32px)); margin: 24px auto 48px; }
.hero, .section { background: var(--cp-surface); border: 1px solid var(--cp-border); border-radius: 16px; box-shadow: 0 1px 2px var(--cp-border); }
.hero { overflow: hidden; }
.hero-top { padding: 28px 32px 24px; border-top: 6px solid var(--cp-accent); }
.eyebrow { margin: 0 0 6px; color: var(--cp-accent); font-size: .78rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
h1, h2, h3, p { margin-top: 0; }
h1 { margin-bottom: 8px; font-size: clamp(1.7rem, 4vw, 2.4rem); line-height: 1.15; }
h2 { margin-bottom: 16px; font-size: 1.25rem; }
h3 { margin-bottom: 6px; font-size: 1rem; }
.subtitle, .muted { color: var(--cp-text-muted); }
.subtitle { margin-bottom: 0; font-size: 1rem; }
.hero-meta { display: flex; flex-wrap: wrap; gap: 12px 24px; padding: 14px 32px; background: var(--cp-surface-soft); border-top: 1px solid var(--cp-border); color: var(--cp-text-muted); font-size: .88rem; }
.hero-meta strong { color: var(--cp-text); }
.notice { display: grid; grid-template-columns: auto 1fr; gap: 12px; margin-top: 20px; padding: 16px 18px; background: var(--cp-accent-soft); border: 1px solid var(--cp-accent); border-radius: .625rem; }
.notice strong { color: var(--cp-accent); }
.notice p { margin: 0; }
.section { margin-top: 20px; padding: 24px; }
.section-heading { display: flex; align-items: end; justify-content: space-between; gap: 16px; margin-bottom: 16px; }
.section-heading h2, .section-heading p { margin-bottom: 0; }
.grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.metric { min-height: 112px; padding: 16px; background: var(--cp-surface-soft); border: 1px solid var(--cp-border); border-radius: .625rem; }
.metric-value { display: block; margin: 8px 0 4px; font-size: 1.9rem; font-weight: 700; line-height: 1; }
.metric-label { color: var(--cp-text-muted); font-size: .82rem; }
.decision-list { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.decision { padding: 16px; border: 1px solid var(--cp-border); border-left: 4px solid var(--cp-warning); border-radius: .625rem; }
.decision.Included { border-left-color: var(--cp-success); }
.decision.Excluded, .decision.NotConfigured { border-left-color: var(--cp-border-strong); }
.decision p { margin-bottom: 0; color: var(--cp-text-muted); }
.tag { display: inline-block; padding: 3px 9px; border: 1px solid var(--cp-border-strong); border-radius: .625rem; color: var(--cp-text-muted); font-size: .75rem; font-weight: 650; white-space: nowrap; }
.tag.Included, .tag.Aligned { border-color: var(--cp-success); color: var(--cp-success); }
.tag.Conditional { border-color: var(--cp-warning); color: var(--cp-warning); }
.tag.Extended { border-color: var(--cp-link); color: var(--cp-link); }
.tag.Excluded, .tag.NotConfigured, .tag.NotImplemented, .tag.NotApplicable { border-color: var(--cp-border-strong); color: var(--cp-text-muted); }
.module-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 10px; }
.module { padding: 14px; background: var(--cp-surface-soft); border: 1px solid var(--cp-border); border-radius: .625rem; }
.module p { margin-bottom: 0; color: var(--cp-text-muted); font-size: .82rem; }
.module .tag { margin-bottom: 10px; }
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
.preview-help { margin-bottom: 14px; }
.preview-help h3 { margin-top: 20px; }
.preview-help h3:first-child { margin-top: 0; }
.preview-help .table-wrap { margin-bottom: 14px; }
.preview-help .closing-note { margin-bottom: 0; padding: 12px 14px; background: var(--cp-accent-soft); border-radius: .625rem; }
.filter { padding: 7px 11px; background: var(--cp-surface); color: var(--cp-text); border: 1px solid var(--cp-border-strong); border-radius: .625rem; cursor: pointer; }
.filter:hover, .filter.active { background: var(--cp-accent); border-color: var(--cp-accent); color: var(--cp-accent-fg); }
.table-wrap { overflow-x: auto; border: 1px solid var(--cp-border); border-radius: .625rem; }
table { width: 100%; border-collapse: collapse; font-size: .88rem; }
th, td { padding: 11px 12px; border-bottom: 1px solid var(--cp-border); text-align: left; vertical-align: top; }
th { background: var(--cp-surface-soft); color: var(--cp-text-muted); font-size: .72rem; letter-spacing: .04em; text-transform: uppercase; }
tbody tr:last-child td { border-bottom: 0; }
.action-title { min-width: 220px; font-weight: 650; }
.small { color: var(--cp-text-muted); font-size: .78rem; }
.tiers { display: grid; gap: 12px; }
.tier { border: 1px solid var(--cp-border); border-radius: .625rem; overflow: hidden; }
.tier > summary { cursor: pointer; list-style: none; padding: 16px 18px; background: var(--cp-surface-soft); font-weight: 700; }
.tier > summary::-webkit-details-marker { display: none; }
.tier-body { padding: 16px 18px; }
.tier-body > p { color: var(--cp-text-muted); }
.meta { display: grid; grid-template-columns: minmax(170px, 220px) minmax(0, 1fr); gap: 8px 16px; }
.meta dt { color: var(--cp-text-muted); }
.meta dd { margin: 0; overflow-wrap: anywhere; }
.handoff { padding: 18px; background: var(--cp-accent-soft); border: 1px solid var(--cp-accent); border-radius: .625rem; }
.handoff p:last-child { margin-bottom: 0; }
pre.snapshot { max-height: 520px; margin: 0; padding: 16px; overflow: auto; background: var(--cp-surface-soft); border: 1px solid var(--cp-border); border-radius: .625rem; color: var(--cp-text); font: .78rem/1.45 Consolas, "Courier New", Courier, monospace; white-space: pre-wrap; word-break: break-word; }
footer { margin-top: 20px; padding: 16px 4px; color: var(--cp-text-muted); font-size: .78rem; }
[hidden] { display: none !important; }
@media (max-width: 900px) { .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .module-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 620px) { .shell { width: min(100% - 20px, 1220px); margin-top: 10px; } .hero-top, .section { padding: 18px; } .hero-meta { padding: 12px 18px; } .grid, .decision-list, .module-grid { grid-template-columns: 1fr; } .meta { grid-template-columns: 1fr; gap: 2px; } .meta dd { margin-bottom: 8px; } }
</style>
'@)
    $null = $sb.AppendLine('</head><body><main class="shell">')
    $null = $sb.AppendLine('<header class="hero"><div class="hero-top">')
    $null = $sb.AppendLine('<p class="eyebrow">Pre-connection intent artifact</p>')
    $null = $sb.AppendLine('<h1>Microsoft Purview Deployment Plan</h1>')
    $null = $sb.AppendLine('<p class="subtitle">Review configuration scope, safety gates, and guide alignment before authentication.</p>')
    $null = $sb.AppendLine(('<div class="notice"><strong>Intent only</strong><p>{0}</p></div></div>' -f (Encode $Model.Disclaimer)))
    $null = $sb.AppendLine('<div class="hero-meta">')
    $null = $sb.AppendLine(('<span><strong>Plan reference</strong> <code>{0}</code></span>' -f (Encode $Model.PlanReference)))
    $null = $sb.AppendLine(('<span><strong>Generated</strong> {0}</span>' -f (Encode $Model.GeneratedAtUtc)))
    $null = $sb.AppendLine(('<span><strong>Source</strong> {0}, {1}</span>' -f (Encode $Model.Guide.Title), (Encode $Model.Guide.Edition)))
    $null = $sb.AppendLine('</div></header>')

    $null = $sb.AppendLine('<section class="section"><div class="section-heading"><h2>At a glance</h2><p>Configuration-derived action intent</p></div><div class="grid">')
    foreach ($metric in @(
        @($selectedCount, 'Included or conditional actions'),
        @($conditionalCount, 'Runtime-dependent actions'),
        @(($excludedCount + $notConfiguredCount), 'Excluded or not configured'),
        @($mappedCount, 'Actions mapped to the SMB guide')
    )) {
        $null = $sb.AppendLine(('<div class="metric"><span class="metric-label">{0}</span><span class="metric-value">{1}</span></div>' -f (Encode $metric[1]), $metric[0]))
    }
    $null = $sb.AppendLine('</div></section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-heading"><h2>Key configuration decisions</h2><p>Review before sign-in</p></div><div class="decision-list">')
    foreach ($action in $decisionActions) {
        if ($null -eq $action) { continue }
        $null = $sb.AppendLine(('<article class="decision {0}"><span class="tag {0}">{1}</span><h3>{2}</h3><p>{3}</p><p class="small"><strong>Gate:</strong> {4}</p></article>' -f `
            (Encode $action.Intent), (Encode (Get-PurviewPlanStatusLabel $action.Intent)), (Encode $action.Title), `
            (Encode $action.SafeDefault), (Encode $action.Gate)))
    }
    $null = $sb.AppendLine('</div></section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-heading"><h2>Module intent</h2><p>Counts come from the action records below</p></div><div class="module-grid">')
    foreach ($module in $Model.Modules) {
        $null = $sb.AppendLine(('<article class="module"><span class="tag {0}">{1}</span><h3>{2}</h3><p>{3} included, {4} conditional, {5} excluded, {6} not configured</p></article>' -f `
            (Encode $module.Intent), (Encode (Get-PurviewPlanStatusLabel $module.Intent)), (Encode $module.Module), `
            $module.Included, $module.Conditional, $module.Excluded, $module.NotConfigured))
    }
    $null = $sb.AppendLine('</div></section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-heading"><h2>Action Preview</h2><p>Filter by deployment intent</p></div>')
    $null = $sb.AppendLine('<details class="tier preview-help"><summary>How to read the Action Preview</summary><div class="tier-body">')
    $null = $sb.AppendLine('<h3>Intent</h3><p>Intent describes what the current configuration and invocation parameters ask the toolkit to do. It does not describe existing tenant state or predict whether an object will be created or updated.</p>')
    $null = $sb.AppendLine('<div class="table-wrap"><table><thead><tr><th>Status</th><th>Meaning</th></tr></thead><tbody>')
    $null = $sb.AppendLine('<tr><td><span class="tag Included">Included</span></td><td>The action is configured and in scope for this deployment. Runtime checks and <code>-WhatIf</code> still apply.</td></tr>')
    $null = $sb.AppendLine('<tr><td><span class="tag Conditional">Conditional</span></td><td>The action is in scope only if a runtime requirement is satisfied, such as licensing, service availability, or another prerequisite that cannot be verified offline.</td></tr>')
    $null = $sb.AppendLine('<tr><td><span class="tag Excluded">Excluded</span></td><td>The action will not run because it was disabled by a switch, blocked by a safety gate, or requires an explicit opt-in that was not selected.</td></tr>')
    $null = $sb.AppendLine('<tr><td><span class="tag NotConfigured">Not configured</span></td><td>The configuration does not contain the settings or objects needed to plan this action.</td></tr>')
    $null = $sb.AppendLine('</tbody></table></div>')
    $null = $sb.AppendLine('<h3>Deployment Priority Level</h3><p>The level identifies the minimum priority where the action appears in the primary Data Security Deployment Guide. The priority levels are cumulative.</p>')
    $null = $sb.AppendLine('<div class="table-wrap"><table><thead><tr><th>Level</th><th>Meaning</th></tr></thead><tbody>')
    $null = $sb.AppendLine('<tr><td><strong>Priority 1 (Good)</strong></td><td>Foundational protection that establishes baseline visibility, classification, and data-loss controls.</td></tr>')
    $null = $sb.AppendLine('<tr><td><strong>Priority 2 (Better)</strong></td><td>Protection that builds on Priority 1. Completing Priority 2 assumes the applicable Priority 1 tasks are also addressed.</td></tr>')
    $null = $sb.AppendLine('<tr><td><strong>Priority 3 (Best)</strong></td><td>Advanced protection that builds on Priorities 1 and 2 and commonly requires Purview Suite capabilities or additional operational maturity.</td></tr>')
    $null = $sb.AppendLine('<tr><td><strong>Toolkit extension</strong></td><td>A toolkit capability that the primary guide does not assign to a deployment priority. A supporting source such as Microsoft Learn may still recommend it.</td></tr>')
    $null = $sb.AppendLine('</tbody></table></div>')
    $null = $sb.AppendLine('<h3>Recommendation and comparison</h3><p>The recommendation contains the stable primary-guide control ID and its normalized summary. <strong>Toolkit extension</strong> means that no primary-guide control is mapped to the action. The badge beneath the recommendation describes how toolkit coverage compares with the source.</p>')
    $null = $sb.AppendLine('<div class="table-wrap"><table><thead><tr><th>Status</th><th>Meaning</th></tr></thead><tbody>')
    $null = $sb.AppendLine('<tr><td><span class="tag Aligned">Aligned</span></td><td>The toolkit action directly implements the mapped recommendation at the level of intent described by the guide.</td></tr>')
    $null = $sb.AppendLine('<tr><td><span class="tag Conditional">Conditional</span></td><td>The toolkit supports some or all of the recommendation, but coverage depends on a prerequisite, explicit opt-in, licensing, or a documented implementation difference.</td></tr>')
    $null = $sb.AppendLine('<tr><td><span class="tag Extended">Extended</span></td><td>The action is a toolkit capability outside the primary guide''s deployment priorities.</td></tr>')
    $null = $sb.AppendLine('<tr><td><span class="tag NotImplemented">Not implemented</span></td><td>The primary guide recommends the capability, but the toolkit does not currently provide an action that implements it. This normally appears in the guide-coverage tables.</td></tr>')
    $null = $sb.AppendLine('<tr><td><span class="tag NotApplicable">Not applicable</span></td><td>The recommendation is intentionally outside the Purview toolkit''s product or automation boundary.</td></tr>')
    $null = $sb.AppendLine('</tbody></table></div>')
    $null = $sb.AppendLine('<p class="closing-note"><strong>Read the columns together:</strong> Intent shows whether the current run includes the action; Deployment Priority Level shows where the primary guide introduces it; comparison shows how closely the toolkit represents that recommendation. None of these values is a tenant-compliance result.</p>')
    $null = $sb.AppendLine('</div></details>')
    $null = $sb.AppendLine('<div class="toolbar" role="group" aria-label="Filter actions by intent">')
    foreach ($filter in @('All', 'Included', 'Conditional', 'Excluded', 'NotConfigured')) {
        $active = if ($filter -eq 'All') { ' active' } else { '' }
        $label = Get-PurviewPlanStatusLabel $filter
        $null = $sb.AppendLine(('<button type="button" class="filter{0}" data-filter="{1}">{2}</button>' -f $active, (Encode $filter), (Encode $label)))
    }
    $null = $sb.AppendLine('</div><div class="table-wrap"><table><thead><tr><th>Action</th><th>Module</th><th>Intent</th><th>Deployment Priority Level</th><th>Recommendation</th><th>Gate</th></tr></thead><tbody id="action-rows">')
    foreach ($action in $Model.Actions) {
        $recommendations = if (@($action.PrimaryGuideRecommendations).Count -gt 0) {
            @($action.PrimaryGuideRecommendations | ForEach-Object { '{0}: {1}' -f $_.ControlId, $_.Summary }) -join '; '
        } else {
            'Toolkit extension'
        }
        $null = $sb.AppendLine(('<tr data-intent="{0}"><td class="action-title"><code>{1}</code><br>{2}<details><summary class="small">Rationale and impact</summary><p class="small">{3}</p><p class="small"><strong>Safe default:</strong> {4}<br><strong>Tenant impact:</strong> {5}</p></details></td><td><code>{6}</code></td><td><span class="tag {0}">{7}</span></td><td>{8}</td><td>{9}<div class="small"><span class="tag {10}">{11}</span></div></td><td><code>{12}</code><div class="small">{13}</div></td></tr>' -f `
            (Encode $action.Intent), (Encode $action.ActionId), (Encode $action.Title), (Encode $action.Rationale), `
            (Encode $action.SafeDefault), (Encode $action.TenantImpact), (Encode $action.Module), `
            (Encode (Get-PurviewPlanStatusLabel $action.Intent)), (Encode (Get-PurviewPlanLevelLabel $action.PrimaryGuideLevel)), `
            (Encode $recommendations), (Encode $action.ComparisonStatus), `
            (Encode (Get-PurviewPlanStatusLabel $action.ComparisonStatus)), (Encode $action.Gate), `
            (Encode $action.RuntimeCondition)))
    }
    $null = $sb.AppendLine('</tbody></table></div></section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-heading"><h2>Data Security Deployment Guide for Small Business</h2><p>Recommendations are grouped by minimum level</p></div><div class="tiers">')
    foreach ($level in $Model.Guide.Levels) {
        $levelControls = @($Model.GuideControls | Where-Object Level -eq $level.Id)
        $inheritance = if (@($level.Inherits).Count -gt 0) {
            ' Includes {0}.' -f (@($level.Inherits) -join ' and ')
        } else {
            ''
        }
        $null = $sb.AppendLine(('<details class="tier"{0}><summary>{1} &mdash; {2} recommendations</summary><div class="tier-body"><p>{3}{4}</p><div class="table-wrap"><table><thead><tr><th>Control</th><th>Recommendation</th><th>Comparison</th><th>Plan intent</th><th>Mapped actions</th></tr></thead><tbody>' -f `
            $(if ($level.Id -eq 'Good') { ' open' } else { '' }), (Encode (Get-PurviewPlanLevelLabel $level.Id)), $levelControls.Count, `
            (Encode $level.Summary), (Encode $inheritance)))
        foreach ($control in $levelControls) {
            $actionText = if (@($control.ActionIds).Count -gt 0) { @($control.ActionIds) -join ', ' } else { '(none)' }
            $null = $sb.AppendLine(('<tr><td><code>{0}</code><div class="small">{1}</div></td><td>{2}<div class="small">Source: {3}</div></td><td><span class="tag {4}">{5}</span><div class="small">{6}</div></td><td><span class="tag {7}">{8}</span></td><td><code>{9}</code></td></tr>' -f `
                (Encode $control.ControlId), (Encode $control.Section), (Encode $control.Summary), (Encode $control.SourceSection), `
                (Encode $control.ComparisonStatus), (Encode (Get-PurviewPlanStatusLabel $control.ComparisonStatus)), `
                (Encode $control.Rationale), (Encode $control.Intent), `
                (Encode (Get-PurviewPlanStatusLabel $control.Intent)), (Encode $actionText)))
        }
        $null = $sb.AppendLine('</tbody></table></div></div></details>')
    }
    $null = $sb.AppendLine('</div></section>')

    if (@($Model.SupportingGuides).Count -gt 0) {
        $null = $sb.AppendLine('<section class="section"><div class="section-heading"><h2>Supporting Microsoft Learn reference</h2><p>Separate from the primary SMB guide</p></div>')
        foreach ($supporting in $Model.SupportingGuides) {
            $null = $sb.AppendLine(('<details class="tier"><summary>{0}, revision {1}</summary><div class="tier-body"><p><strong>Guide ID:</strong> <code>{2}</code>. <strong>Classification:</strong> {3}. <strong>Verified:</strong> {4}.</p><p><a href="{5}">Open the pinned source</a>. Source commit: <code>{6}</code>. Comparison describes toolkit coverage, not tenant state.</p><div class="table-wrap"><table><thead><tr><th>Control</th><th>Recommendation</th><th>Comparison</th><th>Plan intent</th></tr></thead><tbody>' -f `
                (Encode $supporting.Guide.Title), (Encode $supporting.Guide.RevisionDate), `
                (Encode $supporting.Guide.Id), (Encode $supporting.Guide.SourceClassification), `
                (Encode $supporting.Guide.VerifiedDate), (Encode $supporting.Guide.SourceUri), `
                (Encode $supporting.Guide.SourceCommit)))
            foreach ($control in $supporting.GuideControls) {
                $null = $sb.AppendLine(('<tr><td><code>{0}</code><div class="small">{1}</div></td><td>{2}</td><td><span class="tag {3}">{4}</span></td><td><span class="tag {5}">{6}</span></td></tr>' -f `
                    (Encode $control.ControlId), (Encode $control.Section), (Encode $control.Summary), `
                    (Encode $control.ComparisonStatus), (Encode (Get-PurviewPlanStatusLabel $control.ComparisonStatus)), `
                    (Encode $control.Intent), (Encode (Get-PurviewPlanStatusLabel $control.Intent))))
            }
            $null = $sb.AppendLine('</tbody></table></div></div></details>')
        }
        $null = $sb.AppendLine('</section>')
    }

    $null = $sb.AppendLine('<section class="section"><div class="section-heading"><h2>Intended-state snapshot</h2><p>Sanitized comparison input for tenant validation</p></div>')
    $null = $sb.AppendLine(('<p class="muted">This deterministic snapshot records the selected policy settings without tenant identity, resolved label GUIDs, mailbox UPNs, or local paths. SHA-256: <code>{0}</code>. The formatted block below is for reading; the fingerprint is computed over canonical compact JSON in the sidecar.</p>' -f (Encode $Model.IntendedStateSha256)))
    $null = $sb.AppendLine('<details class="tier"><summary>Show normalized intended state</summary><div class="tier-body">')
    $null = $sb.AppendLine(('<pre class="snapshot">{0}</pre>' -f (Encode $intendedStateJson)))
    $null = $sb.AppendLine('</div></details></section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-heading"><h2>Validation handoff</h2><p>Reserved for the later read-only validator</p></div><div class="handoff">')
    $null = $sb.AppendLine(('<p>Provide the matching JSON sidecar to the future validator with <code>-PlanPath</code>. It will read plan reference <code>{0}</code>, Plan ID <code>{1}</code>, plan-input fingerprint <code>{2}</code>, and intended-state fingerprint <code>{3}</code> from the artifact.</p>' -f `
        (Encode $Model.PlanReference), (Encode $Model.PlanId), `
        (Encode $Model.PlanInputSha256), (Encode $Model.IntendedStateSha256)))
    $null = $sb.AppendLine('<p>This plan is not bound to a tenant. The validator must confirm tenant identity after authentication.</p></div></section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-heading"><h2>Technical appendix</h2><p>Identity, fingerprints, switches, and diagnostics</p></div><dl class="meta">')
    foreach ($item in @(
        @('Artifact type', $Model.ArtifactType),
        @('Schema version', $Model.SchemaVersion),
        @('Toolkit version', $Model.ToolkitVersion),
        @('Managed-object tag', $Model.ManagedByTag),
        @('Plan ID', $Model.PlanId),
        @('Plan reference', $Model.PlanReference),
        @('Configuration source', $Model.Configuration.Identity),
        @('Configuration SHA-256', $Model.Configuration.Sha256),
        @('Plan input SHA-256', $Model.PlanInputSha256),
        @('Intended state SHA-256', $Model.IntendedStateSha256),
        @('Minimum validator schema', $Model.Handoff.MinimumValidatorSchema),
        @('Handoff capabilities', (@($Model.Handoff.Capabilities) -join ', ')),
        @('Primary guide ID', $Model.Guide.Id),
        @('Primary guide edition', $Model.Guide.Edition),
        @('Primary guide revision', $Model.Guide.RevisionDate),
        @('Primary guide publisher', $Model.Guide.Publisher),
        @('Primary guide source classification', $Model.Guide.SourceClassification),
        @('Primary guide source file', $Model.Guide.SourceFileName),
        @('Primary guide mapping owner', $Model.Guide.Owner),
        @('Primary guide source modified', $Model.Guide.SourceModifiedDate),
        @('Primary guide verified', $Model.Guide.VerifiedDate)
    )) {
        $null = $sb.AppendLine(('<dt>{0}</dt><dd><code>{1}</code></dd>' -f (Encode $item[0]), (Encode $item[1])))
    }
    $null = $sb.AppendLine('</dl><h3>Effective switches</h3><div class="table-wrap"><table><thead><tr><th>Switch</th><th>Selected</th></tr></thead><tbody>')
    foreach ($property in $Model.EffectiveParameters.PSObject.Properties) {
        $null = $sb.AppendLine(('<tr><td><code>-{0}</code></td><td>{1}</td></tr>' -f (Encode $property.Name), (Encode ([string]$property.Value).ToLowerInvariant())))
    }
    $null = $sb.AppendLine('</tbody></table></div><h3>Generation diagnostics</h3>')
    if (@($Model.Diagnostics).Count -eq 0) {
        $null = $sb.AppendLine('<p class="muted">No generation diagnostics.</p>')
    } else {
        $null = $sb.AppendLine('<ul>')
        foreach ($diagnostic in $Model.Diagnostics) {
            $null = $sb.AppendLine(('<li>{0}</li>' -f (Encode $diagnostic)))
        }
        $null = $sb.AppendLine('</ul>')
    }
    $null = $sb.AppendLine('</section>')
    $null = $sb.AppendLine(('<footer>Generated from local configuration only. Plan input SHA-256: <code>{0}</code></footer>' -f (Encode $Model.PlanInputSha256)))
    $null = $sb.AppendLine(@'
<script>
  document.querySelectorAll("[data-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      const filter = button.dataset.filter;
      document.querySelectorAll("[data-filter]").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      document.querySelectorAll("#action-rows tr").forEach((row) => {
        row.hidden = filter !== "All" && row.dataset.intent !== filter;
      });
    });
  });
</script>
'@)
    $null = $sb.AppendLine('</main></body></html>')
    return $sb.ToString()
}

function Write-PurviewDeploymentPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject] $Model,

        [Parameter(Mandatory)]
        [string] $OutputPath
    )

    $extension = [IO.Path]::GetExtension($OutputPath)
    if ($extension -notin @('.html', '.htm')) {
        throw [NotSupportedException]::new(
            "Deployment Plan output path must use an .html or .htm extension: $OutputPath"
        )
    }
    $jsonPath = [IO.Path]::ChangeExtension($OutputPath, '.json')
    $resolvedHtmlPath = [IO.Path]::GetFullPath($OutputPath)
    $resolvedJsonPath = [IO.Path]::GetFullPath($jsonPath)
    if ($resolvedHtmlPath.Equals($resolvedJsonPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Deployment Plan HTML and JSON output paths must be different.'
    }

    $directory = Split-Path -Parent $OutputPath
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force -WhatIf:$false | Out-Null
    }

    $html = ConvertTo-PurviewDeploymentPlanHtml -Model $Model
    $json = $Model | ConvertTo-Json -Depth 20

    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8 -NoNewline -WhatIf:$false
    Set-Content -LiteralPath $jsonPath -Value $json -Encoding UTF8 -NoNewline -WhatIf:$false

    return [pscustomobject]@{
        HtmlPath = $OutputPath
        JsonPath = $jsonPath
        PlanId = $Model.PlanId
        PlanReference = $Model.PlanReference
        ConfigurationSha256 = $Model.Configuration.Sha256
        PlanInputSha256 = $Model.PlanInputSha256
        IntendedStateSha256 = $Model.IntendedStateSha256
    }
}
