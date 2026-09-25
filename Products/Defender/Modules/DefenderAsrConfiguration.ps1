#requires -Version 7.0

function Test-DefenderAsrToken {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Value,
        [Parameter(Mandatory)] [string] $Expected
    )

    $tokens = if ($Value -is [System.Collections.IEnumerable] -and
        $Value -isnot [string]) {
        @($Value)
    }
    else {
        @(([string] $Value) -split ',')
    }
    return @($tokens | ForEach-Object { ([string] $_).Trim() }) -contains $Expected
}

function New-DefenderAsrAuditPolicyBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $PolicyConfig,
        [Parameter(Mandatory)] [string] $ManagedByTag,
        [Parameter(Mandatory)] [object] $Template,
        [Parameter(Mandatory)] [object[]] $SettingTemplates,
        [Parameter(Mandatory)] [object[]] $ParentDefinitions,
        [Parameter(Mandatory)] [object[]] $ChildDefinitions,
        [Parameter(Mandatory)] [string[]] $ScopeTagIds
    )

    if ([string] $Template.templateFamily -ne $PolicyConfig.TemplateFamily -or
        [string] $Template.lifecycleState -ne 'active' -or
        [int] $Template.version -ne [int] $PolicyConfig.TemplateVersion -or
        -not (Test-DefenderAsrToken -Value $Template.platforms -Expected $PolicyConfig.Platform) -or
        @($PolicyConfig.Technologies | Where-Object {
            -not (Test-DefenderAsrToken -Value $Template.technologies -Expected $_)
        }).Count -gt 0) {
        throw 'The discovered ASR template does not match the configured active template contract.'
    }
    if (@($SettingTemplates).Count -ne 5 -or @($ParentDefinitions).Count -ne 5 -or
        @($ChildDefinitions).Count -ne 19) {
        throw 'The discovered ASR schema must contain five parent settings and 19 child rules.'
    }

    $ruleParents = @($ParentDefinitions | Where-Object { @($_.childIds).Count -eq 19 })
    if ($ruleParents.Count -ne 1) {
        throw "Expected one ASR rule-group parent, found $($ruleParents.Count)."
    }
    $ruleParent = $ruleParents[0]
    $ruleChildIds = @($ruleParent.childIds | ForEach-Object { [string] $_ })
    if (@($ruleChildIds | Sort-Object -Unique).Count -ne 19) {
        throw 'The ASR rule-group parent must reference 19 distinct child definitions.'
    }
    $parentTemplate = @($SettingTemplates | Where-Object {
        $_.settingInstanceTemplate.settingDefinitionId -eq $ruleParent.id
    })
    if ($parentTemplate.Count -ne 1 -or
        [string]::IsNullOrWhiteSpace([string] $parentTemplate[0].settingInstanceTemplate.settingInstanceTemplateId)) {
        throw 'The ASR rule-group parent does not have one setting-instance template.'
    }

    $childrenById = @{}
    foreach ($definition in $ChildDefinitions) {
        if ([string]::IsNullOrWhiteSpace([string] $definition.id) -or
            $childrenById.ContainsKey([string] $definition.id)) {
            throw 'The ASR child schema contains a missing or duplicate definition identifier.'
        }
        $childrenById[[string] $definition.id] = $definition
    }
    if (@($childrenById.Keys | Where-Object { $_ -notin $ruleChildIds }).Count -gt 0) {
        throw 'The discovered ASR child definitions do not exactly match the rule-group parent.'
    }

    $childInstances = foreach ($childId in @($ruleParent.childIds)) {
        $definition = $childrenById[[string] $childId]
        if ($null -eq $definition) {
            throw "ASR child definition '$childId' was not returned by discovery."
        }
        $auditOptions = @($definition.options | Where-Object {
            [string] $_.displayName -ceq $PolicyConfig.RuleMode
        })
        if ($auditOptions.Count -ne 1 -or
            [string]::IsNullOrWhiteSpace([string] $auditOptions[0].itemId)) {
            throw "ASR child definition '$childId' does not expose one exact Audit option."
        }
        [ordered]@{
            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = [string] $definition.id
            choiceSettingValue = [ordered]@{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value = [string] $auditOptions[0].itemId
                children = @()
            }
        }
    }

    $description = "$($PolicyConfig.Description) $ManagedByTag".Trim()
    return [ordered]@{
        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationPolicy'
        name = [string] $PolicyConfig.Name
        description = $description
        platforms = [string] $PolicyConfig.Platform
        technologies = (@($PolicyConfig.Technologies) -join ',')
        roleScopeTagIds = @($ScopeTagIds)
        settings = @(
            [ordered]@{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSetting'
                settingInstance = [ordered]@{
                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
                    settingDefinitionId = [string] $ruleParent.id
                    settingInstanceTemplateReference = [ordered]@{
                        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSettingInstanceTemplateReference'
                        settingInstanceTemplateId = [string] $parentTemplate[0].settingInstanceTemplate.settingInstanceTemplateId
                    }
                    groupSettingCollectionValue = @(
                        [ordered]@{
                            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationGroupSettingValue'
                            children = @($childInstances)
                        }
                    )
                }
            }
        )
        templateReference = [ordered]@{
            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationPolicyTemplateReference'
            templateId = [string] $Template.id
            templateFamily = [string] $Template.templateFamily
            templateDisplayName = [string] $Template.displayName
            templateDisplayVersion = [string] $Template.displayVersion
        }
    }
}

function New-DefenderAsrAssignmentBody {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [guid] $PilotGroupId)

    return [ordered]@{
        assignments = @(
            [ordered]@{
                target = [ordered]@{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId = $PilotGroupId.ToString()
                    deviceAndAppManagementAssignmentFilterId = $null
                    deviceAndAppManagementAssignmentFilterType = 'none'
                }
            }
        )
    }
}

function Assert-DefenderAsrPolicyReadback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Policy,
        [Parameter(Mandatory)] [object[]] $Settings,
        [Parameter(Mandatory)] [hashtable] $ExpectedBody,
        [Parameter(Mandatory)] [string] $ManagedByTag
    )

    $expectedTechnologies = @(([string] $ExpectedBody.technologies) -split ',' |
        ForEach-Object { $_.Trim() } | Sort-Object -Unique)
    $actualTechnologies = @(([string] $Policy.technologies) -split ',' |
        ForEach-Object { $_.Trim() } | Sort-Object -Unique)
    $expectedScopeTags = @($ExpectedBody.roleScopeTagIds | ForEach-Object { [string] $_ } |
        Sort-Object -Unique)
    $actualScopeTags = @($Policy.roleScopeTagIds | ForEach-Object { [string] $_ } |
        Sort-Object -Unique)
    if ([string]::IsNullOrWhiteSpace([string] $Policy.id) -or
        [string] $Policy.name -cne [string] $ExpectedBody.name -or
        -not ([string] $Policy.description).Contains(
            $ManagedByTag,
            [StringComparison]::Ordinal) -or
        [string] $Policy.platforms -ne [string] $ExpectedBody.platforms -or
        ($actualTechnologies -join ',') -ne ($expectedTechnologies -join ',') -or
        ($actualScopeTags -join ',') -ne ($expectedScopeTags -join ',') -or
        [string] $Policy.templateReference.templateId -ne [string] $ExpectedBody.templateReference.templateId -or
        [string] $Policy.templateReference.templateFamily -ne [string] $ExpectedBody.templateReference.templateFamily -or
        [string] $Policy.templateReference.templateDisplayVersion -ne [string] $ExpectedBody.templateReference.templateDisplayVersion) {
        throw 'ASR policy readback mismatch in managed identity, platform, technologies, scope tags, or template.'
    }

    if (@($Settings).Count -ne 1) {
        throw "ASR policy readback mismatch: expected one managed setting group, found $(@($Settings).Count)."
    }
    $expectedInstance = $ExpectedBody.settings[0].settingInstance
    $actualInstance = $Settings[0].settingInstance
    if ([string] $actualInstance.settingDefinitionId -ne [string] $expectedInstance.settingDefinitionId -or
        [string] $actualInstance.settingInstanceTemplateReference.settingInstanceTemplateId -ne
            [string] $expectedInstance.settingInstanceTemplateReference.settingInstanceTemplateId) {
        throw 'ASR policy readback mismatch in the managed setting-group identity.'
    }

    $expectedChildren = @($expectedInstance.groupSettingCollectionValue[0].children)
    $actualValues = @{}
    foreach ($child in @($actualInstance.groupSettingCollectionValue[0].children)) {
        $definitionId = [string] $child.settingDefinitionId
        if ([string]::IsNullOrWhiteSpace($definitionId) -or $actualValues.ContainsKey($definitionId)) {
            throw 'ASR policy readback contains a missing or duplicate child definition identifier.'
        }
        $actualValues[$definitionId] = [string] $child.choiceSettingValue.value
    }
    if ($actualValues.Count -ne 19 -or $expectedChildren.Count -ne 19) {
        throw 'ASR policy readback mismatch: expected exactly 19 managed child rules.'
    }
    foreach ($expectedChild in $expectedChildren) {
        $definitionId = [string] $expectedChild.settingDefinitionId
        if (-not $actualValues.ContainsKey($definitionId) -or
            $actualValues[$definitionId] -ne [string] $expectedChild.choiceSettingValue.value) {
            throw "ASR policy readback mismatch for child definition '$definitionId'."
        }
    }
    return $true
}

function Assert-DefenderAsrAssignmentReadback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Assignments,
        [Parameter(Mandatory)] [guid] $PilotGroupId
    )

    if (@($Assignments).Count -ne 1) {
        throw "ASR assignment readback mismatch: expected one target, found $(@($Assignments).Count)."
    }
    $target = $Assignments[0].target
    if ([string] $target.'@odata.type' -ne '#microsoft.graph.groupAssignmentTarget' -or
        [string] $target.groupId -ne $PilotGroupId.ToString() -or
        -not [string]::IsNullOrWhiteSpace([string] $target.deviceAndAppManagementAssignmentFilterId) -or
        [string] $target.deviceAndAppManagementAssignmentFilterType -ne 'none') {
        throw 'ASR assignment readback mismatch: expected the approved unfiltered direct-group target.'
    }
    return $true
}

function Get-DefenderAsrSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [scriptblock] $GraphRequest,
        [Parameter(Mandatory)] [hashtable] $PolicyConfig
    )

    $policies = @(Get-DefenderAsrGraphCollection -GraphRequest $GraphRequest `
        -InitialUri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies')
    $templates = @(Get-DefenderAsrGraphCollection -GraphRequest $GraphRequest `
        -InitialUri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicyTemplates')
    $templateMatches = @(foreach ($candidate in $templates) {
        $hasTechnologies = $true
        foreach ($technology in @($PolicyConfig.Technologies)) {
            if (-not (Test-DefenderAsrToken -Value $candidate.technologies -Expected $technology)) {
                $hasTechnologies = $false
                break
            }
        }
        if ([string] $candidate.templateFamily -eq $PolicyConfig.TemplateFamily -and
            [string] $candidate.lifecycleState -eq 'active' -and
            [int] $candidate.version -eq [int] $PolicyConfig.TemplateVersion -and
            [int] $candidate.settingTemplateCount -eq [int] $PolicyConfig.TemplateSettingCount -and
            (Test-DefenderAsrToken -Value $candidate.platforms -Expected $PolicyConfig.Platform) -and
            $hasTechnologies) {
            $candidate
        }
    })
    if ($templateMatches.Count -ne 1) {
        throw "Expected one active ASR template matching the configured contract, found $($templateMatches.Count)."
    }

    $configuredScopeTagIds = @($PolicyConfig.ScopeTagIds | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string] $_)
    })
    if ($configuredScopeTagIds.Count -ne 1) {
        throw "Expected the ASR policy config to declare one scope-tag identifier, found $($configuredScopeTagIds.Count)."
    }

    $template = $templateMatches[0]
    $templateId = [uri]::EscapeDataString([string] $template.id)
    $settingTemplates = @(Get-DefenderAsrGraphCollection -GraphRequest $GraphRequest `
        -InitialUri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicyTemplates/$templateId/settingTemplates")
    $parentDefinitions = foreach ($settingTemplate in $settingTemplates) {
        $definitionId = [string] $settingTemplate.settingInstanceTemplate.settingDefinitionId
        if ([string]::IsNullOrWhiteSpace($definitionId)) {
            throw 'An ASR setting template did not expose its linked definition identifier.'
        }
        & $GraphRequest -Method GET -Uri (
            'https://graph.microsoft.com/beta/deviceManagement/configurationSettings/{0}' -f
            [uri]::EscapeDataString($definitionId))
    }
    $childIds = foreach ($parentDefinition in @($parentDefinitions)) {
        if ($parentDefinition -is [System.Collections.IDictionary] -and
            $parentDefinition.Contains('childIds')) {
            @($parentDefinition['childIds'] | Where-Object { $_ })
        }
        else {
            $childIdsProperty = $parentDefinition.PSObject.Properties['childIds']
            if ($null -ne $childIdsProperty) {
                @($childIdsProperty.Value | Where-Object { $_ })
            }
        }
    }
    $childDefinitions = foreach ($childId in @($childIds)) {
        & $GraphRequest -Method GET -Uri (
            'https://graph.microsoft.com/beta/deviceManagement/configurationSettings/{0}' -f
            [uri]::EscapeDataString([string] $childId))
    }

    return [pscustomobject]@{
        Policies = @($policies)
        Template = $template
        SettingTemplates = @($settingTemplates)
        ParentDefinitions = @($parentDefinitions)
        ChildDefinitions = @($childDefinitions)
        ScopeTagIds = @([string] $configuredScopeTagIds[0])
    }
}

function Get-DefenderAsrGraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [scriptblock] $GraphRequest,
        [Parameter(Mandatory)] [string] $InitialUri,
        [ValidateRange(1, 1000)] [int] $MaximumPageCount = 100
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $visitedUris = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $nextUri = $InitialUri
    $pageCount = 0
    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        $parsedUri = $null
        if (-not [uri]::TryCreate($nextUri, [UriKind]::Absolute, [ref] $parsedUri) -or
            $parsedUri.Scheme -cne 'https' -or
            $parsedUri.Host -cne 'graph.microsoft.com' -or
            -not $parsedUri.IsDefaultPort -or
            -not [string]::IsNullOrEmpty($parsedUri.UserInfo) -or
            -not [string]::IsNullOrEmpty($parsedUri.Fragment)) {
            throw "Microsoft Graph returned an untrusted pagination link for '$InitialUri'."
        }
        $pageCount++
        if ($pageCount -gt $MaximumPageCount) {
            throw "Microsoft Graph pagination exceeded the $MaximumPageCount page limit for '$InitialUri'."
        }
        if (-not $visitedUris.Add($nextUri)) {
            throw "Microsoft Graph returned a repeated pagination link for '$InitialUri'."
        }
        $response = & $GraphRequest -Method GET -Uri $nextUri
        $value = if ($response -is [System.Collections.IDictionary]) {
            $response['value']
        }
        else {
            $response.PSObject.Properties['value'].Value
        }
        foreach ($item in @($value)) {
            if ($null -ne $item) { $results.Add($item) }
        }
        $nextUri = if ($response -is [System.Collections.IDictionary]) {
            [string] $response['@odata.nextLink']
        }
        else {
            [string] $response.PSObject.Properties['@odata.nextLink'].Value
        }
    }
    return @($results)
}