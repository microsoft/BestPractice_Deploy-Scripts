#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [switch] $AdoptExisting,
    [switch] $IncludeHighRisk,
    [switch] $EnableMailFlowImpactingChanges,
    [switch] $RollbackAcknowledged
)

. (Join-Path $PSScriptRoot 'DefenderRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'DefenderStateManagement.ps1')
. (Join-Path $PSScriptRoot 'Assert-DefenderExchangeParameterRbac.ps1')
. (Join-Path $PSScriptRoot 'Connect-DefenderServices.ps1') `
    -TenantAdminUpn ([string]$Context.TenantAdminUpn) | Out-Null

$moduleName = 'Setup-MdoEopBaseline'
$safeAttachmentsOperationKey = 'mdo-safe-attachments-apply'
$operationKey = 'mdo-auto-forward-apply'
$quarantineOperationKey = 'mdo-quarantine-policy-apply'
$safeAttachmentsBestPracticeKey = [string]@($Config.BestPracticeItems | Where-Object {
    $_.PermissionOperations -contains 'mdo-safe-attachments-read'
})[0].Key
$autoForwardBestPracticeKey = [string]@($Config.BestPracticeItems | Where-Object {
    $_.PermissionOperations -contains 'mdo-auto-forward-read'
})[0].Key
$quarantineBestPracticeKey = [string]@($Config.BestPracticeItems | Where-Object {
    $_.PermissionOperations -contains 'mdo-quarantine-policy-read'
})[0].Key
$desiredMode = 'Off'
$quarantinePolicyConfig = $Config.DefenderForOffice365.QuarantinePolicy

function Get-DefenderQuarantinePolicyExact {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Identity)

    if ([string]::IsNullOrWhiteSpace($Identity)) {
        throw 'The quarantine policy identity must not be empty.'
    }
    $candidates = @(Get-QuarantinePolicy -ErrorAction Stop |
        Where-Object { [string]$_.Name -ieq $Identity })
    if ($candidates.Count -gt 1) {
        throw "Multiple quarantine policies matched name '$Identity'."
    }
    $exactMatches = @($candidates |
        Where-Object { [string]$_.Name -ceq $Identity })
    if ($candidates.Count -eq 1 -and $exactMatches.Count -eq 0) {
        throw "Quarantine policy '$([string]$candidates[0].Name)' already exists and differs from the configured name '$Identity' only by capitalization. Exchange Online treats these as the same policy, so a create would be rejected. Align the configured name with the existing policy name before continuing."
    }
    return @($exactMatches)[0]
}

function Assert-DefenderExchangeCommandParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Command,
        [Parameter(Mandatory)] [string[]] $Parameters
    )

    $commandInfo = Get-Command -Name $Command -ErrorAction Stop
    foreach ($parameter in $Parameters) {
        if (-not $commandInfo.Parameters.ContainsKey($parameter)) {
            throw "The connected Exchange command '$Command' does not expose required parameter '-$parameter'."
        }
    }
}

Connect-DefenderExchangeOnline -TenantAdminUpn ([string]$Context.TenantAdminUpn) `
    -DelegatedOrganization ([string]$Context.DelegatedOrganization) `
    -NonInteractive:([bool]$Context.NonInteractive) `
    -UseDeviceAuthentication:([bool]$Context.UseDeviceAuthentication) | Out-Null

$quarantineError = $null
if ($null -eq $quarantinePolicyConfig) {
    Add-DefenderRunLogEntry -Module $moduleName -Action $quarantineOperationKey `
        -BestPracticeKey $quarantineBestPracticeKey `
        -Status 'Skipped' -Disposition 'Skipped' `
        -Detail 'The supplied Defender configuration does not define DefenderForOffice365.QuarantinePolicy, so the quarantine policy baseline was skipped and the remaining Defender for Office 365 assessments continued.'
}
else {
    $quarantineLogBaseline = if ($null -eq $global:DefenderRunLog) { 0 } else { @($global:DefenderRunLog).Count }
    try {
        $quarantinePolicyName = [string]$quarantinePolicyConfig.Name
        $builtInQuarantinePolicies = @(
            'AdminOnlyAccessPolicy'
            'DefaultFullAccessPolicy'
            'DefaultFullAccessWithNotificationPolicy'
        )
        if ([string]::IsNullOrWhiteSpace($quarantinePolicyName)) {
            throw 'Defender configuration must define a quarantine policy name.'
        }
        if ($quarantinePolicyName -in $builtInQuarantinePolicies) {
            throw "The configured quarantine policy '$quarantinePolicyName' is built in and cannot be managed."
        }
        if (@($quarantinePolicyConfig.ProtectionPolicyAssignments).Count -ne 0) {
            throw 'The quarantine baseline does not support protection-policy assignment; ProtectionPolicyAssignments must remain empty.'
        }

        $currentQuarantinePolicy = Invoke-WithTransientRetry `
            -Description "Read quarantine policy '$quarantinePolicyName'" `
            -Action { Get-DefenderQuarantinePolicyExact -Identity $quarantinePolicyName }
        if ($null -ne $currentQuarantinePolicy) {
            foreach ($propertyName in @(
                    'EndUserQuarantinePermissionsValue'
                    'ESNEnabled'
                    'IncludeMessagesFromBlockedSenderAddress')) {
                if ($null -eq $currentQuarantinePolicy.PSObject.Properties[$propertyName] -or
                    $null -eq $currentQuarantinePolicy.$propertyName) {
                    throw "Quarantine policy '$quarantinePolicyName' did not return required property '$propertyName'."
                }
            }
        }

        $quarantineDefinition = $Config.StateManagement.ObjectDefinitions.QuarantinePolicy
        $quarantineTagProperty = [string]$quarantineDefinition.ManagedTagProperty
        if ($AdoptExisting -and $null -ne $currentQuarantinePolicy -and
            [string]$currentQuarantinePolicy.$quarantineTagProperty -cne [string]$Config.ManagedByTag) {
            throw "Adoption of the existing quarantine policy '$quarantinePolicyName' is not supported. The toolkit cannot read which anti-spam, anti-phishing, anti-malware, or Safe Attachments policies already reference this policy, so changing its end-user permissions could alter live recipient behaviour. Rename or remove the existing policy, or configure a different quarantine policy name, then re-run without -AdoptExisting."
        }

        $quarantineDesired = @{
            Name = $quarantinePolicyName
            EndUserQuarantinePermissionsValue = [int]$quarantinePolicyConfig.EndUserQuarantinePermissionsValue
            ESNEnabled = [bool]$quarantinePolicyConfig.ESNEnabled
            IncludeMessagesFromBlockedSenderAddress = [bool]$quarantinePolicyConfig.IncludeMessagesFromBlockedSenderAddress
        }
        $quarantineItem = [pscustomobject]@{
            Current = $currentQuarantinePolicy
            Desired = $quarantineDesired
        }
        try {
            $quarantinePlan = Resolve-DefenderStatePlan -Current $currentQuarantinePolicy `
                -Desired $quarantineDesired -Definition $quarantineDefinition `
                -Config $Config -AdoptExisting:$AdoptExisting
        }
        catch {
            Add-DefenderRunLogEntry -Module $moduleName -Action $quarantineOperationKey `
                -BestPracticeKey $quarantinePolicyConfig.Key `
                -Status 'Failed' -Disposition 'Blocked' -Detail $_.Exception.Message
            throw
        }

        if ($quarantinePlan.Action -eq 'Update') {
            throw "Quarantine policy '$quarantinePolicyName' differs from the selected state, but updates to existing quarantine policies are not supported. The toolkit cannot verify which protection policies reference it. Restore the selected values manually or use a different policy name."
        }

        if ($quarantinePlan.Action -eq 'NoOp') {
            Add-DefenderRunLogEntry -Module $moduleName -Action $quarantineOperationKey `
                -BestPracticeKey $quarantinePolicyConfig.Key `
                -Status 'Succeeded' -Disposition 'AlreadyCompliant' `
                -Detail "Quarantine policy '$quarantinePolicyName' already matches the selected configuration; no protection-policy assignments were changed."
        }
        else {
            $quarantineWriteOperation = @($Config.PermissionModel.Operations | Where-Object {
                $_.Key -eq $quarantineOperationKey
            })[0]
            $quarantineWriteVerified = $quarantineWriteOperation.Phase -eq 'WriteApply' -and
                $quarantineWriteOperation.VerificationStatus -eq 'Verified'
            if (-not $quarantineWriteVerified) {
                Add-DefenderRunLogEntry -Module $moduleName -Action $quarantineOperationKey `
                    -BestPracticeKey $quarantinePolicyConfig.Key `
                    -Status 'Skipped' -Disposition 'GuidedOnly' `
                    -Detail "Quarantine policy '$quarantinePolicyName' requires action '$($quarantinePlan.Action)' to apply limited access, notifications enabled, blocked-sender messages excluded, and no protection-policy assignments; the write remains guided-only pending evidence-based approval."
            }
            else {
                $selectedQuarantineWriteOperation = @($Context.PermissionPlan.Operations |
                    Where-Object { $_.Key -eq $quarantineOperationKey })[0]
                if ($null -eq $selectedQuarantineWriteOperation) {
                    throw "The selected permission plan does not authorize '$quarantineOperationKey'. Add the apply operation to the quarantine best-practice item before enabling this write."
                }
                if ($selectedQuarantineWriteOperation.Phase -ne 'WriteApply' -or
                    $selectedQuarantineWriteOperation.VerificationStatus -ne 'Verified') {
                    throw "The selected permission plan does not contain a verified WriteApply operation for '$quarantineOperationKey'."
                }
                $quarantineResults = @(Invoke-DefenderManagedWrite `
                    -Items @($quarantineItem) -Definition $quarantineDefinition `
                    -Config $Config -ModuleName $moduleName `
                    -RollbackGuidance 'The created policy remains unassigned. Leave it in place pending an explicit removal decision.' `
                    -AdoptExisting:$AdoptExisting -Confirm:$false -WhatIf:$WhatIfPreference `
                    -WriteAction {
                        param($Plan)
                        if ($Plan.Action -ne 'Create') {
                            throw "Quarantine policy action '$($Plan.Action)' is not supported; this path is create-only."
                        }
                        $command = 'New-QuarantinePolicy'
                        $parameters = @(
                            'Name'
                            'AdminDisplayName'
                            'EndUserQuarantinePermissionsValue'
                            'ESNEnabled'
                            'IncludeMessagesFromBlockedSenderAddress'
                        )
                        Assert-DefenderExchangeCommandParameters -Command $command `
                            -Parameters $parameters
                        $roleAssignments = @(Get-ManagementRoleAssignment `
                            -RoleAssignee ([string]$Context.TenantAdminUpn) `
                            -Delegating:$false -ErrorAction Stop)
                        foreach ($parameter in $parameters) {
                            Assert-DefenderExchangeParameterRbac `
                                -RoleAssignee ([string]$Context.TenantAdminUpn) `
                                -Command $command -Parameter $parameter `
                                -RoleAssignments $roleAssignments | Out-Null
                        }
                        $writeParameters = @{
                            EndUserQuarantinePermissionsValue = [int]$Plan.State.EndUserQuarantinePermissionsValue
                            ESNEnabled = [bool]$Plan.State.ESNEnabled
                            IncludeMessagesFromBlockedSenderAddress = [bool]$Plan.State.IncludeMessagesFromBlockedSenderAddress
                            ErrorAction = 'Stop'
                            Name = [string]$Plan.State.Name
                            AdminDisplayName = [string]$Plan.State.AdminDisplayName
                        }
                        New-QuarantinePolicy @writeParameters | Out-Null
                    } `
                    -ReadbackAction {
                        param($Plan)
                        Get-DefenderQuarantinePolicyExact -Identity ([string]$Plan.State.Name)
                    })
                foreach ($quarantineResult in $quarantineResults) {
                    $quarantineStatus = if ($quarantineResult.WriteOutcome -eq 'Skipped') {
                        'Skipped'
                    }
                    else {
                        $quarantineResult.Recovery.RunLogStatus
                    }
                    $quarantineDisposition = if ($quarantineResult.WriteOutcome -eq 'Skipped') {
                        'Skipped'
                    }
                    else {
                        $quarantineResult.Recovery.Disposition
                    }
                    $quarantineDetail = $quarantineResult.Detail
                    if ($quarantineResult.Recovery.ContinuationCommand) {
                        $quarantineDetail = "$quarantineDetail $($quarantineResult.Recovery.ContinuationCommand)"
                    }
                    Add-DefenderRunLogEntry -Module $moduleName -Action $quarantineOperationKey `
                        -BestPracticeKey $quarantinePolicyConfig.Key `
                        -Status $quarantineStatus -Disposition $quarantineDisposition `
                        -Readback $quarantineResult.Readback -Detail $quarantineDetail
                }
                $quarantineFailures = @($quarantineResults | Where-Object {
                    $_.WriteOutcome -eq 'Failed' -or
                    $_.Readback -eq 'Failed' -or
                    $_.Recovery.Disposition -eq 'Blocked'
                })
                if ($quarantineFailures.Count -gt 0) {
                    throw 'Quarantine policy managed write failed or could not be confirmed by readback.'
                }
            }
        }
    }
    catch {
        $quarantineError = $_
        $loggedFailures = @($global:DefenderRunLog |
            Select-Object -Skip $quarantineLogBaseline |
            Where-Object { $_.Action -eq $quarantineOperationKey -and $_.Status -eq 'Failed' })
        if ($loggedFailures.Count -eq 0) {
            Add-DefenderRunLogEntry -Module $moduleName -Action $quarantineOperationKey `
                -BestPracticeKey $quarantinePolicyConfig.Key `
                -Status 'Failed' -Disposition 'Blocked' -Detail $_.Exception.Message
        }
    }
}

$safeAttachmentsPolicy = Invoke-WithTransientRetry `
    -Description 'Read the default ATP policy' `
    -Action { Get-AtpPolicyForO365 -Identity 'Default' -ErrorAction Stop }
$safeAttachmentsEnabled = $safeAttachmentsPolicy.EnableATPForSPOTeamsODB
if ($null -eq $safeAttachmentsEnabled) {
    throw 'The default ATP policy did not return EnableATPForSPOTeamsODB.'
}

if ([bool]$safeAttachmentsEnabled) {
    Add-DefenderRunLogEntry -Module $moduleName `
        -Action $safeAttachmentsOperationKey -Status 'Succeeded' `
        -BestPracticeKey $safeAttachmentsBestPracticeKey `
        -Disposition 'AlreadyCompliant' `
        -Detail 'Safe Attachments is already enabled for SharePoint, OneDrive, and Teams.'
}
else {
    $safeAttachmentsWriteOperation = @($Config.PermissionModel.Operations | Where-Object {
        $_.Key -eq $safeAttachmentsOperationKey
    })[0]
    $safeAttachmentsWriteVerified = $safeAttachmentsWriteOperation.Phase -eq 'WriteApply' -and
        $safeAttachmentsWriteOperation.VerificationStatus -eq 'Verified'
    if ($safeAttachmentsWriteVerified) {
        if ($PSCmdlet.ShouldProcess(
                'Default ATP policy',
                'Enable Safe Attachments for SharePoint, OneDrive, and Teams')) {
            Assert-DefenderExchangeParameterRbac `
                -RoleAssignee ([string]$Context.TenantAdminUpn) `
                -Command 'Set-AtpPolicyForO365' `
                -Parameter 'EnableATPForSPOTeamsODB' | Out-Null
            $safeAttachmentsDefinition = @{
                IdentifierProperties = @('Identity')
                ManagedProperties = @('EnableATPForSPOTeamsODB')
            }
            $safeAttachmentsItems = @([pscustomobject]@{
                Current = @{
                    Identity = 'Default'
                    EnableATPForSPOTeamsODB = [bool]$safeAttachmentsEnabled
                }
                Desired = @{
                    Identity = 'Default'
                    EnableATPForSPOTeamsODB = $true
                }
            })
            $safeAttachmentsResults = @(Invoke-DefenderManagedWrite `
                -Items $safeAttachmentsItems -Definition $safeAttachmentsDefinition `
                -Config $Config -BuiltInObject -ModuleName $moduleName `
                -RollbackGuidance "allow up to 30 minutes for propagation, then restore EnableATPForSPOTeamsODB to the captured prior value '$safeAttachmentsEnabled' if recovery is required." `
                -Confirm:$false -WhatIf:$WhatIfPreference `
                -WriteAction {
                    param($Plan)
                    Set-AtpPolicyForO365 -Identity 'Default' `
                        -EnableATPForSPOTeamsODB $Plan.State.EnableATPForSPOTeamsODB `
                        -ErrorAction Stop
                } `
                -ReadbackAction {
                    Get-AtpPolicyForO365 -Identity 'Default' -ErrorAction Stop |
                        Select-Object Identity, EnableATPForSPOTeamsODB
                })
            foreach ($safeAttachmentsResult in $safeAttachmentsResults) {
                $safeAttachmentsDetail = $safeAttachmentsResult.Detail
                if ($safeAttachmentsResult.Recovery.ContinuationCommand) {
                    $safeAttachmentsDetail = "$safeAttachmentsDetail $($safeAttachmentsResult.Recovery.ContinuationCommand)"
                }
                Add-DefenderRunLogEntry -Module $moduleName `
                    -Action $safeAttachmentsOperationKey `
                    -BestPracticeKey $safeAttachmentsBestPracticeKey `
                    -Status $safeAttachmentsResult.Recovery.RunLogStatus `
                    -Disposition $safeAttachmentsResult.Recovery.Disposition `
                    -Readback $safeAttachmentsResult.Readback `
                    -Detail $safeAttachmentsDetail
            }
            $safeAttachmentsFailures = @($safeAttachmentsResults | Where-Object {
                $_.WriteOutcome -eq 'Failed' -or
                $_.Readback -eq 'Failed' -or
                $_.Recovery.Disposition -eq 'Blocked'
            })
            if ($safeAttachmentsFailures.Count -gt 0) {
                throw 'Safe Attachments managed write failed or could not be confirmed by readback.'
            }
        }
        else {
            Add-DefenderRunLogEntry -Module $moduleName `
                -Action $safeAttachmentsOperationKey -Status 'Skipped' `
                -BestPracticeKey $safeAttachmentsBestPracticeKey `
                -Disposition 'Skipped' `
                -Detail 'Safe Attachments for SharePoint, OneDrive, and Teams would be enabled.'
        }
    }
    else {
        Add-DefenderRunLogEntry -Module $moduleName `
            -Action $safeAttachmentsOperationKey -Status 'Skipped' `
            -BestPracticeKey $safeAttachmentsBestPracticeKey `
            -Disposition 'GuidedOnly' `
            -Detail 'Safe Attachments for SharePoint, OneDrive, and Teams would be enabled; the production operation remains guided-only pending separate approved pilot evidence.'
    }
}

$currentPolicy = Invoke-WithTransientRetry `
    -Description 'Read the default outbound spam-filter policy' `
    -Action { Get-HostedOutboundSpamFilterPolicy -Identity 'Default' -ErrorAction Stop }
$priorMode = [string]$currentPolicy.AutoForwardingMode
if ([string]::IsNullOrWhiteSpace($priorMode)) {
    throw 'The default outbound spam-filter policy did not return AutoForwardingMode.'
}

if ($priorMode -eq $desiredMode) {
    Add-DefenderRunLogEntry -Module $moduleName -Action $operationKey `
        -BestPracticeKey $autoForwardBestPracticeKey `
        -Status 'Succeeded' -Disposition 'AlreadyCompliant' `
        -Detail 'Default outbound auto-forwarding is already Off.'
    [pscustomobject]@{
        OperationKey = $operationKey
        Identity = 'Default'
        PriorMode = $priorMode
        DesiredMode = $desiredMode
        Disposition = 'AlreadyCompliant'
        WriteAttempted = $false
    }
}
else {
    $safetyGatesReady = $IncludeHighRisk -and
        $EnableMailFlowImpactingChanges -and $RollbackAcknowledged
    $writeOperation = @($Config.PermissionModel.Operations | Where-Object {
        $_.Key -eq $operationKey
    })[0]
    $writeVerified = $writeOperation.Phase -eq 'WriteApply' -and
        $writeOperation.VerificationStatus -eq 'Verified'
    if ($safetyGatesReady -and $writeVerified) {
        if (-not $PSCmdlet.ShouldProcess(
                'Default outbound spam-filter policy',
                "Set AutoForwardingMode from '$priorMode' to '$desiredMode'")) {
            Add-DefenderRunLogEntry -Module $moduleName -Action $operationKey `
                -BestPracticeKey $autoForwardBestPracticeKey `
                -Status 'Skipped' -Disposition 'Skipped' `
                -Detail "Default outbound auto-forwarding would change from '$priorMode' to '$desiredMode'."
            [pscustomobject]@{
                OperationKey = $operationKey
                Identity = 'Default'
                PriorMode = $priorMode
                DesiredMode = $desiredMode
                Disposition = 'Skipped'
                WriteAttempted = $false
            }
        }
        else {
            Assert-DefenderExchangeParameterRbac `
                -RoleAssignee ([string]$Context.TenantAdminUpn) `
                -Command 'Set-HostedOutboundSpamFilterPolicy' `
                -Parameter 'AutoForwardingMode' | Out-Null
            $definition = @{
                IdentifierProperties = @('Identity')
                ManagedProperties = @('AutoForwardingMode')
            }
            $items = @([pscustomobject]@{
                Current = @{
                    Identity = 'Default'
                    AutoForwardingMode = $priorMode
                }
                Desired = @{
                    Identity = 'Default'
                    AutoForwardingMode = $desiredMode
                }
            })
            $results = Invoke-DefenderManagedWrite -Items $items `
                -Definition $definition -Config $Config -BuiltInObject `
                -ModuleName $moduleName `
                -RollbackGuidance "restore AutoForwardingMode to the captured prior value '$priorMode'." `
                -Confirm:$false -WhatIf:$WhatIfPreference `
                -WriteAction {
                    param($Plan)
                    Set-HostedOutboundSpamFilterPolicy -Identity 'Default' `
                        -AutoForwardingMode $Plan.State.AutoForwardingMode `
                        -ErrorAction Stop
                } `
                -ReadbackAction {
                    Get-HostedOutboundSpamFilterPolicy -Identity 'Default' `
                        -ErrorAction Stop |
                        Select-Object Identity, AutoForwardingMode
                }
            foreach ($result in $results) {
                $status = if ($result.WriteOutcome -eq 'Skipped') {
                    'Skipped'
                }
                else {
                    $result.Recovery.RunLogStatus
                }
                $disposition = if ($result.WriteOutcome -eq 'Skipped') {
                    'Skipped'
                }
                else {
                    $result.Recovery.Disposition
                }
                Add-DefenderRunLogEntry -Module $moduleName -Action $operationKey `
                    -BestPracticeKey $autoForwardBestPracticeKey `
                    -Status $status -Disposition $disposition `
                    -Readback $result.Readback -Detail $result.Detail
            }
            $failures = @($results | Where-Object {
                $_.WriteOutcome -eq 'Failed' -or
                $_.Readback -eq 'Failed' -or
                $_.Recovery.Disposition -eq 'Blocked'
            })
            if ($failures.Count -gt 0) {
                throw 'Outbound auto-forwarding managed write failed or could not be confirmed by readback.'
            }
            $results
        }
    }
    else {
        $disposition = if ($safetyGatesReady) { 'GuidedOnly' } else { 'Blocked' }
        $detail = if ($safetyGatesReady) {
            "Default outbound auto-forwarding would change from '$priorMode' to 'Off'; production changes remain guided-only and require an approved deployment process."
        }
        else {
            "Default outbound auto-forwarding would change from '$priorMode' to 'Off'; IncludeHighRisk, EnableMailFlowImpactingChanges, and RollbackAcknowledged are required before the guided write can be considered."
        }
        Add-DefenderRunLogEntry -Module $moduleName -Action $operationKey `
            -BestPracticeKey $autoForwardBestPracticeKey `
            -Status 'Skipped' -Disposition $disposition -Detail $detail
        [pscustomobject]@{
            OperationKey = $operationKey
            Identity = 'Default'
            PriorMode = $priorMode
            DesiredMode = $desiredMode
            Disposition = $disposition
            WriteAttempted = $false
        }
    }
}

if ($null -ne $quarantineError) {
    throw $quarantineError
}
