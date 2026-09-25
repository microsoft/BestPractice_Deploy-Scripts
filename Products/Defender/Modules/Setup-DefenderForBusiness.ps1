#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [string] $PilotGroupId,
    [string] $RecoveryPolicyId,
    [switch] $EnableAsrAuditPolicy,
    [switch] $RecoverAsrAuditPolicy,
    [switch] $RollbackAcknowledged,
    [switch] $EnableAsrBlockMode
)

. (Join-Path $PSScriptRoot 'DefenderRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'DefenderStateManagement.ps1')
. (Join-Path $PSScriptRoot 'DefenderAsrConfiguration.ps1')

$policyConfig = $Config.DefenderForBusiness.AsrAuditPolicy
function Stop-DefenderAsrOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Message,
        [string] $Action = 'mde-asr-audit-guard',
        [string] $Target,
        [switch] $ReadbackFailed
    )

    $entry = @{
        Module = 'Setup-DefenderForBusiness'
        Action = $Action
        BestPracticeKey = $policyConfig.Key
        FriendlyName = $policyConfig.Name
        Status = 'Failed'
        Disposition = 'Blocked'
        Target = $Target
        Detail = $Message
    }
    if ($ReadbackFailed) { $entry.Readback = 'Failed' }
    Add-DefenderRunLogEntry @entry
    throw $Message
}

function Assert-DefenderAsrWriteAuthorized {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $OperationKey)

    $selectedOperations = @($Context.PermissionPlan.Operations | Where-Object {
        $_.Key -eq $OperationKey
    })
    if ($selectedOperations.Count -ne 1) {
        Stop-DefenderAsrOperation `
            -Message "The selected permission plan does not authorize '$OperationKey'." `
            -Action $OperationKey
    }
    if ($selectedOperations[0].Phase -ne 'WriteApply' -or
        $selectedOperations[0].VerificationStatus -ne 'Verified') {
        Stop-DefenderAsrOperation `
            -Message "The selected permission plan does not contain a verified WriteApply operation for '$OperationKey'." `
            -Action $OperationKey
    }
}

if ($EnableAsrBlockMode) {
    Stop-DefenderAsrOperation `
        -Message 'The managed ASR policy supports Audit mode only; block mode is not implemented.'
}
if ($EnableAsrAuditPolicy -and $RecoverAsrAuditPolicy) {
    Stop-DefenderAsrOperation `
        -Message 'EnableAsrAuditPolicy and RecoverAsrAuditPolicy cannot be used together.'
}
if ($RecoverAsrAuditPolicy -and -not $RollbackAcknowledged) {
    Stop-DefenderAsrOperation `
        -Message 'RecoverAsrAuditPolicy requires RollbackAcknowledged.'
}
if ($EnableAsrAuditPolicy) {
    Assert-DefenderAsrWriteAuthorized -OperationKey 'mde-asr-audit-apply'
}
if ($RecoverAsrAuditPolicy) {
    Assert-DefenderAsrWriteAuthorized -OperationKey 'mde-asr-audit-recovery'
}

$serviceGraphRequest = $Context.ConnectionInfo.GraphRequest
if ($serviceGraphRequest -isnot [scriptblock]) {
    Stop-DefenderAsrOperation `
        -Message 'The Defender for Business readback requires an authenticated Graph request context.'
}
$retryingGraphRequest = {
    param($Method, $Uri, $Body)
    Invoke-WithTransientRetry -Description "Microsoft Graph $Method $Uri" -Action {
        & $serviceGraphRequest -Method $Method -Uri $Uri -Body $Body
    }
}

try {
    $schema = Get-DefenderAsrSchema -GraphRequest $retryingGraphRequest -PolicyConfig $policyConfig
}
catch {
    $httpStatus = Get-DefenderHttpStatusCode -ErrorRecord $_
    if ($httpStatus -in @(401, 403)) {
        Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
            -Action 'AsrAuditReadback' -BestPracticeKey $policyConfig.Key `
            -FriendlyName $policyConfig.Name -Status 'Skipped' `
            -Disposition 'GuidedOnly' -HttpStatusCode $httpStatus `
            -Detail 'Intune ASR configuration discovery is unavailable with the current license or authorization; no tenant change was attempted.'
        return
    }
    Stop-DefenderAsrOperation -Message $_.Exception.Message `
        -Action 'mde-asr-audit-discovery'
}
$expectedBody = New-DefenderAsrAuditPolicyBody -PolicyConfig $policyConfig `
    -ManagedByTag $Config.ManagedByTag -Template $schema.Template `
    -SettingTemplates $schema.SettingTemplates `
    -ParentDefinitions $schema.ParentDefinitions `
    -ChildDefinitions $schema.ChildDefinitions `
    -ScopeTagIds $schema.ScopeTagIds

$namedPolicies = @($schema.Policies | Where-Object { $_.name -ceq $policyConfig.Name })
if ($namedPolicies.Count -gt 1) {
    Stop-DefenderAsrOperation `
        -Message "Multiple Intune policies use the managed ASR policy name '$($policyConfig.Name)'."
}
$pilotGroupGuid = [guid]::Empty
if (($EnableAsrAuditPolicy -or $RecoverAsrAuditPolicy) -and
    ([string]::IsNullOrWhiteSpace($PilotGroupId) -or
        -not [guid]::TryParse($PilotGroupId, [ref] $pilotGroupGuid))) {
    Stop-DefenderAsrOperation `
        -Message 'ASR apply and recovery operations require PilotGroupId as a valid group GUID.'
}
if ($EnableAsrAuditPolicy -or $RecoverAsrAuditPolicy) {
    $encodedPilotGroupId = [uri]::EscapeDataString($pilotGroupGuid.ToString())
    $pilotGroup = & $retryingGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/groups/$encodedPilotGroupId`?`$select=id,displayName,securityEnabled"
    if ([string] $pilotGroup.id -ne $pilotGroupGuid.ToString() -or
        $pilotGroup.securityEnabled -ne $true) {
        Stop-DefenderAsrOperation `
            -Message 'PilotGroupId must resolve to the exact security-enabled Entra group.'
    }
}
if ($RecoverAsrAuditPolicy) {
    $recoveryPolicyGuid = [guid]::Empty
    if ([string]::IsNullOrWhiteSpace($RecoveryPolicyId) -or
        -not [guid]::TryParse($RecoveryPolicyId, [ref] $recoveryPolicyGuid)) {
        Stop-DefenderAsrOperation `
            -Message 'RecoverAsrAuditPolicy requires RecoveryPolicyId as the captured policy GUID.' `
            -Action 'mde-asr-audit-recovery'
    }
    if ($namedPolicies.Count -ne 1 -or
        [string] $namedPolicies[0].id -ne $recoveryPolicyGuid.ToString()) {
        Stop-DefenderAsrOperation `
            -Message 'The captured ASR recovery policy was not found under the exact managed policy name.' `
            -Action 'mde-asr-audit-recovery' -Target $RecoveryPolicyId
    }
    if (-not ([string] $namedPolicies[0].description).Contains(
            $Config.ManagedByTag,
            [StringComparison]::Ordinal)) {
        Stop-DefenderAsrOperation `
            -Message 'The captured ASR recovery policy does not contain the toolkit ownership marker.' `
            -Action 'mde-asr-audit-recovery' -Target $RecoveryPolicyId
    }

    $encodedRecoveryPolicyId = [uri]::EscapeDataString($recoveryPolicyGuid.ToString())
    try {
        $recoveryPolicy = & $retryingGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$encodedRecoveryPolicyId"
        $recoverySettings = & $retryingGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$encodedRecoveryPolicyId/settings"
        $null = Assert-DefenderAsrPolicyReadback -Policy $recoveryPolicy `
            -Settings @($recoverySettings.value) -ExpectedBody $expectedBody `
            -ManagedByTag $Config.ManagedByTag
        $recoveryAssignments = @(Get-DefenderAsrGraphCollection `
            -GraphRequest $retryingGraphRequest `
            -InitialUri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$encodedRecoveryPolicyId/assignments")
        $null = Assert-DefenderAsrAssignmentReadback `
            -Assignments $recoveryAssignments -PilotGroupId $pilotGroupGuid
    }
    catch {
        Stop-DefenderAsrOperation -Message $_.Exception.Message `
            -Action 'mde-asr-audit-recovery' -Target $recoveryPolicyGuid `
            -ReadbackFailed
    }

    if (-not $PSCmdlet.ShouldProcess(
            $policyConfig.Name,
            "Delete captured pilot-owned ASR policy '$recoveryPolicyGuid'")) {
        Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
            -Action 'mde-asr-audit-recovery' -BestPracticeKey $policyConfig.Key `
            -FriendlyName $policyConfig.Name -Status 'Skipped' `
            -Disposition 'Skipped' -Target $recoveryPolicyGuid `
            -Detail 'The captured pilot-owned ASR policy would be deleted after exact ownership and assignment-isolation readback.'
        return
    }

    $null = & $retryingGraphRequest -Method DELETE `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$encodedRecoveryPolicyId"
    $remainingPolicies = @(Get-DefenderAsrGraphCollection `
        -GraphRequest $retryingGraphRequest `
        -InitialUri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies')
    if (@($remainingPolicies | Where-Object {
                [string] $_.id -eq $recoveryPolicyGuid.ToString()
            }).Count -ne 0) {
        Stop-DefenderAsrOperation `
            -Message 'ASR recovery deletion readback still returned the captured policy identifier.' `
            -Action 'mde-asr-audit-recovery' -Target $recoveryPolicyGuid `
            -ReadbackFailed
    }
    Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
        -Action 'mde-asr-audit-recovery' -BestPracticeKey $policyConfig.Key `
        -FriendlyName $policyConfig.Name -Status 'Succeeded' `
        -Disposition 'WillChange' -Target $recoveryPolicyGuid `
        -Readback 'Succeeded' `
        -Detail 'Deleted the captured pilot-owned ASR policy and confirmed that its identifier is absent.'
    return
}
if ($namedPolicies.Count -eq 0) {
    if ($EnableAsrAuditPolicy) {
        if (-not $PSCmdlet.ShouldProcess(
                $policyConfig.Name,
                "Create the ASR Audit policy and assign it to pilot group '$pilotGroupGuid'")) {
            Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
                -Action 'mde-asr-audit-apply' -BestPracticeKey $policyConfig.Key `
                -FriendlyName $policyConfig.Name -Status 'Skipped' `
                -Disposition 'Skipped' `
                -Detail 'The ASR Audit policy and isolated pilot-group assignment would be created.'
            return
        }

        $policyId = $null
        try {
            $createdPolicy = & $retryingGraphRequest -Method POST `
                -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' `
                -Body $expectedBody
            $policyId = [string] $createdPolicy.id
            if ([string]::IsNullOrWhiteSpace($policyId)) {
                throw 'The ASR policy create response did not expose the created policy identifier.'
            }
            Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
                -Action 'mde-asr-audit-create' -BestPracticeKey $policyConfig.Key `
                -FriendlyName $policyConfig.Name -Status 'Created' `
                -Disposition 'WillChange' -Target $policyId `
                -Detail 'Created the managed ASR Audit policy; exact policy readback is required before assignment.'

            $encodedPolicyId = [uri]::EscapeDataString($policyId)
            $policyReadback = & $retryingGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$encodedPolicyId"
            $settingsReadback = & $retryingGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$encodedPolicyId/settings"
            $null = Assert-DefenderAsrPolicyReadback -Policy $policyReadback `
                -Settings @($settingsReadback.value) -ExpectedBody $expectedBody `
                -ManagedByTag $Config.ManagedByTag

            $assignmentBody = New-DefenderAsrAssignmentBody -PilotGroupId $pilotGroupGuid
            $null = & $retryingGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$encodedPolicyId/assign" `
                -Body $assignmentBody
            $assignmentsReadback = @(Get-DefenderAsrGraphCollection `
                -GraphRequest $retryingGraphRequest `
                -InitialUri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$encodedPolicyId/assignments")
            $null = Assert-DefenderAsrAssignmentReadback `
                -Assignments $assignmentsReadback -PilotGroupId $pilotGroupGuid
            Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
                -Action 'mde-asr-audit-apply' -BestPracticeKey $policyConfig.Key `
                -FriendlyName $policyConfig.Name -Status 'Succeeded' `
                -Disposition 'WillChange' -Target $policyId -Readback 'Succeeded' `
                -Detail 'Created the ASR Audit policy and confirmed its isolated direct pilot-group assignment.'
        }
        catch {
            $continuation = Get-DefenderContinuationCommand `
                -Reason 'the ASR apply operation did not complete exact policy and assignment readback'
            Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
                -Action 'mde-asr-audit-apply' -BestPracticeKey $policyConfig.Key `
                -FriendlyName $policyConfig.Name -Status 'Failed' `
                -Disposition 'Blocked' -Target ([string] $policyId) `
                -Readback 'Failed' `
                -Detail "$($_.Exception.Message) $continuation"
            throw
        }
        return
    }

    Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
        -Action 'AsrAuditReadback' -BestPracticeKey $policyConfig.Key `
        -FriendlyName $policyConfig.Name -Status 'Skipped' -Disposition 'GuidedOnly' `
        -Detail 'ASR schema validated. No policy with the configured managed name exists; apply remains GuidedOnly.'
    return
}
if (-not ([string] $namedPolicies[0].description).Contains(
        $Config.ManagedByTag,
        [StringComparison]::Ordinal)) {
    Stop-DefenderAsrOperation `
        -Message "An unmanaged Intune policy already uses the ASR policy name '$($policyConfig.Name)'; implicit adoption is not allowed."
}

$policyId = [string] $namedPolicies[0].id
if ([string]::IsNullOrWhiteSpace($policyId)) {
    Stop-DefenderAsrOperation `
        -Message 'The managed ASR policy collection result did not expose its policy identifier.'
}
$encodedPolicyId = [uri]::EscapeDataString($policyId)
try {
    $policyReadback = & $retryingGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$encodedPolicyId"
    $settingsReadback = & $retryingGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$encodedPolicyId/settings"
    $null = Assert-DefenderAsrPolicyReadback -Policy $policyReadback `
        -Settings @($settingsReadback.value) -ExpectedBody $expectedBody `
        -ManagedByTag $Config.ManagedByTag
}
catch {
    Stop-DefenderAsrOperation -Message $_.Exception.Message `
        -Action 'AsrAuditReadback' -Target $policyId -ReadbackFailed
}

if ([string]::IsNullOrWhiteSpace($PilotGroupId)) {
    Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
        -Action 'AsrAuditReadback' -BestPracticeKey $policyConfig.Key `
        -FriendlyName $policyConfig.Name -Status 'Skipped' -Disposition 'GuidedOnly' `
        -Target $policyId `
        -Detail 'Exact managed policy readback passed; assignment readback requires the approved pilot group identifier.'
    return
}

if (-not [guid]::TryParse($PilotGroupId, [ref] $pilotGroupGuid)) {
    Stop-DefenderAsrOperation -Message 'PilotGroupId must be a valid group GUID.'
}
$existingAssignments = @(Get-DefenderAsrGraphCollection `
    -GraphRequest $retryingGraphRequest `
    -InitialUri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$encodedPolicyId/assignments")
if ($existingAssignments.Count -eq 0 -and $EnableAsrAuditPolicy) {
    if (-not $PSCmdlet.ShouldProcess(
            $policyConfig.Name,
            "Assign the verified ASR Audit policy to pilot group '$pilotGroupGuid'")) {
        Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
            -Action 'mde-asr-audit-assign' -BestPracticeKey $policyConfig.Key `
            -FriendlyName $policyConfig.Name -Status 'Skipped' `
            -Disposition 'Skipped' -Target $policyId `
            -Detail 'The verified ASR Audit policy would be assigned to the approved pilot group.'
        return
    }
    try {
        $assignmentBody = New-DefenderAsrAssignmentBody -PilotGroupId $pilotGroupGuid
        $null = & $retryingGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$encodedPolicyId/assign" `
            -Body $assignmentBody
        $existingAssignments = @(Get-DefenderAsrGraphCollection `
            -GraphRequest $retryingGraphRequest `
            -InitialUri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$encodedPolicyId/assignments")
    }
    catch {
        $continuation = Get-DefenderContinuationCommand `
            -Reason 'the verified ASR policy could not be assigned and confirmed'
        Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
            -Action 'mde-asr-audit-assign' -BestPracticeKey $policyConfig.Key `
            -FriendlyName $policyConfig.Name -Status 'Failed' `
            -Disposition 'Blocked' -Target $policyId -Readback 'Failed' `
            -Detail "$($_.Exception.Message) $continuation"
        throw
    }
}
if ($existingAssignments.Count -eq 0) {
    Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
        -Action 'AsrAuditReadback' -BestPracticeKey $policyConfig.Key `
        -FriendlyName $policyConfig.Name -Status 'Skipped' `
        -Disposition 'GuidedOnly' -Target $policyId -Readback 'Pending' `
        -Detail 'Exact managed policy readback passed, but the policy has no assignment; enable the ASR Audit operation to add the approved pilot-group assignment.'
    return
}
try {
    $null = Assert-DefenderAsrAssignmentReadback -Assignments $existingAssignments `
        -PilotGroupId $pilotGroupGuid
}
catch {
    Stop-DefenderAsrOperation -Message $_.Exception.Message `
        -Action 'AsrAuditReadback' -Target $policyId -ReadbackFailed
}
Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
    -Action 'AsrAuditReadback' -BestPracticeKey $policyConfig.Key `
    -FriendlyName $policyConfig.Name -Status 'Succeeded' `
    -Disposition 'AlreadyCompliant' -Target $policyId `
    -Readback 'Succeeded' `
    -Detail 'Exact managed policy and isolated direct-group assignment readback passed.'
