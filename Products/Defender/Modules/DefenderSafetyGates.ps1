#requires -Version 7.0
<#
.SYNOPSIS
    Validates explicit Defender safety gates before module dispatch.
#>

function Get-DefenderContinuationCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Reason,
        [string] $SwitchToRemove,
        [string] $SwitchToAdd
    )

    if ($SwitchToRemove) {
        return "Review $Reason, then re-run Deploy-DefenderBestPractice.ps1 without $SwitchToRemove."
    }
    if ($SwitchToAdd) {
        return "Review $Reason, then re-run Deploy-DefenderBestPractice.ps1 with $SwitchToAdd."
    }
    return "Review $Reason, then re-run Deploy-DefenderBestPractice.ps1 with the required approval and recovery parameters."
}

function Assert-DefenderSafetyGates {
    [CmdletBinding()]
    param(
        [switch] $IncludeHighRisk,
        [switch] $RollbackAcknowledged,
        [switch] $EnableMailFlowImpactingChanges,
        [switch] $EnableAutomatedRemediation,
        [switch] $EnableAsrBlockMode,
        [switch] $EnableMdcaEnforcement
    )

    $categoryGates = @(
        @{ Enabled = $EnableMailFlowImpactingChanges; Name = 'EnableMailFlowImpactingChanges' }
        @{ Enabled = $EnableAutomatedRemediation; Name = 'EnableAutomatedRemediation' }
        @{ Enabled = $EnableAsrBlockMode; Name = 'EnableAsrBlockMode' }
        @{ Enabled = $EnableMdcaEnforcement; Name = 'EnableMdcaEnforcement' }
    )

    foreach ($gate in $categoryGates) {
        if ($gate.Enabled -and -not $IncludeHighRisk) {
            throw (Get-DefenderContinuationCommand -Reason "$($gate.Name) requires IncludeHighRisk" -SwitchToAdd '-IncludeHighRisk')
        }
    }
    if ($EnableMailFlowImpactingChanges -and -not $RollbackAcknowledged) {
        throw (Get-DefenderContinuationCommand -Reason 'EnableMailFlowImpactingChanges requires RollbackAcknowledged')
    }
    return [pscustomobject]@{
        Status = 'Ready'
        HighRisk = [bool] $IncludeHighRisk
        RollbackAcknowledged = [bool] $RollbackAcknowledged
    }
}
