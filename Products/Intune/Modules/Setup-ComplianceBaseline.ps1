#requires -Version 7.0
<#
.SYNOPSIS
    Default device compliance setting (guide task 4).

.DESCRIPTION
    Assesses and, when authorized, enables the tenant-wide default compliance
    setting (secureByDefault) that treats a device with no targeted compliance
    policy as not compliant. Creating per-platform compliance policies is a
    separate module (Setup-DeviceCompliancePolicies).

    The setting is inert on its own and becomes an access denial once a
    device-based Conditional Access policy exists. The write is therefore High
    risk and only runs when the orchestrator has cleared the item (IncludeHighRisk
    + EnableComplianceEnforcement); otherwise the module assesses and reports
    without changing tenant state. All changes are gated by ShouldProcess,
    wrapped in the shared transient-retry boundary, and read back.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [switch] $AdoptExisting,
    # High-risk authorization. The orchestrator also records the item in
    # Context.WriteBlockedItemKeys when these are absent; both are honored.
    [switch] $IncludeHighRisk,
    [switch] $EnableComplianceEnforcement
)

$ErrorActionPreference = 'Stop'
$ConfirmPreference = 'None'

. (Join-Path $PSScriptRoot 'IntuneRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

function Get-IntuneDefaultComplianceState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if (-not (Get-Command -Name 'Get-MgDeviceManagement' -ErrorAction SilentlyContinue)) {
        throw 'Get-MgDeviceManagement is unavailable. Install or import Microsoft.Graph.DeviceManagement, then rerun the default compliance assessment.'
    }

    $deviceManagement = Invoke-WithTransientRetry `
        -Description 'Get default compliance setting' `
        -Action {
            try {
                Get-MgDeviceManagement -Property 'Settings' -ErrorAction Stop
            }
            catch {
                $status = Get-IntuneHttpStatusCode -ErrorRecord $_
                $exception = [Exception]::new(
                    'Microsoft Graph request failed for the default compliance setting.'
                )
                if ($status) {
                    $exception | Add-Member -NotePropertyName Response `
                        -NotePropertyValue ([pscustomobject] @{ StatusCode = $status })
                }
                throw $exception
            }
        }

    if ($null -eq $deviceManagement) {
        throw 'Get-MgDeviceManagement returned no deviceManagement response; default compliance state is unknown.'
    }

    $settingsProperty = $deviceManagement.PSObject.Properties['Settings']
    if (-not $settingsProperty -or $null -eq $settingsProperty.Value) {
        return [pscustomobject]@{
            SecureByDefault = $null
            ProjectionUnavailable = $true
            ProjectionDetail = 'Microsoft Graph returned no Settings object for default compliance.'
        }
    }

    $secureByDefaultProperty = $settingsProperty.Value.PSObject.Properties['SecureByDefault']
    if (-not $secureByDefaultProperty) {
        return [pscustomobject]@{
            SecureByDefault = $null
            ProjectionUnavailable = $true
            ProjectionDetail = 'Microsoft Graph returned no SecureByDefault value for default compliance.'
        }
    }
    if ($null -eq $secureByDefaultProperty.Value) {
        return [pscustomobject]@{
            SecureByDefault = $null
            ProjectionUnavailable = $true
            ProjectionDetail = 'Microsoft Graph returned a nullable SecureByDefault value, so the effective default compliance state could not be confirmed.'
        }
    }
    if ($secureByDefaultProperty.Value -isnot [bool]) {
        throw 'Get-MgDeviceManagement returned a SecureByDefault value that is not a real Boolean; default compliance state is unknown.'
    }

    return [pscustomobject]@{
        SecureByDefault = [bool] $secureByDefaultProperty.Value
        ProjectionUnavailable = $false
        ProjectionDetail = $null
    }
}

$bestPracticeKey = 'default-compliance-settings'

if ($Context -and @($Context.BlockedItemKeys) -contains $bestPracticeKey) {
    Add-IntuneRunLogEntry -Module 'Setup-ComplianceBaseline' `
        -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
        -Status 'Skipped' -Disposition 'Skipped' `
        -Detail 'Skipped because preflight or operator gating blocked default-compliance-settings.'
    return
}

try {
    if (-not $Context) {
        throw 'Setup-ComplianceBaseline.ps1 requires -Context from a pre-authenticated Graph connection. Run it through Deploy-IntuneBestPractice.ps1 (the orchestrator), or connect to Microsoft Graph yourself and supply -Context.'
    }

    if ([string]::IsNullOrWhiteSpace([string] $Context.TenantAdminUpn)) {
        throw 'Setup-ComplianceBaseline.ps1 requires Context.TenantAdminUpn for Graph authentication.'
    }

    $state = Get-IntuneDefaultComplianceState

    if ($state.SecureByDefault) {
        Add-IntuneRunLogEntry -Module 'Setup-ComplianceBaseline' `
            -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
            -Status 'Skipped' -Disposition 'AlreadyCompliant' -Readback 'Verified' `
            -Detail 'Default compliance already treats devices without a targeted compliance policy as noncompliant. SecureByDefault=True.'
        return
    }

    if ($state.ProjectionUnavailable) {
        Add-IntuneRunLogEntry -Module 'Setup-ComplianceBaseline' `
            -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'GuidedOnly' -Readback 'NotAttempted' `
            -Detail "$($state.ProjectionDetail) Verify the Compliance policy settings page in the Intune admin center. No tenant write was attempted because the current state is unknown."
        return
    }

    # SecureByDefault is False (drift). Only write when the orchestrator cleared
    # the item and both high-risk switches are present; otherwise assess only.
    $writeWithheld = (@($Context.WriteBlockedItemKeys) -contains $bestPracticeKey) -or
        -not $IncludeHighRisk -or
        -not $EnableComplianceEnforcement -or
        -not [bool] $Context.IncludeHighRisk
    if ($writeWithheld) {
        Add-IntuneRunLogEntry -Module 'Setup-ComplianceBaseline' `
            -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'GuidedOnly' `
            -Detail 'Assessment only: the default compliance setting remains unchanged. Enabling secure-by-default is withheld until IncludeHighRisk and EnableComplianceEnforcement are supplied; it marks devices without a targeted compliance policy noncompliant and can deny access when compliant-device Conditional Access is enforced. SecureByDefault=False.'
        return
    }

    $checkin = [int] $Config.DefaultCompliance.CheckinThresholdDays
    if (-not $PSCmdlet.ShouldProcess('Default compliance settings', "Set secureByDefault=true, check-in threshold=$checkin days")) {
        Add-IntuneRunLogEntry -Module 'Setup-ComplianceBaseline' `
            -Action 'DefaultCompliance' -BestPracticeKey $bestPracticeKey `
            -Status 'Info' -Disposition 'WillChange' -Readback 'NotAttempted' `
            -Detail "WhatIf: would enable secure-by-default (checkin threshold $checkin days). This marks devices without a targeted compliance policy noncompliant."
        return
    }

    Invoke-WithTransientRetry -Description 'Enable secure-by-default compliance' -Action {
        Update-MgDeviceManagement -Settings @{
            secureByDefault                      = $true
            deviceComplianceCheckinThresholdDays = $checkin
            isScheduledActionEnabled             = $true
        } -Confirm:$false -ErrorAction Stop | Out-Null
    }
    Add-IntuneRunLogEntry -Module 'Setup-ComplianceBaseline' `
        -Action 'DefaultCompliance' -BestPracticeKey $bestPracticeKey `
        -Status 'Updated' -Disposition 'Applicable' `
        -Detail "Enabled secure-by-default; devices without a targeted compliance policy are now treated as noncompliant (check-in threshold $checkin days)."

    $after = Get-IntuneDefaultComplianceState
    if ($after.ProjectionUnavailable) {
        $reason = "$($after.ProjectionDetail) The update request completed, but Graph did not provide a verifiable readback. Verify the Compliance policy settings page in the Intune admin center before rerunning or continuing deployment."
        Add-IntuneRunLogEntry -Module 'Setup-ComplianceBaseline' `
            -Action 'Readback' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' `
            -Detail $reason
        throw $reason
    }
    $readback = if ($after.SecureByDefault) { 'Verified' } else { 'Mismatch' }
    if ($readback -ne 'Verified') {
        $reason = 'Default compliance readback did not confirm SecureByDefault=True.'
        Add-IntuneRunLogEntry -Module 'Setup-ComplianceBaseline' `
            -Action 'Readback' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback $readback `
            -Detail $reason
        throw $reason
    }
    Add-IntuneRunLogEntry -Module 'Setup-ComplianceBaseline' `
        -Action 'Readback' -BestPracticeKey $bestPracticeKey `
        -Status 'Info' -Disposition 'Applicable' -Readback $readback `
        -Detail "Read-back returned SecureByDefault=$($after.SecureByDefault)."
}
catch {
    $status = Get-IntuneHttpStatusCode -ErrorRecord $_
    Add-IntuneRunLogEntry -Module 'Setup-ComplianceBaseline' `
        -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -HttpStatusCode $status `
        -Detail $_.Exception.Message
    throw
}
