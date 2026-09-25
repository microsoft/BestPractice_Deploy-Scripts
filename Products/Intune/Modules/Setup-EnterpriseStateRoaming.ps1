#requires -Version 7.0
<#
.SYNOPSIS
    Enterprise State Roaming through Windows Backup for Organizations (task 9).

.DESCRIPTION
    Microsoft moved Enterprise State Roaming management from the Entra portal
    to Windows Backup for Organizations policy management after June 2026.
    This module records the current supported guided workflow while policy API,
    payload, assignment, readback, and rollback behavior are verified.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
# smb-quality-gate: read-only
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context
)

. (Join-Path $PSScriptRoot 'IntuneRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

Add-IntuneRunLogEntry -Module 'Setup-EnterpriseStateRoaming' `
    -Action 'GuidedConfiguration' -BestPracticeKey 'enterprise-state-roaming' `
    -Status 'Info' -Disposition 'GuidedOnly' `
    -Detail 'Enterprise State Roaming management moved to Windows Backup for Organizations after June 2026. Use Intune admin center > Devices > Device onboarding > Enrollment > Windows > Windows Backup and Restore, confirm supported Windows builds and licensing, configure a pilot policy, and verify backup and restore status before broader assignment. The former Entra ID > Devices > Enterprise State Roaming path is obsolete. Automated policy creation remains blocked until the supported API payload, assignment, readback, and rollback contract is verified.'
