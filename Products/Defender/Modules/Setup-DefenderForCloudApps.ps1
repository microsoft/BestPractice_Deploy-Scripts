#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [switch] $IncludeHighRisk,
    [switch] $EnableMdcaEnforcement,
    [switch] $CloudDiscoveryReviewed
)

. (Join-Path $PSScriptRoot 'DefenderRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

Add-DefenderRunLogEntry -Module 'Setup-DefenderForCloudApps' `
    -Action 'Module' -Status 'Info' `
    -Detail 'MDCA operations are reserved for verified supported APIs.'
