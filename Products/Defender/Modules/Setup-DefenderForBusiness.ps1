#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [switch] $AdoptExisting,
    [string] $PilotGroupId,
    [switch] $EnableAsrBlockMode
)

. (Join-Path $PSScriptRoot 'DefenderRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

Add-DefenderRunLogEntry -Module 'Setup-DefenderForBusiness' `
    -Action 'Module' -Status 'Info' `
    -Detail 'DfB and Intune policy operations are reserved for verified BP implementations.'
