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

Add-DefenderRunLogEntry -Module 'Setup-MdoEopBaseline' `
    -Action 'Module' -Status 'Info' `
    -Detail 'MDO/EOP API operations are reserved for verified BP implementations.'
