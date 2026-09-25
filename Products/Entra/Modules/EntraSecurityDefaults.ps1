#requires -Version 7.0

. (Join-Path $PSScriptRoot 'EntraGraphClient.ps1')
. (Join-Path $PSScriptRoot 'EntraPolicyComparison.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

function Get-EntraSecurityDefaultsState {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $BaseUri,
        [Parameter(Mandatory)] [string] $Module
    )

    try {
        $uri = Resolve-EntraGraphUri -BaseUri $BaseUri `
            -RelativePath 'policies/identitySecurityDefaultsEnforcementPolicy'
        $policy = Invoke-WithTransientRetry -Description 'Read Security Defaults state' -Action {
            Invoke-EntraGraphRequest -Method GET -Uri $uri `
                -EvidenceTarget 'Security Defaults' -DeferFailureEvidence
        }
        $enabled = Get-EntraPolicyProperty -InputObject $policy -Name 'isEnabled'
        if ($enabled -isnot [bool]) {
            throw 'Security Defaults response must contain a Boolean isEnabled.'
        }
        $state = if ($enabled) { 'Enabled' } else { 'Disabled' }
        Add-EntraRunLogEntry -Module $Module -Action 'SecurityDefaults' `
            -Status 'Info' -Disposition $(if ($enabled) { 'Blocked' } else { 'Applicable' }) `
            -Readback 'Verified' -Detail (
                "SecurityDefaultsState=$state; TenantWritesAllowed=$(-not $enabled). " +
                'Security Defaults is never changed by this toolkit. Disabled does not prove replacement protection.'
            )
        return $state
    }
    catch {
        Add-EntraRunLogEntry -Module $Module -Action 'SecurityDefaults' `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
            -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
            -Detail 'SecurityDefaultsState=Unknown; TenantWritesAllowed=False. The read failed or isEnabled was not Boolean. Verify Policy.Read.All, effective access and the service response; assessment may continue, but no tenant write is authorized.'
        return 'Unknown'
    }
}

function Test-EntraSecurityDefaultsWriteAllowed {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $BaseUri,
        [Parameter(Mandatory)] [string] $Module,
        [Parameter(Mandatory)] [string] $BestPracticeKey
    )

    # Re-read at the write boundary, including standalone modules. A caller's
    # cached context or a successful earlier read cannot authorize a later write.
    $state = Get-EntraSecurityDefaultsState -BaseUri $BaseUri -Module $Module
    if ($state -eq 'Disabled') { return $true }
    Add-EntraRunLogEntry -Module $Module -Action 'SecurityDefaultsWriteGate' `
        -BestPracticeKey $BestPracticeKey -Status 'Skipped' -Disposition 'Blocked' `
        -Detail "Tenant write withheld because Security Defaults is $state. Keep existing protection enabled until an approved transition has active replacement coverage; report-only policies are not a replacement. See the Security Defaults transition guide."
    return $false
}
