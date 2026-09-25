#requires -Version 7.0
<#
.SYNOPSIS
    Shared, connection-independent Microsoft Graph request helpers for Intune.

.DESCRIPTION
    Resolve-IntuneGraphUri and Invoke-IntuneGraphRequest do not authenticate.
    They assume a Microsoft Graph context already exists in the current
    PowerShell session (established once by Connect-IntuneServices.ps1 through
    the orchestrator, or by the operator when a module is run standalone).
    Task modules dot-source this file instead of Connect-IntuneServices.ps1 so
    that reading these helpers never has the side effect of connecting or
    reconnecting Microsoft Graph.
#>

. (Join-Path $PSScriptRoot 'IntuneRunLog.ps1')
# Dot-sourced here (not only relied on from a caller's own dot-source) so
# Get-IntuneHttpStatusCode always resolves even when a caller dot-sources only
# this file, matching the "connection-independent" contract in the synopsis
# above. Re-dot-sourcing is harmless: it only redefines functions that are
# already idempotent to redefine.
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

function Resolve-IntuneGraphUri {
    <#
        Builds a request URI from the configured base. The base is validated
        against the approved Graph hosts so a configuration edit cannot redirect
        tenant reads to an arbitrary endpoint.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $BaseUri,
        [Parameter(Mandatory)] [string] $RelativePath
    )

    $approvedHosts = @(
        'graph.microsoft.com',
        'graph.microsoft.us',
        'dod-graph.microsoft.us',
        'microsoftgraph.chinacloudapi.cn'
    )

    $parsed = $null
    if (-not [uri]::TryCreate($BaseUri, [UriKind]::Absolute, [ref] $parsed)) {
        throw "Api.GraphBaseUri is not an absolute URI: $BaseUri"
    }
    if ($parsed.Scheme -ne 'https') {
        throw "Api.GraphBaseUri must use HTTPS: $BaseUri"
    }
    if ($parsed.Host -notin $approvedHosts) {
        throw "Api.GraphBaseUri host '$($parsed.Host)' is not an approved Microsoft Graph endpoint."
    }

    return ('{0}/{1}' -f $BaseUri.TrimEnd('/'), $RelativePath.TrimStart('/'))
}

function Invoke-IntuneGraphRequest {
    <#
        Read-only while the product is Planned. The write verbs are deliberately
        absent from the ValidateSet rather than merely unused, so a future
        module cannot reach a tenant write before its operation is verified.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('GET')]
        [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [string] $EvidenceTarget,
        [int[]] $ExpectedStatusCodes = @(),
        # Only defer inside Invoke-WithTransientRetry, which owns the terminal
        # Failed entry after retries are exhausted.
        [switch] $DeferFailureEvidence
    )

    try {
        $request = @{
            Method = $Method
            Uri = $Uri
            ErrorAction = 'Stop'
        }
        return Invoke-MgGraphRequest @request
    }
    catch {
        $status = Get-IntuneHttpStatusCode -ErrorRecord $_
        $target = if ([string]::IsNullOrWhiteSpace($EvidenceTarget)) {
            $Uri
        }
        else {
            $EvidenceTarget
        }
        $detail = if ([string]::IsNullOrWhiteSpace($EvidenceTarget)) {
            $_.Exception.Message
        }
        else {
            "Microsoft Graph request failed for $EvidenceTarget."
        }
        $safeException = [Exception]::new($detail)
        if ($status) {
            $safeException | Add-Member -NotePropertyName Response `
                -NotePropertyValue ([pscustomobject] @{ StatusCode = $status })
        }
        if ($status -in $ExpectedStatusCodes) {
            throw $safeException
        }
        if (-not $DeferFailureEvidence) {
            Add-IntuneRunLogEntry -Module 'Connect-IntuneServices' `
                -Action 'Invoke-MgGraphRequest' -Status 'Failed' `
                -Target $target -HttpStatusCode $status -Detail $detail
        }
        throw $safeException
    }
}
