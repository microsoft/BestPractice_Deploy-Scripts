#requires -Version 7.0

. (Join-Path $PSScriptRoot 'EntraRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

function Resolve-EntraGraphUri {
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

function Invoke-EntraGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('GET')]
        [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [string] $EvidenceTarget,
        [int[]] $ExpectedStatusCodes = @(),
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
        $status = Get-EntraHttpStatusCode -ErrorRecord $_
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
            Add-EntraRunLogEntry -Module 'Connect-EntraServices' `
                -Action 'Invoke-MgGraphRequest' -Status 'Failed' `
                -Target $target -HttpStatusCode $status -Detail $detail
        }
        throw $safeException
    }
}
