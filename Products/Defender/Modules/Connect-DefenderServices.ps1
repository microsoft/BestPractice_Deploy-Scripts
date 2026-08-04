#requires -Version 7.0
<#
.SYNOPSIS
    Establishes supported Defender service connections and verifies tenant scope.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantAdminUpn,
    [string] $TenantId,
    [string] $ClientId,
    [string] $CertificateThumbprint,
    [string] $DelegatedOrganization,
    [switch] $AutoInstallModules,
    [switch] $NonInteractive,
    [switch] $ConnectGraph
)

. (Join-Path $PSScriptRoot 'DefenderRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

function Connect-DefenderGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $Scopes,
        [string] $TenantId,
        [string] $ClientId,
        [string] $CertificateThumbprint
    )

    try {
        if ($ClientId -and $CertificateThumbprint -and $TenantId) {
            # Certificate authentication requires a pre-installed certificate
            # in the local certificate store; no secret is accepted here.
            Connect-MgGraph -ClientId $ClientId -TenantId $TenantId `
                -CertificateThumbprint $CertificateThumbprint -NoWelcome `
                -ErrorAction Stop
        }
        else {
            Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
        }

        Add-DefenderRunLogEntry -Module 'Connect-DefenderServices' `
            -Action 'Connect-MgGraph' -Status 'Succeeded' `
            -Detail 'Microsoft Graph connection established.'
    }
    catch {
        $status = Get-DefenderHttpStatusCode -ErrorRecord $_
        Add-DefenderRunLogEntry -Module 'Connect-DefenderServices' `
            -Action 'Connect-MgGraph' -Status 'Failed' -HttpStatusCode $status `
            -Detail $_.Exception.Message
        throw
    }
}

function Invoke-DefenderGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('GET','POST','PATCH','PUT','DELETE')]
        [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [hashtable] $Body
    )

    try {
        $request = @{
            Method = $Method
            Uri = $Uri
            ErrorAction = 'Stop'
        }
        if ($Body) {
            # Graph payloads are JSON objects whose property names and nesting
            # must match the resource schema documented for the target API.
            $request.Body = $Body | ConvertTo-Json -Depth 20
            $request.ContentType = 'application/json'
        }
        return Invoke-MgGraphRequest @request
    }
    catch {
        $status = Get-DefenderHttpStatusCode -ErrorRecord $_
        Add-DefenderRunLogEntry -Module 'Connect-DefenderServices' `
            -Action 'Invoke-MgGraphRequest' -Status 'Failed' `
            -Target $Uri -HttpStatusCode $status -Detail $_.Exception.Message
        throw
    }
}

function Get-DefenderTenantIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ExpectedDomain,
        [Parameter(Mandatory)] [string] $TenantAdminUpn
    )

    try {
        $response = Invoke-DefenderGraphRequest -Method 'GET' `
            -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,verifiedDomains'
        $organization = @($response.value)[0]
        $domains = @($organization.verifiedDomains | ForEach-Object { $_.name.ToLowerInvariant() })
        $expected = $ExpectedDomain.ToLowerInvariant()
        if ($domains -notcontains $expected) {
            throw "Connected tenant does not contain expected domain '$ExpectedDomain'."
        }

        Add-DefenderRunLogEntry -Module 'Connect-DefenderServices' `
            -Action 'TenantIdentity' -Status 'Succeeded' `
            -Detail "Tenant identity verified for $ExpectedDomain."
        return [pscustomobject]@{
            TenantId = $organization.id
            ExpectedDomain = $ExpectedDomain
            VerifiedDomains = $domains
            TenantAdminUpn = $TenantAdminUpn
        }
    }
    catch {
        $status = Get-DefenderHttpStatusCode -ErrorRecord $_
        Add-DefenderRunLogEntry -Module 'Connect-DefenderServices' `
            -Action 'TenantIdentity' -Status 'Failed' `
            -HttpStatusCode $status -Detail $_.Exception.Message
        throw
    }
}

if ($ConnectGraph) {
    $scopes = @('Organization.Read.All')
    Connect-DefenderGraph -Scopes $scopes -TenantId $TenantId `
        -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint
    $expectedDomain = if ($DelegatedOrganization) {
        $DelegatedOrganization
    }
    elseif ($TenantAdminUpn -match '@(?<domain>[^@]+)$') {
        $Matches.domain
    }
    else {
        throw 'Unable to derive an expected tenant domain from the supplied identity.'
    }
    $tenantIdentity = Get-DefenderTenantIdentity `
        -ExpectedDomain $expectedDomain -TenantAdminUpn $TenantAdminUpn
}

[pscustomobject]@{
    TenantAdminUpn = $TenantAdminUpn
    TenantId = $TenantId
    DelegatedOrganization = $DelegatedOrganization
    GraphConnected = [bool] $ConnectGraph
    TenantIdentity = $tenantIdentity
    GraphRequest = ${function:Invoke-DefenderGraphRequest}
}
