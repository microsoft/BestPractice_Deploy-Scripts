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
    [switch] $UseDeviceAuthentication,
    [switch] $ConnectGraph,
    [string[]] $GraphScopes
)

. (Join-Path $PSScriptRoot 'DefenderRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'Get-DefenderPermissionPlan.ps1')

function Assert-DefenderCertificateArguments {
    [CmdletBinding()]
    param(
        [string] $TenantId,
        [string] $ClientId,
        [string] $CertificateThumbprint
    )

    $certificateValues = @($ClientId, $CertificateThumbprint)
    $provided = @($certificateValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
    if ($provided -gt 0 -and
        ([string]::IsNullOrWhiteSpace($TenantId) -or
         [string]::IsNullOrWhiteSpace($ClientId) -or
         [string]::IsNullOrWhiteSpace($CertificateThumbprint))) {
        throw 'TenantId, ClientId, and CertificateThumbprint must be supplied together for certificate authentication.'
    }
}

function Get-DefenderExchangeConnectionParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $TenantAdminUpn,
        [string] $DelegatedOrganization,
        [switch] $UseDeviceAuthentication
    )

    $parameters = @{
        UserPrincipalName = $TenantAdminUpn
        ShowBanner = $false
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($DelegatedOrganization)) {
        $parameters.DelegatedOrganization = $DelegatedOrganization
    }
    if ($UseDeviceAuthentication) {
        $parameters.Device = $true
    }
    return $parameters
}

function Assert-DefenderExchangeOrganization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ExpectedDomain,
        [Parameter(Mandatory)] [object] $Organization
    )

    $organizationName = if ($Organization.PSObject.Properties.Name -contains 'DomainName') {
        [string]$Organization.DomainName
    }
    else {
        [string]$Organization.Name
    }
    if ([string]::IsNullOrWhiteSpace($organizationName) -or
        $organizationName -ine $ExpectedDomain) {
        throw "Connected Exchange Online organization '$organizationName' does not match expected domain '$ExpectedDomain'."
    }
}

function Connect-DefenderExchangeOnline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $TenantAdminUpn,
        [string] $DelegatedOrganization,
        [switch] $NonInteractive,
        [switch] $UseDeviceAuthentication
    )

    if ($NonInteractive) {
        throw 'NonInteractive Exchange Online authentication is blocked until app-only authorization evidence is approved.'
    }

    try {
        $parameters = Get-DefenderExchangeConnectionParameters `
            -TenantAdminUpn $TenantAdminUpn `
            -DelegatedOrganization $DelegatedOrganization `
            -UseDeviceAuthentication:$UseDeviceAuthentication
        Connect-ExchangeOnline @parameters

        $connection = Get-ConnectionInformation -ErrorAction Stop |
            Where-Object { $_.State -eq 'Connected' } |
            Select-Object -First 1
        if (-not $connection) {
            throw 'Exchange Online connection information did not report a connected session.'
        }

        $expectedDomain = if ($DelegatedOrganization) {
            $DelegatedOrganization
        }
        elseif ($TenantAdminUpn -match '@(?<domain>[^@]+)$') {
            $Matches.domain
        }
        else {
            throw 'Unable to derive an expected Exchange Online organization from the supplied identity.'
        }
        Get-OrganizationConfig -ErrorAction Stop | Out-Null
        $organization = Get-AcceptedDomain -Identity $expectedDomain -ErrorAction Stop
        Assert-DefenderExchangeOrganization -ExpectedDomain $expectedDomain `
            -Organization $organization

        Add-DefenderRunLogEntry -Module 'Connect-DefenderServices' `
            -Action 'Connect-ExchangeOnline' -Status 'Succeeded' `
            -Detail 'Exchange Online connection and organization verified.'
        return $connection
    }
    catch {
        $status = Get-DefenderHttpStatusCode -ErrorRecord $_
        Add-DefenderRunLogEntry -Module 'Connect-DefenderServices' `
            -Action 'Connect-ExchangeOnline' -Status 'Failed' `
            -HttpStatusCode $status -Detail $_.Exception.Message
        throw
    }
}

function Assert-DefenderGraphAccount {
    [CmdletBinding()]
    param(
        [AllowNull()] $GraphContext,
        [Parameter(Mandatory)] [string] $TenantAdminUpn
    )

    if (-not $GraphContext -or $GraphContext.AuthType -ne 'Delegated' -or
        [string]::IsNullOrWhiteSpace([string] $GraphContext.Account) -or
        $GraphContext.Account -ine $TenantAdminUpn) {
        throw 'Microsoft Graph is not authenticated as the requested delegated operator. Reconnect with TenantAdminUpn before continuing.'
    }
}

function Connect-DefenderGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $Scopes,
        [Parameter(Mandatory)] [string] $ExpectedDomain,
        [Parameter(Mandatory)] [string] $TenantAdminUpn,
        [string] $TenantId,
        [string] $ClientId,
        [string] $CertificateThumbprint,
        [switch] $NonInteractive,
        [switch] $UseDeviceAuthentication
    )

    try {
        Assert-DefenderCertificateArguments -TenantId $TenantId -ClientId $ClientId `
            -CertificateThumbprint $CertificateThumbprint
        if (-not $Scopes -or $Scopes.Count -eq 0) {
            throw 'Microsoft Graph scopes must be supplied by the operation-scoped Defender permission plan.'
        }
        if ($NonInteractive -and
            ([string]::IsNullOrWhiteSpace($TenantId) -or
             [string]::IsNullOrWhiteSpace($ClientId) -or
             [string]::IsNullOrWhiteSpace($CertificateThumbprint))) {
            throw 'NonInteractive Graph authentication requires TenantId, ClientId, and CertificateThumbprint; delegated sign-in cannot prompt.'
        }

        if ($ClientId -and $CertificateThumbprint -and $TenantId) {
            throw 'App-only Microsoft Graph authorization is not enabled for the Defender least-privilege consent model; certificate-based runs are blocked before connection until operation-level application permission evidence is approved.'
        }
        $existingContext = Get-MgContext -ErrorAction SilentlyContinue
        $contextAccountMatches = $existingContext -and
            $existingContext.AuthType -eq 'Delegated' -and
            $existingContext.Account -ieq $TenantAdminUpn
        $contextTenantMatches = [string]::IsNullOrWhiteSpace($TenantId) -or
            ($existingContext -and $existingContext.TenantId -eq $TenantId)
        $missingScopes = @($Scopes | Where-Object {
                -not $existingContext -or @($existingContext.Scopes) -notcontains $_
            })
        if ($contextAccountMatches -and $contextTenantMatches -and $missingScopes.Count -eq 0) {
            $response = Invoke-WithTransientRetry -Description 'Verify cached Defender tenant' -Action {
                Invoke-DefenderGraphRequest -Method GET `
                    -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,verifiedDomains'
            }
            $organizations = @($response.value)
            $contextTenantMatches = $organizations.Count -eq 1 -and
                -not [string]::IsNullOrWhiteSpace([string] $existingContext.TenantId) -and
                $organizations[0].id -eq $existingContext.TenantId -and
                @($organizations[0].verifiedDomains | ForEach-Object name) -icontains $ExpectedDomain
        }
        $reuseContext = $contextAccountMatches -and $contextTenantMatches -and $missingScopes.Count -eq 0
        if (-not $reuseContext) {
            if ($existingContext) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            }
            $connectParameters = @{
                Scopes = $Scopes
                ContextScope = 'Process'
                NoWelcome = $true
                ErrorAction = 'Stop'
            }
            $connectParameters.TenantId = if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
                $TenantId
            } else { $ExpectedDomain }
            if ($UseDeviceAuthentication) {
                $connectParameters.UseDeviceAuthentication = $true
            }
            Connect-MgGraph @connectParameters | Out-Null
        }
        $verifiedContext = Get-MgContext -ErrorAction Stop
        Assert-DefenderGraphAccount -GraphContext $verifiedContext -TenantAdminUpn $TenantAdminUpn
        if (-not [string]::IsNullOrWhiteSpace($TenantId) -and $verifiedContext.TenantId -ine $TenantId) {
            throw 'Microsoft Graph did not connect to the explicitly requested tenant ID.'
        }
        Add-DefenderRunLogEntry -Module 'Connect-DefenderServices' `
            -Action 'Connect-MgGraph' -Status 'Succeeded' `
            -Detail $(if ($reuseContext) { 'Verified Microsoft Graph context reused for the requested operator and tenant.' }
                else { 'Microsoft Graph connection established for the requested operator.' })
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
        [System.Collections.IDictionary] $Body
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
        if ($null -eq $organization -or $null -eq $organization.verifiedDomains) {
            throw 'Microsoft Graph organization response is missing verifiedDomains.'
        }
        $domains = @($organization.verifiedDomains | ForEach-Object { $_.name.ToLowerInvariant() })
        $expected = $ExpectedDomain.ToLowerInvariant()
        if ($domains -notcontains $expected) {
            throw "Connected tenant does not contain expected domain '$ExpectedDomain'."
        }

        Add-DefenderRunLogEntry -Module 'Connect-DefenderServices' `
            -Action 'TenantIdentity' -Status 'Succeeded' `
            -Detail 'Tenant identity verified against the connected organization.'
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

$tenantIdentity = $null
if ($ConnectGraph) {
    $expectedDomain = if ($DelegatedOrganization) {
        $DelegatedOrganization
    }
    elseif ($TenantAdminUpn -match '@(?<domain>[^@]+)$') {
        $Matches.domain
    }
    else {
        throw 'Unable to derive an expected tenant domain from the supplied identity.'
    }
    Connect-DefenderGraph -Scopes $GraphScopes -TenantId $TenantId -ExpectedDomain $expectedDomain `
        -TenantAdminUpn $TenantAdminUpn `
        -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint `
        -NonInteractive:$NonInteractive `
        -UseDeviceAuthentication:$UseDeviceAuthentication
    $graphContext = Get-MgContext
    if (-not $graphContext) {
        throw 'Microsoft Graph context is not available after connection.'
    }
    try {
        Assert-DefenderGraphAccount -GraphContext $graphContext -TenantAdminUpn $TenantAdminUpn
        $consent = Test-DefenderGraphConsent -GraphContext $graphContext `
            -RequiredDelegatedScopes $GraphScopes
    }
    catch {
        $status = Get-DefenderHttpStatusCode -ErrorRecord $_
        Add-DefenderRunLogEntry -Module 'Connect-DefenderServices' `
            -Action 'PermissionCheck' -Status 'Failed' -HttpStatusCode $status `
            -Detail $_.Exception.Message
        throw
    }
    Add-DefenderRunLogEntry -Module 'Connect-DefenderServices' `
        -Action 'PermissionCheck' -Status 'Succeeded' `
        -Detail "Graph permission disposition: $($consent.Status)."
    $tenantIdentity = Get-DefenderTenantIdentity `
        -ExpectedDomain $expectedDomain -TenantAdminUpn $TenantAdminUpn
}

[pscustomobject]@{
    TenantAdminUpn = $TenantAdminUpn
    TenantId = $TenantId
    DelegatedOrganization = $DelegatedOrganization
    GraphConnected = [bool] $ConnectGraph
    GraphScopes = @($GraphScopes)
    TenantIdentity = $tenantIdentity
    GraphRequest = ${function:Invoke-DefenderGraphRequest}
}
