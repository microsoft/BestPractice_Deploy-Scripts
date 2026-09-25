#requires -Version 7.0
<#
.SYNOPSIS
    Establishes the delegated Microsoft Graph connection required by Entra.

.DESCRIPTION
    Uses the same delegated UPN/GDAP session-guard behavior as Purview. A cached
    context is reused only when its account, scopes, and target tenant are
    trustworthy. Stale contexts are disconnected before a new interactive
    connection is opened, and tenant identity is verified before setup begins.

.PARAMETER TenantAdminUpn
    Administrator UPN used for delegated sign-in.

.PARAMETER DelegatedOrganization
    Customer tenant domain for a GDAP run. Graph authenticates directly to this
    tenant rather than the administrator's home tenant.

.PARAMETER Scopes
    Product-specific delegated Graph scopes supplied from EntraConfig.psd1.

.PARAMETER AutoInstallModules
    Installs missing Microsoft Graph modules to CurrentUser without prompting.

.PARAMETER NonInteractive
    Suppresses toolkit prompts. Delegated Graph authentication can still require
    an existing usable token or interactive browser/WAM sign-in.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantAdminUpn,
    [string] $DelegatedOrganization,
    [string[]] $Scopes = @('User.Read'),
    [Parameter(Mandatory)] [string] $GraphBaseUri,
    [switch] $AutoInstallModules,
    [switch] $NonInteractive,
    [switch] $ConnectGraph
)

$ErrorActionPreference = 'Stop'
$WhatIfPreference = $false
$ConfirmPreference = 'None'

. (Join-Path $PSScriptRoot 'EntraRunLog.ps1')
. (Join-Path $PSScriptRoot 'EntraGraphClient.ps1')

function Add-EntraConnectGuardLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Service,
        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Started', 'Retried', 'Failed')]
        [string] $Status,
        [Parameter(Mandatory)] [string] $ReasonKey,
        [hashtable] $Detail
    )

    if (-not (Get-Command Add-EntraRunLogEntry -ErrorAction SilentlyContinue)) {
        return
    }

    $parts = @("reason=$ReasonKey")
    if ($Detail) {
        foreach ($key in ($Detail.Keys | Sort-Object)) {
            $value = $Detail[$key]
            if ($null -eq $value) { $value = '' }
            $parts += ('{0}={1}' -f $key, $value)
        }
    }

    Add-EntraRunLogEntry -Module 'Connect-EntraServices' `
        -Action "SessionGuard:$Service" -Status $Status `
        -Detail ($parts -join '; ')
}

function Test-EntraIsAdmin {
    try {
        $current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Ensure-EntraRequiredModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [string] $RequiredCmdlet,
        [switch] $AutoInstall,
        [switch] $NonInteractive
    )

    $available = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue
    if ($available) {
        try {
            Import-Module $Name -DisableNameChecking -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Verbose "Import-Module '$Name' failed: $($_.Exception.Message)"
        }
    }

    $cmdletOk = if ($RequiredCmdlet) {
        [bool](Get-Command $RequiredCmdlet -ErrorAction SilentlyContinue)
    }
    else {
        [bool]$available
    }
    if ($cmdletOk) { return }

    Write-Warning "Required module '$Name' is missing or its cmdlets cannot load$(if ($RequiredCmdlet) { " ($RequiredCmdlet not found)" })."
    $shouldInstall = $AutoInstall.IsPresent
    if (-not $shouldInstall -and $NonInteractive.IsPresent) {
        $manual = "Install-Module $Name -Scope CurrentUser -Force -AllowClobber"
        throw "Module '$Name' is required but is not installed and -NonInteractive is set (cannot prompt). Either pre-install the module or re-run with -AutoInstallModules:`n    $manual"
    }
    if (-not $shouldInstall) {
        $response = Read-Host "Install '$Name' from PSGallery now to the current user scope? [Y/n]"
        if ([string]::IsNullOrWhiteSpace($response) -or $response -match '^(y|yes)$') {
            $shouldInstall = $true
        }
    }
    if (-not $shouldInstall) {
        $manual = "Install-Module $Name -Scope CurrentUser -Force -AllowClobber"
        throw "Module '$Name' is required but was not installed. Install manually and re-run:`n    $manual"
    }

    $isAdmin = Test-EntraIsAdmin
    if (-not $isAdmin) {
        Write-Host '  Installing to CurrentUser; elevation is not required.' -ForegroundColor DarkGray
    }
    try {
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    catch {
        $hint = if ($isAdmin) {
            "Try installing for all users:`n    Install-Module $Name -Scope AllUsers -Force -AllowClobber"
        }
        else {
            "Install manually in an elevated PowerShell session, or retry with CurrentUser scope."
        }
        throw "Failed to install module '$Name': $($_.Exception.Message)`n$hint"
    }

    try {
        Import-Module $Name -DisableNameChecking -ErrorAction Stop | Out-Null
    }
    catch {
        throw "Module '$Name' was installed but failed to import: $($_.Exception.Message)"
    }
    if ($RequiredCmdlet -and -not (Get-Command $RequiredCmdlet -ErrorAction SilentlyContinue)) {
        throw "Module '$Name' was installed but cmdlet '$RequiredCmdlet' is still not available. Restart PowerShell and re-run."
    }
}

function Test-EntraWamBrokerReadiness {
    [CmdletBinding()]
    param()

    $issues = @()
    $info = [ordered]@{
        wamEligible = $false
        psEdition = $PSVersionTable.PSEdition
        psVersion = $PSVersionTable.PSVersion.ToString()
        isWindows = [bool]$IsWindows
        windowsBuild = $null
        productType = $null
        userInteractive = [Environment]::UserInteractive
        runningAsSystem = $false
        graphAuthModuleVersion = 'not-installed'
    }

    if (-not $IsWindows) {
        $issues += 'WAM is available only on Windows; Graph will use its browser flow.'
    }
    else {
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $build = [int]$os.BuildNumber
            $productType = [int]$os.ProductType
            $info.windowsBuild = $build
            $info.productType = $productType
            if ($productType -eq 1 -and $build -lt 10240) {
                $issues += "Windows build $build is older than Windows 10 1507."
            }
            elseif ($productType -ge 2 -and $build -lt 17763) {
                $issues += "Windows Server build $build is older than Server 2019."
            }
        }
        catch {
            Write-Verbose "Could not detect Windows build via CIM: $($_.Exception.Message)"
        }

        try {
            $current = [Security.Principal.WindowsIdentity]::GetCurrent()
            if ($current -and $current.IsSystem) {
                $info.runningAsSystem = $true
                $issues += 'WAM requires a user desktop session and cannot run as SYSTEM.'
            }
        }
        catch {
            Write-Verbose "Could not inspect the Windows identity: $($_.Exception.Message)"
        }
    }

    if (-not [Environment]::UserInteractive) {
        $issues += 'WAM requires an interactive desktop session.'
    }

    $graphModule = Get-Module Microsoft.Graph.Authentication -ListAvailable -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if ($graphModule) {
        $info.graphAuthModuleVersion = $graphModule.Version.ToString()
        if ($graphModule.Version.Major -lt 2) {
            $issues += "Microsoft.Graph.Authentication v$($graphModule.Version) predates built-in WAM support."
        }
    }

    $info.wamEligible = ($issues.Count -eq 0)
    return [pscustomobject]@{
        Eligible = $info.wamEligible
        Issues = $issues
        Info = $info
    }
}

function Get-EntraTenantIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ExpectedDomain,
        [Parameter(Mandatory)] [string] $TenantAdminUpn,
        [Parameter(Mandatory)] [string] $GraphBaseUri
    )

    try {
        $organizationUri = Resolve-EntraGraphUri -BaseUri $GraphBaseUri `
            -RelativePath 'organization?$select=id,verifiedDomains'
        $response = Invoke-EntraGraphRequest -Method 'GET' -Uri $organizationUri `
            -EvidenceTarget 'tenant organization'
        $organization = @($response.value)[0]
        if (-not $organization -or [string]::IsNullOrWhiteSpace([string]$organization.id)) {
            throw 'Microsoft Graph returned no tenant organization identity.'
        }
        $domains = @($organization.verifiedDomains | ForEach-Object { $_.name.ToLowerInvariant() })
        Register-EntraSensitiveValue -Value $domains
        if ($domains -notcontains $ExpectedDomain.ToLowerInvariant()) {
            throw 'Connected tenant does not contain the expected verified domain.'
        }

        Add-EntraRunLogEntry -Module 'Connect-EntraServices' `
            -Action 'TenantIdentity' -Status 'Succeeded' `
            -Detail 'Tenant identity verified against the expected domain.'
        return [pscustomobject]@{
            TenantId = $organization.id
            ExpectedDomain = $ExpectedDomain
            VerifiedDomains = $domains
            TenantAdminUpn = $TenantAdminUpn
        }
    }
    catch {
        $status = Get-EntraHttpStatusCode -ErrorRecord $_
        Add-EntraRunLogEntry -Module 'Connect-EntraServices' `
            -Action 'TenantIdentity' -Status 'Failed' `
            -HttpStatusCode $status -Detail $_.Exception.Message
        throw
    }
}

$tenantIdentity = $null
if ($ConnectGraph) {
    Register-EntraSensitiveValue -Value $DelegatedOrganization
    if ($TenantAdminUpn -notmatch '@(?<domain>[^@\s]+)$') {
        throw 'Unable to derive an expected tenant domain from TenantAdminUpn.'
    }
    $upnDomain = $Matches.domain
    Register-EntraSensitiveValue -Value $upnDomain
    $targetTenantDomain = if ($DelegatedOrganization) { $DelegatedOrganization } else { $upnDomain }

    $wamReadiness = Test-EntraWamBrokerReadiness
    if ($wamReadiness.Eligible) {
        Write-Host "WAM broker available: Graph sign-in should usually use a one-click 'Continue' prompt." -ForegroundColor DarkGray
    }
    else {
        Write-Warning 'Windows Authentication Manager (WAM) is not fully usable; expect a browser sign-in.'
        foreach ($issue in $wamReadiness.Issues) { Write-Warning "  * $issue" }
    }
    Add-EntraConnectGuardLog -Service 'Startup' -Status 'Info' `
        -ReasonKey $(if ($wamReadiness.Eligible) { 'wam-ready' } else { 'wam-not-ready' }) `
        -Detail $wamReadiness.Info

    Ensure-EntraRequiredModule -Name 'Microsoft.Graph.Authentication' `
        -RequiredCmdlet 'Connect-MgGraph' -AutoInstall:$AutoInstallModules `
        -NonInteractive:$NonInteractive

    $requiredScopes = @($Scopes | Where-Object { $_ } | Select-Object -Unique)
    if ($requiredScopes.Count -eq 0) { $requiredScopes = @('User.Read') }
    $guardDetail = @{
        expectedUpn = $TenantAdminUpn
        expectedTenantDomain = $targetTenantDomain
        expectedScopes = ($requiredScopes -join ',')
    }
    $graphConnected = $false
    $guardReason = 'no-context'

    try {
        $context = Get-MgContext -ErrorAction Stop
        if ($context) {
            $cachedScopes = @($context.Scopes)
            $missingScopes = @($requiredScopes | Where-Object { $cachedScopes -notcontains $_ })
            if ($context.Account -and
                $context.Account -ieq $TenantAdminUpn -and
                $missingScopes.Count -eq 0) {
                $tenantMatches = $false
                try {
                    $organizationUri = Resolve-EntraGraphUri -BaseUri $GraphBaseUri `
                        -RelativePath 'organization?$select=verifiedDomains'
                    $response = Invoke-EntraGraphRequest -Method 'GET' -Uri $organizationUri `
                        -EvidenceTarget 'cached tenant organization'
                    $domains = @($response.value.verifiedDomains | ForEach-Object { $_.name.ToLowerInvariant() })
                    Register-EntraSensitiveValue -Value $domains
                    $tenantMatches = $domains -contains $targetTenantDomain.ToLowerInvariant()
                    if (-not $tenantMatches) { $guardReason = 'tenant-domain-mismatch' }
                }
                catch {
                    $guardReason = 'tenant-verification-failed'
                }
                if ($tenantMatches) {
                    $graphConnected = $true
                    $guardReason = 'reused'
                }
            }
            elseif ($missingScopes.Count -gt 0 -and $context.Account -ieq $TenantAdminUpn) {
                $guardReason = 'missing-scopes'
                $guardDetail.missingScopes = ($missingScopes -join ',')
            }
            else {
                $guardReason = 'account-mismatch'
            }

            $guardDetail.cachedAccount = [string]$context.Account
            $guardDetail.cachedTenantId = [string]$context.TenantId
            if (-not $graphConnected) {
                Add-EntraConnectGuardLog -Service 'Graph' -Status 'Retried' `
                    -ReasonKey $guardReason -Detail $guardDetail
                try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
            }
        }
    }
    catch {
        $guardReason = 'get-mgcontext-failed'
        $guardDetail.error = $_.Exception.Message
    }

    if ($graphConnected) {
        Add-EntraConnectGuardLog -Service 'Graph' -Status 'Info' `
            -ReasonKey 'reused' -Detail $guardDetail
    }
    else {
        Add-EntraConnectGuardLog -Service 'Graph' -Status 'Started' `
            -ReasonKey "reconnect-$guardReason" -Detail $guardDetail
        try {
            Connect-MgGraph -TenantId $targetTenantDomain -Scopes $requiredScopes `
                -NoWelcome -ErrorAction Stop
            Add-EntraConnectGuardLog -Service 'Graph' -Status 'Info' `
                -ReasonKey 'connected' -Detail $guardDetail
        }
        catch {
            Add-EntraConnectGuardLog -Service 'Graph' -Status 'Failed' `
                -ReasonKey 'connect-failed' -Detail @{ error = $_.Exception.Message }
            throw
        }
    }

    $tenantIdentity = Get-EntraTenantIdentity -ExpectedDomain $targetTenantDomain `
        -TenantAdminUpn $TenantAdminUpn -GraphBaseUri $GraphBaseUri
}

[pscustomobject]@{
    TenantAdminUpn = $TenantAdminUpn
    TenantId = if ($tenantIdentity) { $tenantIdentity.TenantId } else { $null }
    DelegatedOrganization = $DelegatedOrganization
    GraphConnected = [bool]$ConnectGraph
    GraphBaseUri = $GraphBaseUri
    TenantIdentity = $tenantIdentity
}
