#requires -Version 7.0
<#
.SYNOPSIS
    Establishes the delegated Microsoft Graph connection required by Intune.

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
    Product-specific delegated Graph scopes supplied from IntuneConfig.psd1.

.PARAMETER AutoInstallModules
    Installs missing Microsoft Graph modules to CurrentUser without prompting.
    DeviceManagement is pinned to the Authentication version used by this run.

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

. (Join-Path $PSScriptRoot 'IntuneRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'IntuneGraphClient.ps1')

function Add-IntuneConnectGuardLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Service,
        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Started', 'Retried', 'Failed')]
        [string] $Status,
        [Parameter(Mandatory)] [string] $ReasonKey,
        [hashtable] $Detail
    )

    if (-not (Get-Command Add-IntuneRunLogEntry -ErrorAction SilentlyContinue)) {
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

    Add-IntuneRunLogEntry -Module 'Connect-IntuneServices' `
        -Action "SessionGuard:$Service" -Status $Status `
        -Detail ($parts -join '; ')
}

function Test-IntuneIsAdmin {
    try {
        $current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Ensure-IntuneRequiredModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [string] $RequiredCmdlet,
        [version] $RequiredVersion,
        [switch] $AutoInstall,
        [switch] $NonInteractive
    )

    $loaded = @(Get-Module -Name $Name -ErrorAction SilentlyContinue | Where-Object { $null -ne $_ })
    if ($loaded.Count -gt 1 -or ($RequiredVersion -and @($loaded | Where-Object Version -ne $RequiredVersion).Count -gt 0)) {
        throw "Module '$Name' is already loaded with an incompatible version. Open a fresh PowerShell 7 session and rerun the toolkit before importing other Graph modules. Required version: $RequiredVersion; loaded: $($loaded.Version -join ', ')."
    }
    if (-not $RequiredVersion -and $loaded.Count -eq 1) {
        $RequiredVersion = $loaded[0].Version
    }
    $available = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue |
        Where-Object { $null -ne $_ -and (-not $RequiredVersion -or $_.Version -eq $RequiredVersion) } |
        Sort-Object Version -Descending | Select-Object -First 1
    if ($available) { $RequiredVersion = $available.Version }
    $versionArgument = if ($RequiredVersion) { "-RequiredVersion $RequiredVersion " } else { '' }
    $manual = "Install-Module $Name ${versionArgument}-Scope CurrentUser -Force -AllowClobber"

    if (-not $available) {
        $versionLabel = if ($RequiredVersion) { " v$RequiredVersion" } else { '' }
        Write-Warning "Required module '$Name'$versionLabel is not installed."
        $shouldInstall = $AutoInstall.IsPresent
        if (-not $shouldInstall -and $NonInteractive.IsPresent) {
            throw "Module '$Name'$versionLabel is required and -NonInteractive is set (cannot prompt). Pre-install the matching module or rerun with -AutoInstallModules:`n    $manual"
        }
        if (-not $shouldInstall) {
            $response = Read-Host "Install '$Name'$versionLabel from PSGallery now to the current user scope? [Y/n]"
            $shouldInstall = [string]::IsNullOrWhiteSpace($response) -or $response -match '^(y|yes)$'
        }
        if (-not $shouldInstall) {
            throw "Module '$Name'$versionLabel is required but was not installed. Install manually and rerun:`n    $manual"
        }
        if (-not (Test-IntuneIsAdmin)) {
            Write-Host '  Installing to CurrentUser; elevation is not required.' -ForegroundColor DarkGray
        }
        $installArgs = @{ Name = $Name; Scope = 'CurrentUser'; Force = $true; AllowClobber = $true; ErrorAction = 'Stop' }
        if ($RequiredVersion) { $installArgs.RequiredVersion = $RequiredVersion }
        try { Install-Module @installArgs }
        catch { throw "Failed to install module '$Name': $($_.Exception.Message)`nRetry the approved installation manually:`n    $manual" }

        $available = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue |
            Where-Object { $null -ne $_ -and (-not $RequiredVersion -or $_.Version -eq $RequiredVersion) } |
            Sort-Object Version -Descending | Select-Object -First 1
        if (-not $available) { throw "Module '$Name' is still unavailable after installation. Open a fresh PowerShell 7 session and verify:`n    $manual" }
        $RequiredVersion = $available.Version
    }

    try {
        # A newer side-by-side SDK module may require a different Authentication assembly.
        Import-Module -Name $Name -RequiredVersion $RequiredVersion -DisableNameChecking -ErrorAction Stop | Out-Null
    }
    catch {
        throw "Could not import '$Name' v$RequiredVersion. Open a fresh PowerShell 7 session and rerun the toolkit before importing other Graph modules. Loaded assemblies cannot be replaced in this session. If needed, repair the matching installation with:`n    Install-Module $Name -RequiredVersion $RequiredVersion -Scope CurrentUser -Force -AllowClobber`nOriginal error: $($_.Exception.Message)"
    }
    if ($RequiredCmdlet -and -not (Get-Command $RequiredCmdlet -ListImported -ErrorAction SilentlyContinue)) {
        throw "Module '$Name' v$RequiredVersion was imported but cmdlet '$RequiredCmdlet' is unavailable. Open a fresh PowerShell 7 session and repair the module installation."
    }
    return $RequiredVersion
}

function Test-IntuneWamBrokerReadiness {
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

    $graphModule = Get-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $graphModule) {
        $graphModule = Get-Module Microsoft.Graph.Authentication -ListAvailable -ErrorAction SilentlyContinue |
            Sort-Object Version -Descending | Select-Object -First 1
    }
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

function Get-IntuneTenantIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ExpectedDomain,
        [Parameter(Mandatory)] [string] $TenantAdminUpn,
        [Parameter(Mandatory)] [string] $GraphBaseUri
    )

    try {
        $organizationUri = Resolve-IntuneGraphUri -BaseUri $GraphBaseUri `
            -RelativePath 'organization?$select=id,verifiedDomains'
        $response = Invoke-IntuneGraphRequest -Method 'GET' -Uri $organizationUri `
            -EvidenceTarget 'tenant organization'
        $organization = @($response.value)[0]
        if (-not $organization -or [string]::IsNullOrWhiteSpace([string]$organization.id)) {
            throw 'Microsoft Graph returned no tenant organization identity.'
        }
        $domains = @($organization.verifiedDomains | ForEach-Object { $_.name.ToLowerInvariant() })
        # Register before the comparison so a mismatch failure cannot quote an
        # unregistered tenant domain in its evidence.
        Register-IntuneSensitiveValue -Value $domains
        $expected = $ExpectedDomain.ToLowerInvariant()
        if ($domains -notcontains $expected) {
            throw 'Connected tenant does not contain the expected verified domain.'
        }

        Add-IntuneRunLogEntry -Module 'Connect-IntuneServices' `
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
        $status = Get-IntuneHttpStatusCode -ErrorRecord $_
        Add-IntuneRunLogEntry -Module 'Connect-IntuneServices' `
            -Action 'TenantIdentity' -Status 'Failed' `
            -HttpStatusCode $status -Detail $_.Exception.Message
        throw
    }
}

$tenantIdentity = $null
if ($ConnectGraph) {
    Register-IntuneSensitiveValue -Value $DelegatedOrganization
    if ($TenantAdminUpn -notmatch '@(?<domain>[^@\s]+)$') {
        throw 'Unable to derive an expected tenant domain from TenantAdminUpn.'
    }
    $upnDomain = $Matches.domain
    Register-IntuneSensitiveValue -Value $upnDomain
    $targetTenantDomain = if ($DelegatedOrganization) { $DelegatedOrganization } else { $upnDomain }

    $wamReadiness = Test-IntuneWamBrokerReadiness
    if ($wamReadiness.Eligible) {
        Write-Host "WAM broker available: Graph sign-in should usually use a one-click 'Continue' prompt." -ForegroundColor DarkGray
    }
    else {
        Write-Warning 'Windows Authentication Manager (WAM) is not fully usable; expect a browser sign-in.'
        foreach ($issue in $wamReadiness.Issues) { Write-Warning "  * $issue" }
    }
    Add-IntuneConnectGuardLog -Service 'Startup' -Status 'Info' `
        -ReasonKey $(if ($wamReadiness.Eligible) { 'wam-ready' } else { 'wam-not-ready' }) `
        -Detail $wamReadiness.Info

    try {
        $authVersion = Ensure-IntuneRequiredModule -Name 'Microsoft.Graph.Authentication' `
            -RequiredCmdlet 'Connect-MgGraph' -AutoInstall:$AutoInstallModules `
            -NonInteractive:$NonInteractive
        $null = Ensure-IntuneRequiredModule -Name 'Microsoft.Graph.DeviceManagement' `
            -RequiredVersion $authVersion -RequiredCmdlet 'Get-MgDeviceManagement' `
            -AutoInstall:$AutoInstallModules -NonInteractive:$NonInteractive
        Add-IntuneConnectGuardLog -Service 'Prerequisites' -Status 'Info' `
            -ReasonKey 'graph-modules-aligned' -Detail @{ graphModuleVersion = $authVersion.ToString() }
    }
    catch {
        Add-IntuneConnectGuardLog -Service 'Prerequisites' -Status 'Failed' `
            -ReasonKey 'module-readiness-failed' -Detail @{ error = $_.Exception.Message }
        throw
    }

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
                # Verified for every run, not only GDAP: an account/scope match
                # alone does not prove the cached context is connected to the
                # intended tenant (the same delegated account can hold a Graph
                # context for a different tenant it was previously connected
                # to). Fail closed and reconnect whenever /organization cannot
                # confirm the target tenant domain.
                $tenantMatches = $false
                try {
                    $organizationUri = Resolve-IntuneGraphUri -BaseUri $GraphBaseUri `
                        -RelativePath 'organization?$select=verifiedDomains'
                    $response = Invoke-IntuneGraphRequest -Method 'GET' -Uri $organizationUri `
                        -EvidenceTarget 'cached tenant organization'
                    $domains = @($response.value.verifiedDomains | ForEach-Object { $_.name.ToLowerInvariant() })
                    Register-IntuneSensitiveValue -Value $domains
                    $tenantMatches = $domains -contains $targetTenantDomain.ToLowerInvariant()
                    if (-not $tenantMatches) { $guardReason = 'tenant-domain-mismatch' }
                }
                catch {
                    $tenantMatches = $false
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
                Add-IntuneConnectGuardLog -Service 'Graph' -Status 'Retried' `
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
        Add-IntuneConnectGuardLog -Service 'Graph' -Status 'Info' `
            -ReasonKey 'reused' -Detail $guardDetail
    }
    else {
        Add-IntuneConnectGuardLog -Service 'Graph' -Status 'Started' `
            -ReasonKey "reconnect-$guardReason" -Detail $guardDetail
        try {
            Connect-MgGraph -TenantId $targetTenantDomain -Scopes $requiredScopes `
                -NoWelcome -ErrorAction Stop
            Add-IntuneConnectGuardLog -Service 'Graph' -Status 'Info' `
                -ReasonKey 'connected' -Detail $guardDetail
        }
        catch {
            Add-IntuneConnectGuardLog -Service 'Graph' -Status 'Failed' `
                -ReasonKey 'connect-failed' -Detail @{ error = $_.Exception.Message }
            throw
        }
    }

    $tenantIdentity = Get-IntuneTenantIdentity -ExpectedDomain $targetTenantDomain `
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
