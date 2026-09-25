#requires -Version 7.0
<#
.SYNOPSIS
    Read-only service connections for Purview configuration validation.

.DESCRIPTION
    A dedicated least-privilege profile rather than a reuse of the deployment
    connection. The deployment profile requests write scopes so it can create
    labels, policies, and directory settings. Validation only reads, so asking
    for those scopes would ask an operator to consent to permissions the run
    cannot use.

    Requested delegated Microsoft Graph scopes:

      * Organization.Read.All        read /organization for tenant identity
      * GroupSettings.Read.All       read the Group.Unified directory setting

    The narrower Graph scopes are the least-privileged permissions Microsoft
    documents for those reads. See the Permissions section in
    ../docs/Configuration-Validation.md for the public connection boundary.

    Exchange Online, Security & Compliance, and SharePoint Online do not offer
    per-operation delegated scopes. The operator's directory role governs what
    those sessions can read. Service-role mappings still need pilot
    verification; the public validation guide records that limitation.

    This script connects and verifies. It never writes.

.PARAMETER TenantAdminUpn
    UPN used for sign-in.

.PARAMETER DelegatedOrganization
    Customer tenant primary domain when a partner signs in through GDAP.

.PARAMETER SharePointAdminUrl
    Explicit SharePoint admin URL. Required for multi-geo, renamed tenants, or
    vanity-domain admin UPNs where the URL cannot be derived.

.PARAMETER ClientId
    Optional approved tenant-local public-client application ID. Use an
    isolated client whose delegated Microsoft Graph grant contains only the
    validator's two resource scopes. The script does not create or consent an
    application.

.PARAMETER UseDeviceAuthentication
    Use Microsoft Graph device authentication instead of the default browser
    flow. Useful in terminals that cannot provide a WAM parent window.

.PARAMETER NeedsSharePoint
    Connect SharePoint Online. Only required when the plan contains an action
    whose adapter reads Get-SPOTenant.

.PARAMETER NeedsGraph
    Connect Microsoft Graph. Required for tenant identity, entitlement, and the
    container-label directory setting.

.PARAMETER AutoInstallModules
    Install missing modules for the current user without prompting.

.PARAMETER NonInteractive
    Fail instead of prompting.

.OUTPUTS
    PSCustomObject describing which sessions were established and the resolved
    SharePoint admin URL.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $TenantAdminUpn,

    [Parameter()]
    [string] $DelegatedOrganization,

    [Parameter()]
    [string] $SharePointAdminUrl,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $ClientId,

    [Parameter()]
    [switch] $UseDeviceAuthentication,

    [Parameter()]
    [switch] $NeedsSharePoint,

    [Parameter()]
    [switch] $NeedsGraph,

    [Parameter()]
    [switch] $AutoInstallModules,

    [Parameter()]
    [switch] $NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Connecting is a precondition, not a change. Some auth flows respect
# $WhatIfPreference internally and silently skip work, which surfaces later as
# a confusing "no valid authentication session" error.
$WhatIfPreference = $false
$ConfirmPreference = 'None'

$_runLogPath = Join-Path $PSScriptRoot 'PurviewRunLog.ps1'
if (Test-Path -LiteralPath $_runLogPath) { . $_runLogPath }
$_tenantIdentityPath = Join-Path $PSScriptRoot 'PurviewTenantIdentity.ps1'
if (Test-Path -LiteralPath $_tenantIdentityPath) { . $_tenantIdentityPath }

# Least-privilege delegated scopes for the three Graph reads this tool makes.
$script:PurviewValidationGraphScopes = @(
    'Organization.Read.All'
    'GroupSettings.Read.All'
)

function Add-ValidationConnectLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Service,
        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Started', 'Succeeded', 'Skipped', 'Failed')]
        [string] $Status,
        [Parameter()] [string] $Detail = ''
    )

    if (-not (Get-Command -Name 'Add-RunLogEntry' -ErrorAction SilentlyContinue)) { return }
    try {
        Add-RunLogEntry -Module 'Connect-PurviewValidationServices' `
            -Action "Connect:$Service" -Status $Status -Detail $Detail
    } catch {
        Write-Verbose "Validation connect log failed: $($_.Exception.Message)"
    }
}

function Assert-ValidationModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $RequiredCmdlet
    )

    if (Get-Command -Name $RequiredCmdlet -ErrorAction SilentlyContinue) { return }
    if (Get-Module -ListAvailable -Name $Name) {
        Import-Module -Name $Name -ErrorAction Stop
        return
    }

    if (-not $AutoInstallModules) {
        if ($NonInteractive) {
            throw "Module '$Name' is required for validation reads and is not installed. Rerun with -AutoInstallModules or install it first."
        }
        $answer = Read-Host "Module '$Name' is required for validation reads. Install it for the current user now? (y/n)"
        if ($answer -notmatch '^(y|yes)$') {
            throw "Module '$Name' is required for validation reads."
        }
    }

    Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    Import-Module -Name $Name -ErrorAction Stop
}

$targetTenantDomain = if ($DelegatedOrganization) {
    $DelegatedOrganization
} else {
    ($TenantAdminUpn -split '@')[-1]
}

$graphConnected = $false
$sharePointConnected = $false

# Graph first. Microsoft Graph and Exchange Online ship different versions of
# the MSAL client library, and whichever loads first wins the process. Graph's
# credential types fail on Exchange Online's newer MSAL, so Graph must connect
# before Exchange Online does.
if ($NeedsGraph) {
    Assert-ValidationModule -Name 'Microsoft.Graph.Authentication' -RequiredCmdlet 'Connect-MgGraph'

    $reuse = $false
    $cachedScopeError = $null
    try {
        $context = Get-MgContext -ErrorAction Stop
        if ($context) {
            $contextCheck = Test-PurviewValidationGraphContext -Context $context `
                -ExpectedAccount $TenantAdminUpn `
                -RequiredScopes $script:PurviewValidationGraphScopes
            $reuse = $contextCheck.Matched
            if (-not $reuse) {
                $reason = if (-not $contextCheck.AccountMatched) {
                    'Cached account does not match the requested validation account.'
                } elseif ($contextCheck.MissingScopes.Count -gt 0) {
                    'Cached context is missing required validation scopes.'
                } else {
                    'Cached context contains Graph resource permissions outside the validation allowlist.'
                }
                Add-ValidationConnectLog -Service 'Graph' -Status 'Info' -Detail $reason
                try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
                if ($contextCheck.UnexpectedScopes.Count -gt 0) {
                    $cachedScopeError = (
                        'The existing Microsoft Graph context contains resource permissions outside ' +
                        "the validator allowlist: $($contextCheck.UnexpectedScopes -join ', '). " +
                        'Close this PowerShell process, open a fresh pwsh -NoProfile session, and rerun ' +
                        'the validator so it can request a new read-only token. If the fresh token is ' +
                        'still broader, use an approved tenant-local public client with -ClientId.')
                }
            }
        }
    } catch {
        $reuse = $false
    }
    if ($cachedScopeError) { throw $cachedScopeError }

    if ($reuse) {
        Add-ValidationConnectLog -Service 'Graph' -Status 'Info' -Detail 'Existing read-only session reused.'
        Write-Host 'Microsoft Graph: existing session reused.' -ForegroundColor DarkGray
    } else {
        Add-ValidationConnectLog -Service 'Graph' -Status 'Started' `
            -Detail ('Requesting read-only scopes: {0}' -f ($script:PurviewValidationGraphScopes -join ', '))
        Write-Host ('Connecting to Microsoft Graph with read-only scopes: {0}' -f `
            ($script:PurviewValidationGraphScopes -join ', ')) -ForegroundColor Cyan
        $graphArgs = @{
            TenantId = $targetTenantDomain
            Scopes = $script:PurviewValidationGraphScopes
            ContextScope = 'Process'
            NoWelcome = $true
            ErrorAction = 'Stop'
        }
        if ($ClientId) { $graphArgs['ClientId'] = $ClientId }
        if ($UseDeviceAuthentication) { $graphArgs['UseDeviceAuthentication'] = $true }
        Connect-MgGraph @graphArgs
        Add-ValidationConnectLog -Service 'Graph' -Status 'Succeeded'
    }

    $effectiveContext = Get-MgContext -ErrorAction Stop
    $effectiveCheck = Test-PurviewValidationGraphContext -Context $effectiveContext `
        -ExpectedAccount $TenantAdminUpn `
        -RequiredScopes $script:PurviewValidationGraphScopes
    if (-not $effectiveCheck.Matched) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        if ($effectiveCheck.UnexpectedScopes.Count -gt 0) {
            throw (
                'The newly authenticated Microsoft Graph context contains resource permissions outside ' +
                "the validator allowlist: $($effectiveCheck.UnexpectedScopes -join ', '). " +
                'The shared client or broker did not issue a read-only token. Use an approved ' +
                'tenant-local public client with only Organization.Read.All and ' +
                'GroupSettings.Read.All, then pass its application ID with -ClientId.')
        }
        if (-not $effectiveCheck.AccountMatched) {
            throw 'The effective Microsoft Graph account does not match -TenantAdminUpn.'
        }
        throw "The effective Microsoft Graph context is missing required scopes: $($effectiveCheck.MissingScopes -join ', ')."
    }
    $graphConnected = $true

    # The Group.Unified directory setting is read through the Graph beta
    # directory-setting commands, matching the surface the deployment writes.
    # Its absence is not fatal: the container-label action resolves to
    # 'Not evaluated' instead.
    try {
        Assert-ValidationModule -Name 'Microsoft.Graph.Beta.Identity.DirectoryManagement' `
            -RequiredCmdlet 'Get-MgBetaDirectorySetting'
    } catch {
        Add-ValidationConnectLog -Service 'GraphBeta' -Status 'Skipped' -Detail $_.Exception.Message
        Write-Warning "Container-label directory settings cannot be read: $($_.Exception.Message)"
    }
}

Assert-ValidationModule -Name 'ExchangeOnlineManagement' -RequiredCmdlet 'Connect-ExchangeOnline'

$exoArgs = @{
    UserPrincipalName = $TenantAdminUpn
    ShowBanner = $false
    ErrorAction = 'Stop'
}
if ($DelegatedOrganization) { $exoArgs['DelegatedOrganization'] = $DelegatedOrganization }
if ($graphConnected) { $exoArgs['DisableWAM'] = $true }

Add-ValidationConnectLog -Service 'ExchangeOnline' -Status 'Started'
Write-Host 'Connecting to Exchange Online...' -ForegroundColor Cyan
Connect-ExchangeOnline @exoArgs
Add-ValidationConnectLog -Service 'ExchangeOnline' -Status 'Succeeded'

$ippsArgs = @{
    UserPrincipalName = $TenantAdminUpn
    ErrorAction = 'Stop'
}
if ($DelegatedOrganization) { $ippsArgs['DelegatedOrganization'] = $DelegatedOrganization }
if ($graphConnected) { $ippsArgs['DisableWAM'] = $true }

Add-ValidationConnectLog -Service 'SecurityCompliance' -Status 'Started'
Write-Host 'Connecting to Security and Compliance PowerShell...' -ForegroundColor Cyan
Connect-IPPSSession @ippsArgs
Add-ValidationConnectLog -Service 'SecurityCompliance' -Status 'Succeeded'

if ($NeedsSharePoint) {
    try {
        Assert-ValidationModule -Name 'Microsoft.Online.SharePoint.PowerShell' `
            -RequiredCmdlet 'Connect-SPOService'

        if (-not $SharePointAdminUrl) {
            $initial = Get-AcceptedDomain -ErrorAction Stop |
                Where-Object { $_.InitialDomain } |
                Select-Object -First 1
            if (-not $initial) {
                throw 'No initial onmicrosoft.com domain was returned, so the SharePoint admin URL could not be derived.'
            }
            $prefix = ([string]$initial.DomainName -split '\.')[0]
            $SharePointAdminUrl = "https://$prefix-admin.sharepoint.com"
        }

        Add-ValidationConnectLog -Service 'SharePointOnline' -Status 'Started'
        Write-Host 'Connecting to SharePoint Online...' -ForegroundColor Cyan
        Connect-SPOService -Url $SharePointAdminUrl -ErrorAction Stop
        Add-ValidationConnectLog -Service 'SharePointOnline' -Status 'Succeeded'
        $sharePointConnected = $true
    } catch {
        # SharePoint reads back two tenant settings. Losing them should degrade
        # those two actions to 'Not evaluated', not abort a run that can still
        # assess the other sixteen.
        Add-ValidationConnectLog -Service 'SharePointOnline' -Status 'Failed' -Detail $_.Exception.Message
        Write-Warning "SharePoint Online could not be connected: $($_.Exception.Message)"
        Write-Warning 'Actions that read Get-SPOTenant will be reported as Not evaluated.'
    }
}

Write-Host 'Read-only validation sessions established.' -ForegroundColor Green

[pscustomobject]@{
    GraphConnected = $graphConnected
    ExchangeOnlineConnected = $true
    SecurityComplianceConnected = $true
    SharePointConnected = $sharePointConnected
    SharePointAdminUrl = if ($sharePointConnected) { $SharePointAdminUrl } else { $null }
    RequestedGraphScopes = @($script:PurviewValidationGraphScopes)
}
