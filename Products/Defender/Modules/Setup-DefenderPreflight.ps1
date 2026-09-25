#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
# smb-quality-gate: read-only
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [Parameter(Mandatory)] [string] $TenantAdminUpn
)

. (Join-Path $PSScriptRoot 'DefenderRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'Get-DefenderPermissionPlan.ps1')

function Test-DefenderApiCapability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $ApiDefinition,
        [Parameter(Mandatory)] [string] $TenantAdminUpn
    )

    $missing = @($ApiDefinition.RequiredCommands | Where-Object {
        -not (Get-Command -Name $_ -ErrorAction SilentlyContinue)
    })
    if ($missing.Count -gt 0) {
        throw "Required Defender API commands are unavailable: $($missing -join ', ')"
    }

    $graphContext = Get-MgContext
    if (-not $graphContext) {
        throw 'Microsoft Graph context is not available after connection.'
    }
    Assert-DefenderGraphAccount -GraphContext $graphContext -TenantAdminUpn $TenantAdminUpn
    $account = Protect-DefenderIdentity -Value ([string] $graphContext.Account)
    Add-DefenderRunLogEntry -Module 'Setup-DefenderPreflight' `
        -Action 'ApiCapability' -Status 'Succeeded' `
        -Detail "Graph context available. AuthenticationType=$($graphContext.AuthType); Account=$account."
}

function Write-DefenderGuidedReadiness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Action,
        [Parameter(Mandatory)] [string] $Detail,
        [ValidateSet('Applicable','AlreadyCompliant','WillChange','GuidedOnly','Skipped','Blocked')]
        [string] $Disposition = 'GuidedOnly'
    )

    Add-DefenderRunLogEntry -Module 'Setup-DefenderPreflight' `
        -Action $Action -Status 'Info' -Disposition $Disposition `
        -Detail $Detail
}

function Write-DefenderWorkloadCapabilities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Capabilities
    )

    foreach ($capability in @($Capabilities)) {
        $status = if ([string] $capability.Status -eq 'Verified') {
            'Succeeded'
        }
        else {
            'Skipped'
        }
        $disposition = if ([string] $capability.Status -eq 'Verified') {
            'Applicable'
        }
        else {
            'GuidedOnly'
        }
        Add-DefenderRunLogEntry -Module 'Setup-DefenderPreflight' `
            -Action 'WorkloadCapability' -Status $status `
            -Disposition $disposition -Detail (
                "Capability=$($capability.Key); Workload=$($capability.Workload); " +
                "Mode=$($capability.Mode); $($capability.Detail)"
            )
    }
}

Add-DefenderRunLogEntry -Module 'Setup-DefenderPreflight' `
    -Action 'Preflight' -Status 'Started' -Detail 'Read-only capability checks started.'

try {
    if (-not $Context) {
        throw 'Setup-DefenderPreflight.ps1 requires -Context for Graph authentication. Run it through Deploy-DefenderBestPractice.ps1 (the orchestrator) or provide -Context with the required connection settings.'
    }
    $connectScript = Join-Path $PSScriptRoot 'Connect-DefenderServices.ps1'
    if ($Context.NonInteractive -and
        ([string]::IsNullOrWhiteSpace([string] $Context.ClientId) -or
         [string]::IsNullOrWhiteSpace([string] $Context.CertificateThumbprint) -or
         [string]::IsNullOrWhiteSpace([string] $Context.TenantId))) {
        throw 'Setup-DefenderPreflight.ps1 requires TenantId, ClientId, and CertificateThumbprint for noninteractive Graph authentication; delegated sign-in cannot prompt.'
    }
    $connectArgs = @{
        TenantAdminUpn = $TenantAdminUpn
        TenantId = $Context.TenantId
        ClientId = $Context.ClientId
        CertificateThumbprint = $Context.CertificateThumbprint
        DelegatedOrganization = $Context.DelegatedOrganization
        NonInteractive = [bool] $Context.NonInteractive
        ConnectGraph = $true
        GraphScopes = @($Context.PermissionPlan.GraphDelegatedScopes)
    }
    # Dot-sourcing retains the verified Graph request helper in this module's
    # current runspace. The orchestrator invokes this script as a separate
    # script invocation, not as a child PowerShell process.
    . $connectScript @connectArgs | Out-Null
    Test-DefenderApiCapability -ApiDefinition $Config.Api -TenantAdminUpn $TenantAdminUpn
    Write-DefenderWorkloadCapabilities -Capabilities $Config.WorkloadCapabilities

    foreach ($item in @($Config.BestPracticeItems)) {
        $capabilityKey = [string] $item.LicenseCapability
        $definition = $Config.LicenseCapabilities[$capabilityKey]
        if (-not $definition) {
            Add-DefenderRunLogEntry -Module $item.Module `
                -Action 'LicenseDocumentation' -BestPracticeKey $item.Key `
                -Status 'Info' -Disposition 'GuidedOnly' `
                -Detail 'No licensing documentation mapping is configured.'
            continue
        }
        Add-DefenderRunLogEntry -Module $item.Module `
            -Action 'LicenseDocumentation' -BestPracticeKey $item.Key `
            -Status 'Info' -Disposition 'GuidedOnly' `
            -Detail "Licensing prerequisite is documented only; no SKU entitlement inference is performed. Requirement=$($definition.Requirement); Documentation=$($definition.DocumentationUrl)"
    }
    Write-DefenderGuidedReadiness -Action 'AuditReadiness' `
        -Disposition $Config.Preflight.AuditReadinessDisposition `
        -Detail 'Audit readiness requires tenant-specific retention and audit policy review; no stable least-privilege unattended check is claimed.'
    Write-DefenderGuidedReadiness -Action 'EmergencyAccessSafety' `
        -Disposition $Config.Preflight.EmergencyAccessDisposition `
        -Detail 'Emergency-access account coverage and break-glass exclusions require operator confirmation before enforcement.'

    Add-DefenderRunLogEntry -Module 'Setup-DefenderPreflight' `
        -Action 'Preflight' -Status 'Succeeded' `
        -Detail 'Preflight framework completed without state changes.'
}
catch {
    $status = Get-DefenderHttpStatusCode -ErrorRecord $_
    Add-DefenderRunLogEntry -Module 'Setup-DefenderPreflight' `
        -Action 'Preflight' -Status 'Failed' -HttpStatusCode $status `
        -Detail $_.Exception.Message
    throw
}
