#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [Parameter(Mandatory)] [string] $TenantAdminUpn,
    [string] $TenantId,
    [switch] $NoLicenseAutoDetect
)

. (Join-Path $PSScriptRoot 'DefenderRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')

function Get-DefenderLicenseInventory {
    [CmdletBinding()]
    param()

    try {
        $uri = 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber,capabilityStatus,consumedUnits,prepaidUnits,servicePlans'
        $response = Invoke-WithTransientRetry -Description 'Get subscribed SKUs' -Action {
            Invoke-DefenderGraphRequest -Method 'GET' -Uri $uri
        }
        $records = @($response.value | ForEach-Object {
            [pscustomobject]@{
                SkuId = $_.skuId
                SkuPartNumber = [string] $_.skuPartNumber
                CapabilityStatus = [string] $_.capabilityStatus
                ConsumedUnits = [int] $_.consumedUnits
                PrepaidUnitsEnabled = [int] $_.prepaidUnits.enabled
                ServicePlanNames = @($_.servicePlans | ForEach-Object { [string] $_.servicePlanName })
            }
        })
        if ($records.Count -eq 0) {
            throw 'Microsoft Graph returned no subscribed SKU records; license readiness is unknown.'
        }
        return $records
    }
    catch {
        $status = Get-DefenderHttpStatusCode -ErrorRecord $_
        Add-DefenderRunLogEntry -Module 'Setup-DefenderPreflight' `
            -Action 'LicenseCheck' -Status 'Failed' -HttpStatusCode $status `
            -Detail $_.Exception.Message
        throw
    }
}

function Test-DefenderLicenseCapability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $CapabilityDefinition,
        [Parameter(Mandatory)] [object[]] $Inventory
    )

    $identified = @($Inventory | Where-Object {
        ($_.SkuPartNumber -in @($CapabilityDefinition.SkuPartNumbers)) -or
        (@($_.ServicePlanNames) | Where-Object {
            $_ -in @($CapabilityDefinition.ServicePlanNames)
        })
    })
    $skuMatches = @($identified | Where-Object {
        $_.CapabilityStatus -eq 'Enabled' -and
        ($_.ConsumedUnits -gt 0 -or $_.PrepaidUnitsEnabled -gt 0)
    })
    return [pscustomobject]@{
        Available = $skuMatches.Count -gt 0
        Matches = $skuMatches
        Identified = $identified
    }
}

function Test-DefenderApiCapability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $ApiDefinition
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
    Add-DefenderRunLogEntry -Module 'Setup-DefenderPreflight' `
        -Action 'ApiCapability' -Status 'Succeeded' `
        -Detail "Graph context available. AuthenticationType=$($graphContext.AuthType); Account=$($graphContext.Account)."
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

Add-DefenderRunLogEntry -Module 'Setup-DefenderPreflight' `
    -Action 'Preflight' -Status 'Started' -Detail 'Read-only capability checks started.'

try {
    if (-not $Context) {
        throw 'F6 requires orchestrator context for Graph authentication.'
    }
    $connectScript = Join-Path $PSScriptRoot 'Connect-DefenderServices.ps1'
    if ($Context.NonInteractive -and
        ([string]::IsNullOrWhiteSpace([string] $Context.ClientId) -or
         [string]::IsNullOrWhiteSpace([string] $Context.CertificateThumbprint) -or
         [string]::IsNullOrWhiteSpace([string] $Context.TenantId))) {
        throw 'NonInteractive F6 requires certificate authentication parameters; delegated sign-in cannot prompt.'
    }
    $connectArgs = @{
        TenantAdminUpn = $TenantAdminUpn
        TenantId = $Context.TenantId
        ClientId = $Context.ClientId
        CertificateThumbprint = $Context.CertificateThumbprint
        DelegatedOrganization = $Context.DelegatedOrganization
        NonInteractive = $true
        ConnectGraph = $true
    }
    # Dot-sourcing retains the verified Graph request helper in this
    # independently running module process.
    . $connectScript @connectArgs | Out-Null
    Test-DefenderApiCapability -ApiDefinition $Config.Api

    if (-not $NoLicenseAutoDetect) {
        $inventory = Get-DefenderLicenseInventory
        Add-DefenderRunLogEntry -Module 'Setup-DefenderPreflight' `
            -Action 'LicenseCheck' -Status 'Succeeded' `
            -Detail "Retrieved $(@($inventory).Count) subscribed SKU records."

        foreach ($item in @($Config.BestPracticeItems)) {
            $capabilityKey = [string] $item.LicenseCapability
            $definition = $Config.LicenseCapabilities[$capabilityKey]
            if (-not $definition) {
                Add-DefenderRunLogEntry -Module $item.Module `
                    -Action 'Disposition' -BestPracticeKey $item.Key `
                        -Status 'Skipped' -Disposition 'GuidedOnly' `
                    -Detail 'No configured license capability mapping; treat as GuidedOnly.'
                continue
            }
            $result = Test-DefenderLicenseCapability `
                -CapabilityDefinition $definition -Inventory $inventory
            $disposition = if ($result.Available) { 'Applicable' } else { 'Skipped' }
            Add-DefenderRunLogEntry -Module $item.Module `
                -Action 'Disposition' -BestPracticeKey $item.Key `
                -Status 'Info' -Disposition $disposition `
                -Detail "Disposition=$disposition; LicenseCapability=$capabilityKey; IdentifiedSubscriptions=$(@($result.Identified).Count); EnabledSubscriptions=$(@($result.Matches).Count)."
        }

    }
    else {
        Add-DefenderRunLogEntry -Module 'Setup-DefenderPreflight' `
            -Action 'LicenseCheck' -Status 'Skipped' `
            -Detail 'Automatic license detection disabled by NoLicenseAutoDetect.'
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
