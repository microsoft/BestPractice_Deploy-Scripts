#requires -Version 7.0
<#
.SYNOPSIS
    Read-only Intune capability, license, and readiness checks.

.DESCRIPTION
    Establishes what the tenant can support before any state-changing module
    runs, and records an explicit disposition for every configured baseline
    item. Items whose licence capability is absent are recorded as Skipped with
    the reason rather than silently omitted.

    Items that Microsoft does not expose through a stable, least-privilege,
    unattended path are recorded as GuidedOnly and are never attempted.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
# smb-quality-gate: read-only
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [Parameter(Mandatory)] [string] $TenantAdminUpn,
    [switch] $NoLicenseAutoDetect
)

. (Join-Path $PSScriptRoot 'IntuneRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'IntuneGraphClient.ps1')

function Get-IntuneLicenseInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $GraphBaseUri
    )

    try {
        $uri = Resolve-IntuneGraphUri -BaseUri $GraphBaseUri `
            -RelativePath 'subscribedSkus?$select=skuId,skuPartNumber,capabilityStatus,consumedUnits,prepaidUnits,servicePlans'
        $response = Invoke-WithTransientRetry -Description 'Get subscribed SKUs' -Action {
            Invoke-IntuneGraphRequest -Method 'GET' -Uri $uri `
                -EvidenceTarget 'subscribed SKUs' `
                -DeferFailureEvidence
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
        $status = Get-IntuneHttpStatusCode -ErrorRecord $_
        Add-IntuneRunLogEntry -Module 'Setup-IntunePreflight' `
            -Action 'LicenseCheck' -Status 'Failed' -HttpStatusCode $status `
            -Detail $_.Exception.Message
        throw
    }
}

function Test-IntuneLicenseCapability {
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

function Test-IntuneApiCapability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $ApiDefinition
    )

    $missing = @($ApiDefinition.RequiredCommands | Where-Object {
        -not (Get-Command -Name $_ -ErrorAction SilentlyContinue)
    })
    if ($missing.Count -gt 0) {
        throw "Required Intune API commands are unavailable: $($missing -join ', ')"
    }

    $graphContext = Get-MgContext
    if (-not $graphContext) {
        throw 'Microsoft Graph context is not available after connection.'
    }
    $account = Protect-IntuneIdentity -Value ([string] $graphContext.Account)
    Add-IntuneRunLogEntry -Module 'Setup-IntunePreflight' `
        -Action 'ApiCapability' -Status 'Succeeded' `
        -Detail "Graph context available. AuthenticationType=$($graphContext.AuthType); Account=$account."
}

function Write-IntuneGuidedReadiness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Action,
        [Parameter(Mandatory)] [string] $Detail,
        [string] $BestPracticeKey,
        [ValidateSet('Applicable','AlreadyCompliant','WillChange','GuidedOnly','Skipped','Blocked')]
        [string] $Disposition = 'GuidedOnly'
    )

    $entry = @{
        Module = 'Setup-IntunePreflight'
        Action = $Action
        Status = 'Info'
        Disposition = $Disposition
        Detail = $Detail
    }
    if ($BestPracticeKey) { $entry['BestPracticeKey'] = $BestPracticeKey }
    Add-IntuneRunLogEntry @entry
}

Add-IntuneRunLogEntry -Module 'Setup-IntunePreflight' `
    -Action 'Preflight' -Status 'Started' -Detail 'Read-only capability checks started.'

# Baseline items whose licence capability is absent. Written out at the end so
# the orchestrator can stop later modules acting on them. Recording a finding
# without being able to act on it is not a preflight, it is a comment.
$unavailableKeys = @()

try {
    if (-not $Context) {
        throw 'Setup-IntunePreflight.ps1 requires -Context from a pre-authenticated Graph connection. Run it through Deploy-IntuneBestPractice.ps1 (the orchestrator), or connect to Microsoft Graph yourself and supply -Context.'
    }
    Test-IntuneApiCapability -ApiDefinition $Config.Api

    if (-not $NoLicenseAutoDetect) {
        $inventory = Get-IntuneLicenseInventory -GraphBaseUri $Config.Api.GraphBaseUri
        Add-IntuneRunLogEntry -Module 'Setup-IntunePreflight' `
            -Action 'LicenseCheck' -Status 'Succeeded' `
            -Detail "Retrieved $(@($inventory).Count) subscribed SKU records."

        foreach ($item in @($Config.BestPracticeItems | Sort-Object Priority, GuideTask)) {
            $capabilityKey = [string] $item.LicenseCapability
            $definition = $Config.LicenseCapabilities[$capabilityKey]
            if (-not $definition) {
                Add-IntuneRunLogEntry -Module $item.Module `
                    -Action 'LicenseDisposition' -BestPracticeKey $item.Key `
                    -Status 'Skipped' -Disposition 'GuidedOnly' `
                    -Detail 'No configured license capability mapping; treat as GuidedOnly.'
                continue
            }
            $result = Test-IntuneLicenseCapability `
                -CapabilityDefinition $definition -Inventory $inventory
            $disposition = if ($result.Available) { 'Applicable' } else { 'Skipped' }
            # An unavailable capability is a skipped outcome, not an
            # informational one. Recording it as Info left it uncounted in the
            # report's skipped total and made the run look cleaner than it was.
            $status = if ($result.Available) { 'Info' } else { 'Skipped' }
            if (-not $result.Available) { $unavailableKeys += $item.Key }
            Add-IntuneRunLogEntry -Module $item.Module `
                -Action 'LicenseDisposition' -BestPracticeKey $item.Key `
                -Status $status -Disposition $disposition `
                -Detail "Disposition=$disposition; Priority=$($item.Priority); LicenseCapability=$capabilityKey; IdentifiedSubscriptions=$(@($result.Identified).Count); EnabledSubscriptions=$(@($result.Matches).Count)."
        }
    }
    else {
        Add-IntuneRunLogEntry -Module 'Setup-IntunePreflight' `
            -Action 'LicenseCheck' -Status 'Skipped' `
            -Detail 'Automatic license detection disabled by NoLicenseAutoDetect.'
    }

    # Managed Google Play requires a human credential and an interactive browser
    # flow. There is no unattended path, so the toolkit records the requirement
    # and never attempts it.
    Write-IntuneGuidedReadiness -Action 'ManagedGooglePlay' `
        -BestPracticeKey 'managed-google-play' `
        -Disposition $Config.Preflight.ManagedGooglePlayDisposition `
        -Detail 'Managed Google Play binding is GuidedOnly. In the Intune admin center, use Devices > Device onboarding > Enrollment > Android > Managed Google Play with a customer-controlled Microsoft Entra account that has an active mailbox and either Intune Administrator or custom Intune organization read and update permissions. Complete the interactive Google consent flow, add a second Google enterprise owner, and verify that the four core Android apps appear in Intune. GDAP does not replace the customer-owned Google identity or interactive consent.'

    # These two remain guided until a supported, generally available API
    # surface is verified and documented in the product supportability record.
    Write-IntuneGuidedReadiness -Action 'WindowsAutoEnrollment' `
        -BestPracticeKey 'windows-auto-enrollment' `
        -Disposition $Config.Preflight.WindowsAutoEnrollmentDisposition `
        -Detail 'Windows automatic MDM enrollment scope has no verified supported API in this product yet. Leave the Windows Information Protection scope set to None; WIP is deprecated.'
    Write-IntuneGuidedReadiness -Action 'EnterpriseStateRoaming' `
        -BestPracticeKey 'enterprise-state-roaming' `
        -Disposition $Config.Preflight.EnterpriseStateRoamingDisposition `
        -Detail 'Enterprise State Roaming management moved to Windows Backup for Organizations after June 2026. In the Intune admin center, use Devices > Device onboarding > Enrollment > Windows > Windows Backup and Restore; the former Entra portal path is obsolete. Automated policy creation remains blocked pending API, assignment, readback, and rollback verification.'

    Write-IntuneGuidedReadiness -Action 'EmergencyAccessSafety' `
        -Disposition $Config.Preflight.EmergencyAccessDisposition `
        -Detail 'Emergency-access account coverage and break-glass exclusions require operator confirmation before any Conditional Access enforcement.'

    # The combined effect of these two items is an access denial, and the
    # ordering is what makes it safe or unsafe. This is operator guidance, not
    # a blocked action, so it is recorded as informational. A Blocked
    # disposition on a successful step would be success-shaped evidence of a
    # block that never happened.
    Add-IntuneRunLogEntry -Module 'Setup-IntunePreflight' `
        -Action 'EnforcementCoupling' -Status 'Info' `
        -Detail 'Marking unevaluated devices as not compliant is inert until a device-based Conditional Access policy exists, and becomes an access denial once it does. Apply compliance policies and confirm device evaluation before enabling Conditional Access enforcement.'

    # Persist the applicability outcome so the orchestrator can act on it.
    # Modules run as separate processes, so an in-memory result would not
    # survive the process boundary.
    if ($Context.ApplicabilityPath) {
        $applicability = [ordered]@{
            generatedUtc = [datetime]::UtcNow.ToString('o')
            unavailableItemKeys = @($unavailableKeys)
        }
        $applicabilityDirectory = Split-Path -Parent $Context.ApplicabilityPath
        if ($applicabilityDirectory -and -not (Test-Path -LiteralPath $applicabilityDirectory)) {
            New-Item -ItemType Directory -Path $applicabilityDirectory -Force -WhatIf:$false | Out-Null
        }
        $applicability | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $Context.ApplicabilityPath -Encoding utf8 -WhatIf:$false
    }

    Add-IntuneRunLogEntry -Module 'Setup-IntunePreflight' `
        -Action 'Preflight' -Status 'Succeeded' `
        -Detail "Preflight framework completed without state changes. UnavailableItems=$(@($unavailableKeys).Count)."
}
catch {
    $status = Get-IntuneHttpStatusCode -ErrorRecord $_
    Add-IntuneRunLogEntry -Module 'Setup-IntunePreflight' `
        -Action 'Preflight' -Status 'Failed' -HttpStatusCode $status `
        -Detail $_.Exception.Message
    throw
}
