#requires -Version 7.0
<#
.SYNOPSIS
    Enrollment prerequisites for supported device platforms (guide tasks 1-3).

.DESCRIPTION
    Read-only until each operation's supported API, permissions, licensing,
    readback, and recovery contract is verified. Covers Windows automatic MDM
    enrollment, the Apple MDM push certificate, and the managed Google Play
    connection.

    This module now performs a GET-only health assessment for the Apple MDM push
    certificate. Managed Google Play remains guided-only because it requires a
    human credential and an interactive browser flow with no unattended path.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
# smb-quality-gate: read-only
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context,
    [switch] $AdoptExisting
)

. (Join-Path $PSScriptRoot 'IntuneRunLog.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'IntuneGraphClient.ps1')

function ConvertTo-IntuneUtcDateTime {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [AllowNull()] [string] $Value,
        [Parameter(Mandatory)] [string] $FieldName
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Microsoft Graph returned no $FieldName value; Apple MDM push certificate state is unknown."
    }

    $parsed = [datetimeoffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor `
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [datetimeoffset]::TryParse(
            $Value,
            [System.Globalization.CultureInfo]::InvariantCulture,
            $styles,
            [ref] $parsed
        )) {
        throw "Microsoft Graph returned a malformed $FieldName value; Apple MDM push certificate state is unknown."
    }

    return $parsed.UtcDateTime
}

function Get-IntuneApplePushCertificateState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $GraphBaseUri
    )

    $uri = Resolve-IntuneGraphUri -BaseUri $GraphBaseUri `
        -RelativePath 'deviceManagement/applePushNotificationCertificate'
    $response = Invoke-WithTransientRetry `
        -Description 'Get Apple MDM push certificate' `
        -ExpectedStatusCodes @(404) `
        -Action {
            Invoke-IntuneGraphRequest -Method 'GET' -Uri $uri `
                -EvidenceTarget 'Apple MDM push certificate' `
                -ExpectedStatusCodes @(404) `
                -DeferFailureEvidence
        }

    if ($null -eq $response) {
        throw 'Microsoft Graph returned no Apple MDM push certificate response; certificate state is unknown.'
    }

    $expirationUtc = ConvertTo-IntuneUtcDateTime `
        -Value ([string] $response.expirationDateTime) `
        -FieldName 'expirationDateTime'
    $lastModifiedUtc = ConvertTo-IntuneUtcDateTime `
        -Value ([string] $response.lastModifiedDateTime) `
        -FieldName 'lastModifiedDateTime'

    return [pscustomobject]@{
        ExpirationDateTime = $expirationUtc
        LastModifiedDateTime = $lastModifiedUtc
        IsExpired = $expirationUtc -le [datetime]::UtcNow
    }
}

$bestPracticeKey = 'apple-push-certificate'

if ($Context -and @($Context.BlockedItemKeys) -contains $bestPracticeKey) {
    Add-IntuneRunLogEntry -Module 'Setup-EnrollmentPrerequisites' `
        -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
        -Status 'Skipped' -Disposition 'Skipped' `
        -Detail 'Skipped because preflight or operator gating blocked apple-push-certificate.'
    return
}

try {
    if (-not $Context) {
        throw 'Setup-EnrollmentPrerequisites.ps1 requires -Context from a pre-authenticated Graph connection. Run it through Deploy-IntuneBestPractice.ps1 (the orchestrator), or connect to Microsoft Graph yourself and supply -Context.'
    }

    if (-not $Config.ContainsKey('ApplePushCertificate') -or
        -not $Config.ApplePushCertificate.ContainsKey('RenewalWarningDays') -or
        $Config.ApplePushCertificate.RenewalWarningDays -isnot [int] -or
        $Config.ApplePushCertificate.RenewalWarningDays -lt 1 -or
        $Config.ApplePushCertificate.RenewalWarningDays -gt 90) {
        throw 'ApplePushCertificate.RenewalWarningDays must be an integer from 1 through 90.'
    }

    if ([string]::IsNullOrWhiteSpace([string] $Context.TenantAdminUpn)) {
        throw 'Setup-EnrollmentPrerequisites.ps1 requires Context.TenantAdminUpn for Graph authentication.'
    }

    $state = Get-IntuneApplePushCertificateState -GraphBaseUri $Config.Api.GraphBaseUri
    $renewalWarningDays = [int] $Config.ApplePushCertificate.RenewalWarningDays
    $renewalDue = -not $state.IsExpired -and
        $state.ExpirationDateTime -le [datetime]::UtcNow.AddDays($renewalWarningDays)
    $disposition = if ($state.IsExpired -or $renewalDue) { 'GuidedOnly' } else { 'AlreadyCompliant' }
    $detail = if ($state.IsExpired) {
        'Apple MDM push certificate has expired. Renew it through the supported annual workflow in the Intune admin center and the Apple Push Certificates Portal. ExpirationUtc={0}; LastModifiedUtc={1}.' -f `
            $state.ExpirationDateTime.ToString('o'),
            $state.LastModifiedDateTime.ToString('o')
    }
    elseif ($renewalDue) {
        'Apple MDM push certificate expires within the configured {0}-day renewal warning window. Renew it before expiration through the supported workflow in the Intune admin center and the Apple Push Certificates Portal. ExpirationUtc={1}; LastModifiedUtc={2}.' -f `
            $renewalWarningDays,
            $state.ExpirationDateTime.ToString('o'),
            $state.LastModifiedDateTime.ToString('o')
    }
    else {
        'Apple MDM push certificate is configured and unexpired. ExpirationUtc={0}; LastModifiedUtc={1}.' -f `
            $state.ExpirationDateTime.ToString('o'),
            $state.LastModifiedDateTime.ToString('o')
    }

    Add-IntuneRunLogEntry -Module 'Setup-EnrollmentPrerequisites' `
        -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
        -Status 'Succeeded' `
        -Disposition $disposition `
        -Detail $detail
}
catch {
    $status = Get-IntuneHttpStatusCode -ErrorRecord $_
    if ($status -eq 404) {
        Add-IntuneRunLogEntry -Module 'Setup-EnrollmentPrerequisites' `
            -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'GuidedOnly' `
            -HttpStatusCode $status `
            -Detail 'Microsoft Graph returned 404 for the Apple MDM push certificate singleton. Microsoft does not document this response, so it does not prove whether a certificate is configured. Verify the state in the Intune admin center and complete the supported Apple certificate setup or renewal workflow.'
        return
    }
    Add-IntuneRunLogEntry -Module 'Setup-EnrollmentPrerequisites' `
        -Action 'Assessment' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -HttpStatusCode $status `
        -Detail $_.Exception.Message
    throw
}
