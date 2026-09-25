#requires -Version 7.0
<#
.SYNOPSIS
    Single retry boundary for transient Defender API and cmdlet operations.

.DESCRIPTION
    Uses bounded exponential backoff with small random jitter and records
    Started, Retried, Succeeded, and Failed outcomes through the Defender
    run-log interface when it is available.
#>

function Get-DefenderHttpStatusCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )

    $response = $ErrorRecord.Exception.Response
    if ($response -and $response.StatusCode) {
        return [int] $response.StatusCode
    }
    return 0
}

function Get-DefenderErrorMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )

    $messages = @(
        $ErrorRecord.Exception.Message
        $ErrorRecord.Exception.InnerException.Message
        $ErrorRecord.ErrorDetails.Message
        $ErrorRecord.ToString()
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    return ($messages -join ' | ')
}

# Default transient HTTP status codes. Kept as a named, exported list (rather
# than inlined at the call site) so failure classification is a single
# testable contract instead of duplicated per-workload judgment calls.
$script:DefaultTransientHttpStatusCodes = @(408, 429, 500, 502, 503, 504)
$script:DefenderTransientMessagePatterns = @(
    '(?i)\b429\b'
    '(?i)\b(?:500|502|503|504)\b'
    '(?i)\btoo many requests\b'
    '(?i)\bthrottl'
    '(?i)\brate limit'
    '(?i)\bservice unavailable\b'
    '(?i)\bgateway timeout\b'
    '(?i)\bbad gateway\b'
    '(?i)\binternal server error\b'
    '(?i)\bserver[- ]side (?:error|failure)\b'
    '(?i)\btemporar(?:y|ily)\b.*\b(?:unavailable|failure|error)\b'
    '(?i)\bserver is busy\b'
    '(?i)\btime(?:d)? out\b'
    '(?i)\btry again later\b'
)
$script:DefenderNonTransientMessagePatterns = @(
    '(?i)\bunauthori[sz]ed\b'
    '(?i)\bforbidden\b'
    '(?i)\baccess denied\b'
    '(?i)\b(?:invalid|malformed)\b'
    '(?i)\b(?:not found|does not exist)\b'
    '(?i)\b(?:already exists|duplicate)\b'
    '(?i)\bvalidation\b'
    '(?i)\bnot supported\b'
    '(?i)\bunsupported\b'
)

function Get-DefenderTransientFailureReason {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord] $ErrorRecord,
        [int[]] $TransientHttpStatusCodes = $script:DefaultTransientHttpStatusCodes
    )

    $status = Get-DefenderHttpStatusCode -ErrorRecord $ErrorRecord
    $message = Get-DefenderErrorMessage -ErrorRecord $ErrorRecord

    if ($message -match ($script:DefenderNonTransientMessagePatterns -join '|')) {
        return ''
    }

    if ($status -in $TransientHttpStatusCodes) {
        return "HTTP status $status"
    }

    foreach ($pattern in $script:DefenderTransientMessagePatterns) {
        if ($message -match $pattern) {
            return 'error message matched transient signature'
        }
    }

    return ''
}

function Test-DefenderTransientFailure {
    <#
    .SYNOPSIS
        Classifies an error record as transient (retry-eligible) or permanent
        (fail fast). This is the single failure-classification
        contract every workload should reuse instead of re-deriving its own
        transient/permanent judgment.

    .DESCRIPTION
        Response-backed status codes are checked first, while cmdlet-style
        errors fall back to narrowly scoped transient message signatures.
        Deterministic semantic and authorization messages take precedence over
        generic transient status codes so a wrapped 500 does not cause retries.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [int] $HttpStatusCode,
        [System.Management.Automation.ErrorRecord] $ErrorRecord,
        [int[]] $TransientHttpStatusCodes = $script:DefaultTransientHttpStatusCodes
    )

    if ($ErrorRecord) {
        return [bool](Get-DefenderTransientFailureReason -ErrorRecord $ErrorRecord `
                -TransientHttpStatusCodes $TransientHttpStatusCodes)
    }

    return $HttpStatusCode -in $TransientHttpStatusCodes
}

function Invoke-WithTransientRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [scriptblock] $Action,
        [Parameter(Mandatory)] [string] $Description,
        [int] $MaxAttempts = 3,
        # Allows a workload to widen/narrow the transient classification
        # without editing this shared helper. Defaults to the shared list.
        [int[]] $TransientHttpStatusCodes = $script:DefaultTransientHttpStatusCodes,
        [int] $BackoffCapSeconds = 30,
        [int] $MaxJitterSeconds = 3
    )

    $logEnabled = [bool](Get-Command 'Add-DefenderRunLogEntry' -ErrorAction SilentlyContinue)
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    if ($logEnabled) {
        Add-DefenderRunLogEntry -Module 'Invoke-WithTransientRetry' `
            -Action $Description -Status 'Started' -Attempt 1 `
            -Detail 'Transient operation started.'
    }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $result = & $Action
            $stopwatch.Stop()
            if ($logEnabled) {
                Add-DefenderRunLogEntry -Module 'Invoke-WithTransientRetry' `
                    -Action $Description -Status 'Succeeded' -Attempt $attempt `
                    -ElapsedMs ([int] $stopwatch.ElapsedMilliseconds) `
                    -Detail 'Transient operation completed successfully.'
            }
            return $result
        }
        catch {
            $errorRecord = $_
            $status = Get-DefenderHttpStatusCode -ErrorRecord $errorRecord
            $transientReason = Get-DefenderTransientFailureReason -ErrorRecord $errorRecord `
                -TransientHttpStatusCodes $TransientHttpStatusCodes
            $transient = -not [string]::IsNullOrWhiteSpace($transientReason)
            if (-not $transient -or $attempt -eq $MaxAttempts) {
                $stopwatch.Stop()
                if ($logEnabled) {
                    Add-DefenderRunLogEntry -Module 'Invoke-WithTransientRetry' `
                        -Action $Description -Status 'Failed' -Attempt $attempt `
                        -HttpStatusCode $status `
                        -ElapsedMs ([int] $stopwatch.ElapsedMilliseconds) `
                        -Detail $errorRecord.Exception.Message
                }
                throw
            }

            $backoff = [math]::Min($BackoffCapSeconds, [math]::Pow(2, $attempt))
            $jitter = Get-Random -Minimum 0 -Maximum ($MaxJitterSeconds + 1)
            $sleepSeconds = $backoff + $jitter
            if ($logEnabled) {
                Add-DefenderRunLogEntry -Module 'Invoke-WithTransientRetry' `
                    -Action $Description -Status 'Retried' -Attempt $attempt `
                    -HttpStatusCode $status `
                    -Detail ("{0} ({1}). Sleeping {2}s before retry." -f `
                        $errorRecord.Exception.Message, $transientReason, $sleepSeconds)
            }
            Start-Sleep -Seconds $sleepSeconds
        }
    }
}
