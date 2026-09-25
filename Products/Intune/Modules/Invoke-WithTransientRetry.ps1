#requires -Version 7.0
<#
.SYNOPSIS
    Single retry boundary for transient Intune API and cmdlet operations.

.DESCRIPTION
    Uses bounded exponential backoff with small random jitter and records
    Started, Retried, Succeeded, and Failed outcomes through the Intune
    run-log interface when it is available.

    This is the only retry mechanism in the product. Do not hand-roll retry
    loops in task modules.
#>

function Invoke-WithTransientRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [scriptblock] $Action,
        [Parameter(Mandatory)] [string] $Description,
        [int] $MaxAttempts = 3,
        [int[]] $ExpectedStatusCodes = @(),
        [int[]] $AdditionalTransientStatusCodes = @(),
        [int] $BackoffCapSeconds = 30,
        [int] $MaxJitterSeconds = 3
    )

    $transientStatusCodes = @(408, 429, 500, 502, 503, 504)
    $extraOverlap = @($AdditionalTransientStatusCodes | Where-Object { $_ -in $transientStatusCodes })
    if ($extraOverlap.Count -gt 0) {
        throw "AdditionalTransientStatusCodes cannot include standard transient HTTP status codes: $($extraOverlap -join ', ')."
    }
    $expectedExtraOverlap = @($ExpectedStatusCodes | Where-Object { $_ -in $AdditionalTransientStatusCodes })
    if ($expectedExtraOverlap.Count -gt 0) {
        throw "ExpectedStatusCodes and AdditionalTransientStatusCodes cannot overlap: $($expectedExtraOverlap -join ', ')."
    }
    $transientStatusCodes = @($transientStatusCodes + $AdditionalTransientStatusCodes | Sort-Object -Unique)
    $overlap = @($ExpectedStatusCodes | Where-Object { $_ -in $transientStatusCodes })
    if ($overlap.Count -gt 0) {
        throw "ExpectedStatusCodes cannot include transient HTTP status codes: $($overlap -join ', ')."
    }

    $logEnabled = [bool](Get-Command 'Add-IntuneRunLogEntry' -ErrorAction SilentlyContinue)
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    if ($logEnabled) {
        Add-IntuneRunLogEntry -Module 'Invoke-WithTransientRetry' `
            -Action $Description -Status 'Started' -Attempt 1 `
            -Detail 'Transient operation started.'
    }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $result = & $Action
            $stopwatch.Stop()
            if ($logEnabled) {
                Add-IntuneRunLogEntry -Module 'Invoke-WithTransientRetry' `
                    -Action $Description -Status 'Succeeded' -Attempt $attempt `
                    -ElapsedMs ([int] $stopwatch.ElapsedMilliseconds) `
                    -Detail 'Transient operation completed successfully.'
            }
            return $result
        }
        catch {
            $errorRecord = $_
            $status = Get-IntuneHttpStatusCode -ErrorRecord $errorRecord
            if ($status -in $ExpectedStatusCodes) {
                $stopwatch.Stop()
                if ($logEnabled) {
                    Add-IntuneRunLogEntry -Module 'Invoke-WithTransientRetry' `
                        -Action $Description -Status 'Info' -Attempt $attempt `
                        -HttpStatusCode $status `
                        -ElapsedMs ([int] $stopwatch.ElapsedMilliseconds) `
                        -Detail ("{0} returned an expected unsupported response." -f $Description)
                }
                throw
            }

            $transient = Test-IntuneTransientFailure -ErrorRecord $errorRecord `
                -HttpStatusCode $status -TransientHttpStatusCodes $transientStatusCodes
            if (-not $transient -or $attempt -eq $MaxAttempts) {
                $stopwatch.Stop()
                if ($logEnabled) {
                    Add-IntuneRunLogEntry -Module 'Invoke-WithTransientRetry' `
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
                Add-IntuneRunLogEntry -Module 'Invoke-WithTransientRetry' `
                    -Action $Description -Status 'Retried' -Attempt $attempt `
                    -HttpStatusCode $status `
                    -Detail ("{0}. Sleeping {1}s before retry." -f $errorRecord.Exception.Message, $sleepSeconds)
            }
            Start-Sleep -Seconds $sleepSeconds
        }
    }
}

# Response-less transient failures (cmdlet-style throttling or a transport
# reset) expose no HTTP status, so classification falls back to the exception
# type/message. Only consulted when no HTTP status code is available.
$script:IntuneTransientExceptionTypeNames = @(
    'HttpRequestException', 'TaskCanceledException', 'TimeoutException',
    'WebException', 'SocketException', 'IOException'
)
$script:IntuneTransientMessagePattern =
    'throttl|too many requests|\b429\b|\b502\b|\b503\b|\b504\b|service unavailable|temporarily unavailable|timed? ?out|connection (?:reset|closed|refused|aborted)|(?:operation|task) was canceled'

function Test-IntuneTransientFailure {
    <#
        Single failure-classification contract. A transient failure is any
        configured transient HTTP status, or — when no HTTP status is available
        (a response-less cmdlet/transport error) — a recognized throttling or
        transient-transport exception type/message. A real permanent status
        (400/401/403/404/409...) always fails fast.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord,
        [int] $HttpStatusCode = 0,
        [int[]] $TransientHttpStatusCodes = @(408, 429, 500, 502, 503, 504)
    )

    if ($HttpStatusCode -in $TransientHttpStatusCodes) { return $true }
    if ($HttpStatusCode -ne 0) { return $false }

    $exception = $ErrorRecord.Exception
    while ($exception) {
        if ($exception.GetType().Name -in $script:IntuneTransientExceptionTypeNames) { return $true }
        $exception = $exception.InnerException
    }
    return ([string] $ErrorRecord.Exception.Message) -match $script:IntuneTransientMessagePattern
}

function Get-IntuneHttpStatusCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )

    $responseProperty = $ErrorRecord.Exception.PSObject.Properties['Response']
    if (-not $responseProperty) {
        return 0
    }

    $response = $responseProperty.Value
    $statusCodeProperty = if ($response) {
        $response.PSObject.Properties['StatusCode']
    }
    if ($statusCodeProperty -and $null -ne $statusCodeProperty.Value) {
        $value = $statusCodeProperty.Value
        if ($value -is [enum]) {
            return [int] $value
        }

        $parsedStatusCode = 0
        if ([int]::TryParse([string] $value, [ref] $parsedStatusCode)) {
            return $parsedStatusCode
        }
    }
    return 0
}
