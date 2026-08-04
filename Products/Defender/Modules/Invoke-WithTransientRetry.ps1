#requires -Version 7.0
<#
.SYNOPSIS
    Single retry boundary for transient Defender API and cmdlet operations.
#>

function Invoke-WithTransientRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [scriptblock] $Action,
        [Parameter(Mandatory)] [string] $Description,
        [int] $MaxAttempts = 3
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $Action
        }
        catch {
            $status = Get-DefenderHttpStatusCode -ErrorRecord $_
            $transient = $status -in @(408, 429, 500, 502, 503, 504)
            if (-not $transient -or $attempt -eq $MaxAttempts) {
                throw
            }

            Add-DefenderRunLogEntry -Module 'Invoke-WithTransientRetry' `
                -Action $Description -Status 'Retried' -Attempt $attempt `
                -HttpStatusCode $status -Detail $_.Exception.Message
            Start-Sleep -Seconds ([math]::Min(30, [math]::Pow(2, $attempt)))
        }
    }
}

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
