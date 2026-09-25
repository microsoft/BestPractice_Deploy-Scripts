#requires -Version 7.0
<#
.SYNOPSIS
    Structured console and local JSON logging for Defender deployments.

.DESCRIPTION
    Mirrors the Purview run-log contract while adding Defender-specific
    best-practice keys and HTTP status evidence. Logging failures are surfaced
    through verbose output but do not interrupt the deployment.
#>

function Initialize-DefenderRunLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $JsonPath,
        [guid] $RunId = [guid]::NewGuid(),
        [datetime] $StartTime = [datetime]::UtcNow,
        [string] $ScriptVersion = 'unknown',
        [string] $TenantId,
        [string] $TenantAdminUpn
    )

    $directory = Split-Path -Parent $JsonPath
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        # Evidence output is local, not a tenant change. It must be written even
        # during -WhatIf, otherwise a dry run produces no report at all, which
        # is precisely when the operator most needs one.
        New-Item -ItemType Directory -Path $directory -Force -WhatIf:$false | Out-Null
    }

    $global:DefenderRunLog = [System.Collections.Generic.List[hashtable]]::new()
    $global:DefenderRunLogPath = $JsonPath
    $global:DefenderRunMetadata = @{
        RunId = $RunId
        StartTime = $StartTime
        ScriptVersion = $ScriptVersion
        TenantId = Protect-DefenderIdentity -Value $TenantId
        TenantAdminUpn = Protect-DefenderIdentity -Value $TenantAdminUpn
    }
    Save-DefenderRunLogJson
}

function Save-DefenderRunLogJson {
    [CmdletBinding()]
    param(
        [string] $Path = $global:DefenderRunLogPath,
        [datetime] $EndTime = [datetime]::UtcNow
    )

    try {
        if (-not $Path) { return }
        $entries = if ($global:DefenderRunLog) { @($global:DefenderRunLog) } else { @() }
        $metadata = if ($global:DefenderRunMetadata) { $global:DefenderRunMetadata } else { @{} }
        $moduleSummary = @($entries | Group-Object Module | Sort-Object Name | ForEach-Object {
            $items = @($_.Group)
            [ordered]@{
                module = $_.Name
                result = Get-DefenderModuleVerdict -Entries $items
                entryCount = $items.Count
            }
        })
        $payload = [ordered]@{
            runId = if ($metadata.RunId) { ([guid] $metadata.RunId).ToString() } else { $null }
            scriptVersion = $metadata.ScriptVersion
            startTime = if ($metadata.StartTime) { ([datetime] $metadata.StartTime).ToString('o') } else { $null }
            endTime = $EndTime.ToString('o')
            durationSec = if ($metadata.StartTime) { [int] (($EndTime - [datetime] $metadata.StartTime).TotalSeconds) } else { $null }
            tenantId = $metadata.TenantId
            tenantAdmin = $metadata.TenantAdminUpn
            entryCount = $entries.Count
            moduleSummary = $moduleSummary
            entries = @($entries | ForEach-Object {
                [ordered]@{
                    timestamp = $_.Timestamp
                    module = $_.Module
                    action = $_.Action
                    bestPracticeKey = $_.BestPracticeKey
                    friendlyName = $_.FriendlyName
                    disposition = $_.Disposition
                    target = $_.Target
                    status = $_.Status
                    detail = $_.Detail
                    httpStatusCode = $_.HttpStatusCode
                    attempt = $_.Attempt
                    elapsedMs = $_.ElapsedMs
                    readback = $_.Readback
                }
            })
        }
        # Evidence output is local, not a tenant change; never suppress it under
        # -WhatIf.
        $payload | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding utf8 -WhatIf:$false
    }
    catch {
        Write-Verbose "Save-DefenderRunLogJson failed: $($_.Exception.Message)"
    }
}

function Add-DefenderRunLogEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Module,
        [Parameter(Mandatory)] [string] $Action,
        [ValidateSet('Started','Succeeded','Created','Updated','Adopted','Skipped','Failed','Retried','Info')]
        [string] $Status = 'Info',
        [string] $BestPracticeKey,
        [string] $FriendlyName,
        [ValidateSet('Applicable','AlreadyCompliant','WillChange','GuidedOnly','Skipped','Blocked')]
        [string] $Disposition,
        [string] $Target,
        [string] $Detail,
        [int] $HttpStatusCode,
        [int] $Attempt,
        [int] $ElapsedMs,
        [ValidateSet('NotApplicable','Pending','Succeeded','Failed')]
        [string] $Readback
    )

    try {
        if (-not $global:DefenderRunLog) {
            $global:DefenderRunLog = [System.Collections.Generic.List[hashtable]]::new()
        }

        $entry = [ordered]@{
            Timestamp = [datetime]::UtcNow.ToString('o')
            Module = $Module
            Action = $Action
            Status = $Status
            BestPracticeKey = $BestPracticeKey
            FriendlyName = Protect-DefenderLogText -Value $FriendlyName
            Disposition = $Disposition
            Target = Protect-DefenderLogText -Value $Target
            Detail = Protect-DefenderLogText -Value $Detail
            HttpStatusCode = if ($PSBoundParameters.ContainsKey('HttpStatusCode')) { $HttpStatusCode } else { $null }
            Attempt = if ($PSBoundParameters.ContainsKey('Attempt')) { $Attempt } else { $null }
            ElapsedMs = if ($PSBoundParameters.ContainsKey('ElapsedMs')) { $ElapsedMs } else { $null }
            Readback = $Readback
        }

        $global:DefenderRunLog.Add($entry)
        Write-Verbose ("[{0}] {1}/{2}: {3}" -f $Status, $Module, $Action, $entry.Detail)
        Write-Host ("[{0}] {1}: {2}" -f $Status, $Action, $entry.Detail)
        Save-DefenderRunLogJson
    }
    catch {
        Write-Verbose "Add-DefenderRunLogEntry failed: $($_.Exception.Message)"
    }
}

function Protect-DefenderLogText {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)

    if ($null -eq $Value) { return $null }
    $text = [string] $Value
    $text = $text -replace '(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+', '$1[REDACTED]'
    $text = $text -replace '(?i)(access[_-]?token|refresh[_-]?token|client[_-]?secret|password)\s*[=:]\s*[^&\s,;]+', '$1=[REDACTED]'
    return $text
}

function Protect-DefenderIdentity {
    [CmdletBinding()]
    param([AllowNull()] [string] $Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ($Value -match '^([^@\s])[^@\s]*(@[^@\s]+)$') {
        return "$($Matches[1])***$($Matches[2])"
    }
    return '[REDACTED]'
}

function Get-DefenderRunLog {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param()

    if (-not $global:DefenderRunLog) { return @() }
    return @($global:DefenderRunLog.ToArray())
}

function Get-DefenderEntryField {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Entry,
        [Parameter(Mandatory)] [string] $Name
    )

    if ($null -eq $Entry) { return $null }
    if ($Entry -is [System.Collections.IDictionary]) {
        if ($Entry.Contains($Name)) { return $Entry[$Name] }
        return $null
    }

    $property = $Entry.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Get-DefenderModuleVerdict {
    <#
        Single source of truth for the per-module verdict shown in the JSON
        sidecar and HTML report. Empty modules are treated as OK, matching the
        existing product report contract.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Entries)

    $items = @($Entries)
    if (@($items | Where-Object {
        (Get-DefenderEntryField -Entry $_ -Name 'Disposition') -eq 'Blocked'
    }).Count -gt 0) { return 'BLOCKED' }
    if (@($items | Where-Object {
        (Get-DefenderEntryField -Entry $_ -Name 'Status') -eq 'Failed' -or
        (Get-DefenderEntryField -Entry $_ -Name 'Readback') -eq 'Failed'
    }).Count -gt 0) { return 'FAILED' }
    if (@($items | Where-Object {
        (Get-DefenderEntryField -Entry $_ -Name 'Status') -eq 'Skipped' -or
        (Get-DefenderEntryField -Entry $_ -Name 'Disposition') -eq 'GuidedOnly'
    }).Count -gt 0) { return 'SKIPPED' }
    return 'OK'
}

function Clear-DefenderRunLog {
    [CmdletBinding()]
    param()

    Remove-Variable -Name 'DefenderRunLog' -Scope Global -ErrorAction SilentlyContinue -WhatIf:$false
    Remove-Variable -Name 'DefenderRunLogPath' -Scope Global -ErrorAction SilentlyContinue -WhatIf:$false
    Remove-Variable -Name 'DefenderRunMetadata' -Scope Global -ErrorAction SilentlyContinue -WhatIf:$false
}
