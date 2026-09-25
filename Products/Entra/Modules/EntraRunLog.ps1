#requires -Version 7.0
<#
.SYNOPSIS
    Structured console and local JSON logging for Entra deployments.

.DESCRIPTION
    Mirrors the Purview and Defender run-log contract while adding Entra
    best-practice keys and HTTP status evidence. JSON persistence failures are
    surfaced through warnings but do not interrupt the deployment.

    The status and disposition vocabulary is a compatibility contract for
    the product's structured evidence. Preserve existing values when
    changing the logger or report renderer.

    Persistence is deliberately durability-first: every entry rewrites the whole
    JSON sidecar, so a run killed at any point still leaves a complete and valid
    evidence file. The cost is that serialisation work grows quadratically with
    entry count. That is an accepted trade for the current baseline, which
    produces on the order of one hundred entries per run.

    If a run is ever expected to exceed roughly one thousand entries, revisit
    the model rather than the constant: append events to a JSON Lines file for
    durability and build the sidecar once at completion. Measure first, because
    the current behaviour is the reason a crashed run is still diagnosable.
#>

function Initialize-EntraRunLog {
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

    $global:EntraRunLog = [System.Collections.Generic.List[hashtable]]::new()
    $global:EntraRunLogPath = $JsonPath
    if ($TenantAdminUpn -match '@(?<domain>[^@\s]+)$') {
        Register-EntraSensitiveValue -Value $Matches.domain
    }
    $global:EntraRunMetadata = @{
        RunId = $RunId
        StartTime = $StartTime
        ScriptVersion = $ScriptVersion
        TenantId = Protect-EntraTenantId -Value $TenantId
        TenantAdminUpn = Protect-EntraIdentity -Value $TenantAdminUpn
    }
    Save-EntraRunLogJson
}

function Set-EntraRunTenantId {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $TenantId)

    if (-not $global:EntraRunMetadata) {
        throw 'Entra run log metadata is not initialized.'
    }
    Register-EntraSensitiveValue -Value $TenantId
    $global:EntraRunMetadata.TenantId = Protect-EntraTenantId -Value $TenantId
    Save-EntraRunLogJson
}

function Save-EntraRunLogJson {
    [CmdletBinding()]
    param(
        [string] $Path = $global:EntraRunLogPath,
        [datetime] $EndTime = [datetime]::UtcNow,
        [switch] $PassThru
    )

    try {
        if (-not $Path) { return }
        $entries = if ($global:EntraRunLog) { @($global:EntraRunLog) } else { @() }
        $metadata = if ($global:EntraRunMetadata) { $global:EntraRunMetadata } else { @{} }
        # Per-module verdicts, so the JSON sidecar carries the same summary the
        # HTML report shows and a downstream consumer does not have to
        # re-derive it from the raw entries.
        $moduleSummary = @($entries | Group-Object Module | Sort-Object Name | ForEach-Object {
            $items = @($_.Group)
            [ordered]@{
                module = $_.Name
                result = Get-EntraModuleVerdict -Entries $items
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
        $payload | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding utf8 -WhatIf:$false -ErrorAction Stop
        if ($PassThru) { (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath }
    }
    catch {
        Write-Warning "JSON run log could not be written: $($_.Exception.Message)" -WarningAction Continue
    }
}

function Add-EntraRunLogEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Module,
        [Parameter(Mandatory)] [string] $Action,
        [ValidateSet('Started','Succeeded','Created','Updated','Adopted','Skipped','Failed','Retried','Info')]
        [string] $Status = 'Info',
        [string] $BestPracticeKey,
        [ValidateSet('Applicable','AlreadyCompliant','WillChange','GuidedOnly','Skipped','Blocked')]
        [string] $Disposition,
        [string] $Target,
        [string] $Detail,
        [int] $HttpStatusCode,
        [int] $Attempt,
        [int] $ElapsedMs,
        [ValidateSet('Verified','Mismatch','NotAttempted')]
        [string] $Readback
    )

    try {
        if (-not $global:EntraRunLog) {
            $global:EntraRunLog = [System.Collections.Generic.List[hashtable]]::new()
        }

        $entry = [ordered]@{
            Timestamp = [datetime]::UtcNow.ToString('o')
            Module = $Module
            Action = $Action
            Status = $Status
            BestPracticeKey = $BestPracticeKey
            Disposition = $Disposition
            Target = Protect-EntraLogText -Value $Target
            Detail = Protect-EntraLogText -Value $Detail
            HttpStatusCode = if ($PSBoundParameters.ContainsKey('HttpStatusCode')) { $HttpStatusCode } else { $null }
            Attempt = if ($PSBoundParameters.ContainsKey('Attempt')) { $Attempt } else { $null }
            ElapsedMs = if ($PSBoundParameters.ContainsKey('ElapsedMs')) { $ElapsedMs } else { $null }
            Readback = if ($PSBoundParameters.ContainsKey('Readback')) { $Readback } else { $null }
        }

        $global:EntraRunLog.Add($entry)
        Write-Verbose ("[{0}] {1}/{2}: {3}" -f $Status, $Module, $Action, $entry.Detail)
        $color = 'Cyan'
        $label = $Status
        if ($Disposition) { $label += "/$Disposition" }
        if ($Status -eq 'Failed') { $color = 'Red' }
        elseif ($Disposition -eq 'Blocked' -or $Status -eq 'Retried' -or $entry.Detail -match '^WARNING:') {
            $color = 'Yellow'
        }
        elseif ($Readback -eq 'Verified') {
            $color = 'Green'
            $label += '/VALIDATED'
        }
        elseif ($Disposition -eq 'GuidedOnly' -or $Readback -eq 'Mismatch') { $color = 'Yellow' }
        elseif ($Disposition -eq 'AlreadyCompliant' -or $Status -in @('Succeeded', 'Created', 'Updated', 'Adopted')) {
            $color = 'Green'
        }
        elseif ($Status -eq 'Skipped' -or $Disposition -eq 'Skipped') { $color = 'DarkGray' }

        if ($Action -eq 'Stage') {
            Write-Host ("`n=== {0} ===" -f $entry.Detail) -ForegroundColor White
        }
        else {
            Write-Host ("[{0}] {1}: {2}" -f $label, $Action, $entry.Detail) -ForegroundColor $color
        }
        Save-EntraRunLogJson
    }
    catch {
        Write-Verbose "Add-EntraRunLogEntry failed: $($_.Exception.Message)"
    }
}

function Protect-EntraLogText {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)

    if ($null -eq $Value) { return $null }
    $text = [string] $Value
    $text = $text -replace '(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+', '$1[REDACTED]'
    # Key=value and key: value forms.
    $text = $text -replace '(?i)(access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|password|api[_-]?key)\s*[=:]\s*[^&\s,;]+', '$1=[REDACTED]'
    # JSON forms, where the separator sits between quotes and the plain
    # key=value pattern above does not match.
    $text = $text -replace '(?i)("(?:access|refresh|id)[_-]?token"|"client[_-]?secret"|"password"|"api[_-]?key")\s*:\s*"[^"]*"', '$1:"[REDACTED]"'
    # Object and tenant identifiers are useful for correlation, but the complete
    # GUID is tenant evidence. Preserve only the first segment.
    $text = [regex]::Replace(
        $text,
        '(?i)\b([0-9a-f]{8})-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
        '$1-****-****-****-************'
    )
    # Mask both the local part and tenant domain in UPNs and email addresses.
    $text = [regex]::Replace(
        $text,
        '(?i)\b([A-Z0-9])[A-Z0-9._%+-]*@[A-Z0-9.-]+\.[A-Z]{2,}\b',
        '$1***@[REDACTED]'
    )
    # Tenant-scoped hostnames name the customer directly. Entra and Graph
    # failures quote them in plain text, and that exception reaches evidence
    # verbatim, so the domain has to be removed here rather than at the caller.
    $text = [regex]::Replace(
        $text,
        '(?i)\b[A-Z0-9][A-Z0-9-]*\.(?:onmicrosoft\.com|sharepoint\.com)\b',
        '[REDACTED]'
    )
    # Domains resolved for this run, which covers a verified vanity domain that
    # no fixed pattern can predict. Microsoft service endpoints are deliberately
    # not registered, because they are diagnostic rather than tenant evidence.
    $registered = Get-Variable -Name 'EntraSensitiveValues' -Scope Global -ErrorAction SilentlyContinue
    if ($registered -and $registered.Value) {
        foreach ($sensitive in @($registered.Value)) {
            if ([string]::IsNullOrWhiteSpace($sensitive)) { continue }
            $text = [regex]::Replace($text, [regex]::Escape($sensitive), '[REDACTED]', 'IgnoreCase')
        }
    }
    return $text
}

function Register-EntraSensitiveValue {
    <#
        Records a tenant-identifying value so later evidence can remove it.
        Values shorter than five characters are ignored, because redacting a
        very short string would corrupt unrelated text.
    #>
    [CmdletBinding()]
    param([AllowNull()] [string[]] $Value)

    if (-not (Get-Variable -Name 'EntraSensitiveValues' -Scope Global -ErrorAction SilentlyContinue)) {
        $global:EntraSensitiveValues = [System.Collections.Generic.List[string]]::new()
    }

    foreach ($item in @($Value)) {
        if ([string]::IsNullOrWhiteSpace($item)) { continue }
        $normalized = $item.Trim()
        if ($normalized.Length -lt 5) { continue }
        if ($global:EntraSensitiveValues -notcontains $normalized) {
            $global:EntraSensitiveValues.Add($normalized)
        }
    }
}

function Protect-EntraIdentity {
    [CmdletBinding()]
    param([AllowNull()] [string] $Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ($Value -match '^([^@\s])[^@\s]*@[^@\s]+$') {
        return "$($Matches[1])***@[REDACTED]"
    }
    return '[REDACTED]'
}

function Protect-EntraTenantId {
    [CmdletBinding()]
    param([AllowNull()] [string] $Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ($Value -match '^(?<prefix>[0-9a-fA-F]{8})-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        return "$($Matches.prefix)-****-****-****-************"
    }
    return '[REDACTED]'
}

function Get-EntraRunLog {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param()

    if (-not (Test-EntraRunLogInitialized)) { return @() }
    return ,@($global:EntraRunLog.ToArray())
}

function Get-EntraEntryField {
    <#
        Reads a field from a run-log entry regardless of whether it arrives as a
        hashtable or an object, and returns null for an absent field rather than
        throwing under Set-StrictMode.
    #>
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

function Get-EntraModuleVerdict {
    <#
        Single source of truth for the per-module verdict shown in both the JSON
        sidecar and the HTML report. Precedence is FAILED, then BLOCKED, then
        SKIPPED, then OK. Deriving it twice let the two reports disagree after a
        status or disposition change, which would give an operator contradictory
        evidence for the same run.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Entries)

    # Derived summaries must not change the module results they describe.
    $items = @($Entries | Where-Object { (Get-EntraEntryField -Entry $_ -Name 'Action') -ne 'ModuleSummary' })
    if (@($items | Where-Object { (Get-EntraEntryField -Entry $_ -Name 'Status') -eq 'Failed' }).Count -gt 0) { return 'FAILED' }
    if (@($items | Where-Object { (Get-EntraEntryField -Entry $_ -Name 'Disposition') -eq 'Blocked' }).Count -gt 0) { return 'BLOCKED' }
    if (@($items | Where-Object { (Get-EntraEntryField -Entry $_ -Name 'Status') -eq 'Skipped' }).Count -gt 0) { return 'SKIPPED' }
    return 'OK'
}

function Test-EntraRunLogInitialized {    <#
        Strict-mode safe check for run-log availability. A configuration failure
        can terminate before Initialize-EntraRunLog runs, and reading an unset
        global under Set-StrictMode throws an error that masks the real reason
        the run stopped.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $variable = Get-Variable -Name 'EntraRunLog' -Scope Global -ErrorAction SilentlyContinue
    return [bool] ($variable -and $variable.Value)
}

function Clear-EntraRunLog {
    [CmdletBinding()]
    param()

    Remove-Variable -Name 'EntraRunLog' -Scope Global -ErrorAction SilentlyContinue -WhatIf:$false
    Remove-Variable -Name 'EntraRunLogPath' -Scope Global -ErrorAction SilentlyContinue -WhatIf:$false
    Remove-Variable -Name 'EntraRunMetadata' -Scope Global -ErrorAction SilentlyContinue -WhatIf:$false
    Remove-Variable -Name 'EntraSensitiveValues' -Scope Global -ErrorAction SilentlyContinue -WhatIf:$false
}
