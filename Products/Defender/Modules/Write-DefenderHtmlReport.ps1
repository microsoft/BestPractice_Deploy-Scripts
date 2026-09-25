#requires -Version 7.0
# Get-DefenderModuleVerdict lives in DefenderRunLog.ps1 so the JSON sidecar and
# this report cannot disagree about a module outcome.
function Write-DefenderHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [hashtable[]] $Entries,
        [guid] $RunId,
        [datetime] $StartTime,
        [datetime] $EndTime = [datetime]::UtcNow,
        [string] $TenantId,
        [string] $TenantAdminUpn,
        [string] $ScriptVersion = 'unknown'
    )

    function Encode([object] $Value) {
        if ($null -eq $Value) { return '' }
        return [System.Net.WebUtility]::HtmlEncode([string] $Value)
    }

    function Get-StatusClass([string] $Status) {
        switch ($Status) {
            'Failed' { return 'failed' }
            'Skipped' { return 'skipped' }
            'Retried' { return 'retried' }
            'Succeeded' { return 'succeeded' }
            default { return 'info' }
        }
    }

    function Protect-Identity([string] $Value) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
        if ($Value -match '^([^@\s])[^@\s]*(@[^@\s]+)$') {
            return "$($Matches[1])***$($Matches[2])"
        }
        return '[REDACTED]'
    }

    try {
        $failed = @($Entries | Where-Object Status -eq 'Failed').Count
        $skipped = @($Entries | Where-Object Status -eq 'Skipped').Count
        $succeeded = @($Entries | Where-Object Status -in @('Succeeded','Created','Updated','Adopted')).Count
        $duration = if ($StartTime) { [int] (($EndTime - $StartTime).TotalSeconds) } else { $null }
        $startText = if ($StartTime) { $StartTime.ToString('o') } else { $null }

        $moduleRows = foreach ($group in ($Entries | Group-Object Module | Sort-Object Name)) {
            $items = @($group.Group)
            $verdict = Get-DefenderModuleVerdict -Entries $items
            $verdictClass = switch ($verdict) {
                'FAILED'  { 'failed' }
                'BLOCKED' { 'skipped' }
                'SKIPPED' { 'skipped' }
                default   { 'succeeded' }
            }
            '<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f `
                (Encode $group.Name),
                ('<span class="status {0}">{1}</span>' -f $verdictClass, $verdict),
                $items.Count
        }

        $rows = foreach ($entry in $Entries) {
            $statusClass = Get-StatusClass $entry.Status
            $friendlyName = if ($entry.FriendlyName) {
                [string]$entry.FriendlyName
            } elseif ($entry.Detail -match '(^|;\s*)Recommendation=(?<name>[^;]+)') {
                $Matches.name.Trim()
            } else {
                [string]$entry.Action
            }
            '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td><td>{9}</td><td>{10}</td></tr>' -f `
                (Encode $entry.Timestamp), (Encode $entry.Module), (Encode $entry.Action),
                (Encode $friendlyName), (Encode $entry.Disposition), (Encode $entry.Target),
                ('<span class="status {0}">{1}</span>' -f $statusClass, (Encode $entry.Status)),
                (Encode $entry.Detail), (Encode $entry.HttpStatusCode), (Encode $entry.ElapsedMs),
                (Encode $entry.Readback)
        }

        function ColumnHeader([string] $Label, [string] $Description) {
            '<th title="{0}">{1}</th>' -f (Encode $Description), (Encode $Label)
        }

        $moduleHeaders = @(
            (ColumnHeader 'Module' 'The deployment module that produced the grouped evidence.')
            (ColumnHeader 'Result' 'The final module verdict: OK, FAILED, SKIPPED, or BLOCKED.')
            (ColumnHeader 'Entries' 'The number of evidence entries recorded for this module.')
        ) -join ''
        $decisionHeaders = @(
            (ColumnHeader 'Timestamp' 'The UTC time when the evidence entry was recorded.')
            (ColumnHeader 'Module' 'The deployment module that recorded this evidence.')
            (ColumnHeader 'Action' 'The operation or decision represented by this evidence entry.')
            (ColumnHeader 'Recommendation' 'The configured friendly best-practice recommendation name.')
            (ColumnHeader 'Disposition' 'The applicability or intended-change outcome for the recommendation.')
            (ColumnHeader 'Target' 'The tenant workload, object, or scope affected or inspected.')
            (ColumnHeader 'Status' 'The execution status recorded for the operation.')
            (ColumnHeader 'Detail / reason' 'Additional context, reason, or operator guidance for the entry.')
            (ColumnHeader 'HTTP' 'The HTTP response status code, when an HTTP call produced one.')
            (ColumnHeader 'Elapsed ms' 'The elapsed operation time in milliseconds, when measured.')
            (ColumnHeader 'Readback' 'Whether post-operation or authorization readback succeeded, failed, or was not applicable.')
        ) -join ''

        $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Defender deployment report</title>
<style>
:root { color-scheme: light; --bg: #f7f4ef; --surface: #fff; --border: #dedede; --text: #242424; --muted: #5c5c5c; --accent: #b11f4b; --success: #16a34a; --danger: #dc2626; --warning: #f59e0b; }
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: "Segoe UI", Aptos, Calibri, sans-serif; margin: 0; padding: 24px; }
.container { max-width: 1400px; margin: 0 auto; }
header { background: var(--accent); color: var(--surface); padding: 20px 24px; border-radius: 10px 10px 0 0; }
header h1 { margin: 0 0 4px; font-size: 20px; }
header p { margin: 0; opacity: .9; }
section { background: var(--surface); border: 1px solid var(--border); border-top: 0; padding: 20px 24px; }
.meta { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; }
.meta dt { color: var(--muted); font-weight: 600; }
.meta dd { margin: 0; font-family: Consolas, "Courier New", monospace; word-break: break-all; }
.stats { display: flex; gap: 12px; flex-wrap: wrap; }
.stat { border: 1px solid var(--border); border-radius: 10px; padding: 10px 16px; min-width: 110px; }
.stat strong { display: block; font-size: 20px; }
.stat span { color: var(--muted); font-size: 12px; }
.table-wrap { max-width: 100%; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th, td { border-bottom: 1px solid var(--border); padding: 8px; text-align: left; vertical-align: top; }
th { background: var(--bg); color: var(--muted); font-size: 11px; text-transform: uppercase; }
th[title] { cursor: help; }
td:nth-child(1), td:nth-child(8), td:nth-child(9) { font-family: Consolas, "Courier New", monospace; white-space: nowrap; }
.status { border-radius: 10px; display: inline-block; padding: 2px 8px; font-weight: 600; }
.status.succeeded { background: #e7f7ec; color: var(--success); }
.status.failed { background: #fde8e7; color: var(--danger); }
.status.skipped, .status.retried { background: #fff4d6; color: #9a6700; }
.status.info { background: #f0e7eb; color: var(--accent); }
</style>
</head>
<body><div class="container">
<header><h1>Microsoft Defender Best Practice Deployment Report</h1><p>Read-only and state-changing evidence for one deployment run.</p></header>
<section><h2>Run metadata</h2><dl class="meta">
<dt>Run ID</dt><dd>$(Encode $RunId)</dd>
<dt>Script version</dt><dd>$(Encode $ScriptVersion)</dd>
<dt>Tenant ID</dt><dd>$(Encode (Protect-Identity $TenantId))</dd>
<dt>Tenant administrator</dt><dd>$(Encode (Protect-Identity $TenantAdminUpn))</dd>
<dt>Started</dt><dd>$(Encode $startText)</dd>
<dt>Ended</dt><dd>$(Encode $EndTime.ToString('o'))</dd>
<dt>Duration (seconds)</dt><dd>$(Encode $duration)</dd>
</dl></section>
<section><h2>Evidence summary</h2><div class="stats">
<div class="stat"><strong>$($Entries.Count)</strong><span>Total entries</span></div>
<div class="stat"><strong>$succeeded</strong><span>Successful/change entries</span></div>
<div class="stat"><strong>$skipped</strong><span>Skipped</span></div>
<div class="stat"><strong>$failed</strong><span>Failed</span></div>
</div></section>
<section><h2>Module summary</h2><div class="table-wrap"><table>
<thead><tr>$moduleHeaders</tr></thead>
<tbody>$($moduleRows -join [Environment]::NewLine)</tbody>
</table></div></section>
<section><h2>Decision-point evidence</h2><div class="table-wrap"><table>
<thead><tr>$decisionHeaders</tr></thead>
<tbody>$($rows -join [Environment]::NewLine)</tbody>
</table></div></section>
</div></body></html>
"@
        # Evidence output is local, not a tenant change; never suppress it under
        # -WhatIf. A dry run must still produce its report.
        Set-Content -LiteralPath $Path -Value $html -Encoding utf8 -WhatIf:$false
    }
    catch {
        throw "Unable to write Defender HTML report '$Path': $($_.Exception.Message)"
    }
}
