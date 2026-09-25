#requires -Version 7.0
# Get-EntraModuleVerdict and the identity redaction helpers live in
# EntraRunLog.ps1 so the JSON sidecar and this report use the same verdict and
# privacy rules. Callers dot-source that file before invoking this function.
function Write-EntraHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [hashtable[]] $Entries,
        [guid] $RunId,
        [datetime] $StartTime,
        [datetime] $EndTime = [datetime]::UtcNow,
        [string] $TenantId,
        [string] $TenantAdminUpn,
        [string] $ScriptVersion = 'unknown',
        [switch] $WhatIfRun
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
            'Created' { return 'succeeded' }
            'Updated' { return 'succeeded' }
            'Adopted' { return 'succeeded' }
            default { return 'info' }
        }
    }

    try {
        $failed = @($Entries | Where-Object Status -eq 'Failed').Count
        $skipped = @($Entries | Where-Object Status -eq 'Skipped').Count
        $guided = @($Entries | Where-Object Disposition -eq 'GuidedOnly').Count
        $succeeded = @($Entries | Where-Object Status -in @('Succeeded','Created','Updated','Adopted')).Count
        $duration = if ($StartTime) { [int] (($EndTime - $StartTime).TotalSeconds) } else { $null }
        $startText = if ($StartTime) { $StartTime.ToString('o') } else { $null }
        $modeBanner = if ($WhatIfRun) {
            '<p class="banner">WhatIf preview. No state-changing call was made during this run.</p>'
        }
        else {
            ''
        }

        # The operator report requires a final summary showing
        # each module as OK, FAILED, SKIPPED, or BLOCKED. Entry counts alone do
        # not satisfy it: an operator scanning a long run needs the per-module
        # verdict without reading every row.
        $moduleRows = foreach ($group in ($Entries | Group-Object Module | Sort-Object Name)) {
            $items = @($group.Group)
            $verdict = Get-EntraModuleVerdict -Entries $items
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
            '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td><td>{9}</td><td>{10}</td></tr>' -f `
                (Encode $entry.Timestamp), (Encode $entry.Module), (Encode $entry.Action),
                (Encode $entry.BestPracticeKey), (Encode $entry.Disposition), (Encode $entry.Target),
                ('<span class="status {0}">{1}</span>' -f $statusClass, (Encode $entry.Status)),
                (Encode $entry.Detail), (Encode $entry.Readback),
                (Encode $entry.HttpStatusCode), (Encode $entry.ElapsedMs)
        }

        $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Entra deployment report</title>
<style>
:root { color-scheme: light; --bg: #f7f4ef; --surface: #fff; --border: #dedede; --text: #242424; --muted: #5c5c5c; --accent: #0f6cbd; --success: #16a34a; --danger: #dc2626; --warning: #f59e0b; }
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: "Segoe UI", Aptos, Calibri, sans-serif; margin: 0; padding: 24px; }
.container { max-width: 1400px; margin: 0 auto; }
header { background: var(--accent); color: var(--surface); padding: 20px 24px; border-radius: 10px 10px 0 0; }
header h1 { margin: 0 0 4px; font-size: 20px; }
header p { margin: 0; opacity: .9; }
section { background: var(--surface); border: 1px solid var(--border); border-top: 0; padding: 20px 24px; }
.banner { background: #fff4d6; border: 1px solid #f0c36d; border-radius: 8px; color: #9a6700; font-weight: 600; margin: 0 0 16px; padding: 10px 14px; }
.meta { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; }
.meta dt { color: var(--muted); font-weight: 600; }
.meta dd { margin: 0; font-family: Consolas, "Courier New", monospace; word-break: break-all; }
.stats { display: flex; gap: 12px; flex-wrap: wrap; }
.stat { border: 1px solid var(--border); border-radius: 10px; padding: 10px 16px; min-width: 110px; }
.stat strong { display: block; font-size: 20px; }
.stat span { color: var(--muted); font-size: 12px; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th, td { border-bottom: 1px solid var(--border); padding: 8px; text-align: left; vertical-align: top; }
th { background: var(--bg); color: var(--muted); font-size: 11px; text-transform: uppercase; }
td:nth-child(1), td:nth-child(10), td:nth-child(11) { font-family: Consolas, "Courier New", monospace; white-space: nowrap; }
.status { border-radius: 10px; display: inline-block; padding: 2px 8px; font-weight: 600; }
.status.succeeded { background: #e7f7ec; color: var(--success); }
.status.failed { background: #fde8e7; color: var(--danger); }
.status.skipped, .status.retried { background: #fff4d6; color: #9a6700; }
.status.info { background: #e8f1fb; color: var(--accent); }
</style>
</head>
<body><div class="container">
<header><h1>Microsoft Entra Best Practice Deployment Report</h1><p>Read-only and state-changing evidence for one deployment run.</p></header>
<section>$modeBanner<h2>Run metadata</h2><dl class="meta">
<dt>Run ID</dt><dd>$(Encode $RunId)</dd>
<dt>Script version</dt><dd>$(Encode $ScriptVersion)</dd>
<dt>Tenant ID</dt><dd>$(Encode (Protect-EntraTenantId -Value $TenantId))</dd>
<dt>Tenant administrator</dt><dd>$(Encode (Protect-EntraIdentity -Value $TenantAdminUpn))</dd>
<dt>Started</dt><dd>$(Encode $startText)</dd>
<dt>Ended</dt><dd>$(Encode $EndTime.ToString('o'))</dd>
<dt>Duration (seconds)</dt><dd>$(Encode $duration)</dd>
</dl></section>
<section><h2>Evidence summary</h2><div class="stats">
<div class="stat"><strong>$($Entries.Count)</strong><span>Total entries</span></div>
<div class="stat"><strong>$succeeded</strong><span>Successful/change entries</span></div>
<div class="stat"><strong>$skipped</strong><span>Skipped</span></div>
<div class="stat"><strong>$guided</strong><span>Guided only</span></div>
<div class="stat"><strong>$failed</strong><span>Failed</span></div>
</div></section>
<section><h2>Module summary</h2><table>
<thead><tr><th>Module</th><th>Result</th><th>Entries</th></tr></thead>
<tbody>$($moduleRows -join [Environment]::NewLine)</tbody>
</table></section>
<section><h2>Decision-point evidence</h2><table>
<thead><tr><th>Timestamp</th><th>Module</th><th>Action</th><th>BP key</th><th>Disposition</th><th>Target</th><th>Status</th><th>Detail / reason</th><th>Readback</th><th>HTTP</th><th>Elapsed ms</th></tr></thead>
<tbody>$($rows -join [Environment]::NewLine)</tbody>
</table></section>
</div></body></html>
"@
        # Evidence output is local, not a tenant change; never suppress it under
        # -WhatIf. A dry run must still produce its report.
        Set-Content -LiteralPath $Path -Value $html -Encoding utf8 -WhatIf:$false
    }
    catch {
        throw "Unable to write Entra HTML report '$Path': $($_.Exception.Message)"
    }
}
