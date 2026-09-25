#requires -Version 7.0
<#
.SYNOPSIS
    Renders the Purview configuration-validation HTML report and JSON sidecar.

.DESCRIPTION
    Both artifacts come from one canonical model. The renderer computes no
    facts of its own, so the HTML and the JSON can never disagree.

    The HTML is self-contained: no external stylesheet, font, or script. All
    result content is server-rendered and HTML-encoded. The only script is a
    filter that toggles visibility of already-rendered rows, so no tenant value
    is ever interpolated into JavaScript.

    EXPORTS (via dot-source):
      * ConvertTo-PurviewValidationHtml
      * Write-PurviewValidationReport
#>

Set-StrictMode -Version Latest

function Get-PurviewValidationStatusClass {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Status)

    switch ($Status) {
        'Matched' { return 'matched' }
        'Drift' { return 'drift' }
        'Not evaluated' { return 'not-evaluated' }
        'Informational' { return 'informational' }
        'Collection failed' { return 'collection-failed' }
        default { return 'informational' }
    }
}

function ConvertTo-PurviewValidationHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [psobject] $Model
    )

    function Encode([object] $Value) {
        return [Net.WebUtility]::HtmlEncode([string]$Value)
    }

    $sb = [Text.StringBuilder]::new()
    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $sb.AppendLine('<title>Purview Tenant Validation</title>')
    $null = $sb.AppendLine(@'
<style>
:root {
  color-scheme: light;
  --bg: #f7f4ef; --elevated: #fcfbf8; --surface: #ffffff; --border: #dedede;
  --border-strong: #919191; --text: #242424; --muted: #5c5c5c; --soft: #6f6f6f;
  --accent: #b11f4b; --accent-soft: rgba(177, 31, 75, 0.08); --accent-fg: #ffffff;
  --success: #16a34a; --danger: #dc2626; --warning: #b45309; --link: #0f5ba7;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --bg: #3d3b3a; --elevated: #343231; --surface: #292929; --border: #474747;
    --border-strong: #5f5f5f; --text: #dedede; --muted: #b0b0b0; --soft: #a0a0a0;
    --accent: #fd8ea1; --accent-soft: rgba(253, 142, 161, 0.14); --accent-fg: #1a1a1a;
    --success: #4ade80; --danger: #f87171; --warning: #fbbf24; --link: #4da6ff;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.45 "Segoe UI", Arial, sans-serif; }
button, input { font: inherit; }
code, .mono { font-family: Consolas, "Courier New", monospace; }
a { color: var(--link); }
.shell { max-width: 1280px; margin: 0 auto; padding: 32px 28px 56px; }
.eyebrow { color: var(--accent); font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; margin-bottom: 8px; }
.hero { padding: 28px; border: 1px solid var(--border); border-left: 6px solid var(--accent); border-radius: 16px; background: var(--surface); }
h1 { margin: 0 0 8px; font-size: 32px; line-height: 1.08; }
h2 { margin: 0; font-size: 20px; }
h3 { margin: 0; font-size: 15px; }
p { margin: 0; }
.hero p { color: var(--muted); max-width: 820px; font-size: 15px; }
.notice { margin-top: 16px; padding: 14px 16px; border: 1px solid var(--border); border-radius: 10px; background: var(--elevated); color: var(--muted); }
.notice strong { color: var(--text); }
.summary-grid { margin-top: 20px; display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; }
.metric { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 18px; }
.metric .value { font-size: 32px; line-height: 1; font-weight: 700; margin: 10px 0 8px; }
.metric .label { color: var(--muted); font-weight: 600; }
.metric .hint { color: var(--soft); font-size: 12px; }
.metric.matched .value { color: var(--success); }
.metric.drift .value { color: var(--danger); }
.metric.informational .value { color: var(--warning); }
.metric.not-evaluated .value { color: var(--link); }
.metric.collection-failed .value { color: var(--muted); }
.section { margin-top: 20px; background: var(--surface); border: 1px solid var(--border); border-radius: 16px; overflow: hidden; }
.section-head { padding: 20px 22px; border-bottom: 1px solid var(--border); }
.section-head p { color: var(--muted); margin-top: 4px; }
.metadata { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1px; background: var(--border); }
.meta-item { padding: 16px 18px; background: var(--surface); min-width: 0; }
.meta-item dt { color: var(--muted); font-size: 12px; margin-bottom: 5px; }
.meta-item dd { margin: 0; font-weight: 600; overflow-wrap: anywhere; }
.toolbar { padding: 14px 18px; display: flex; flex-wrap: wrap; gap: 8px; border-bottom: 1px solid var(--border); background: var(--elevated); }
.filter { border: 1px solid var(--border); background: var(--surface); color: var(--text); border-radius: 10px; padding: 8px 11px; cursor: pointer; font-weight: 600; }
.filter.active { background: var(--accent); color: var(--accent-fg); border-color: var(--accent); }
.search { margin-left: auto; min-width: 260px; border: 1px solid var(--border); background: var(--surface); color: var(--text); border-radius: 10px; padding: 8px 12px; }
.module { border-bottom: 1px solid var(--border); }
.module > summary { padding: 14px 20px; cursor: pointer; font-weight: 700; background: var(--elevated); }
.result { padding: 16px 20px; border-top: 1px solid var(--border); }
.result-main { display: grid; grid-template-columns: minmax(0, 2fr) 160px minmax(0, 1fr) minmax(0, 1fr); gap: 14px; align-items: start; }
.action-title { font-weight: 600; }
.action-id { color: var(--soft); font-size: 12px; }
.cell-label { color: var(--soft); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
.cell-value { overflow-wrap: anywhere; }
.status { display: inline-block; padding: 3px 10px; border-radius: 999px; font-weight: 700; font-size: 12px; }
.status.matched { background: rgba(22, 163, 74, .14); color: var(--success); }
.status.drift { background: rgba(220, 38, 38, .14); color: var(--danger); }
.status.not-evaluated { background: rgba(15, 91, 167, .14); color: var(--link); }
.status.informational { background: rgba(180, 83, 9, .14); color: var(--warning); }
.status.collection-failed { background: rgba(120, 120, 120, .18); color: var(--muted); }
.result-detail { margin-top: 12px; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.detail-block { border: 1px solid var(--border); border-radius: 10px; padding: 12px; background: var(--elevated); }
.detail-block strong { display: block; margin-bottom: 5px; }
.detail-block span, .detail-block li { color: var(--muted); }
.detail-block ul { margin: 0; padding-left: 18px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
th { background: var(--elevated); color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
.next-grid { padding: 20px; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.next-card { border: 1px solid var(--border); border-radius: 10px; padding: 16px; background: var(--elevated); }
.next-card .priority { color: var(--accent); font-weight: 700; font-size: 12px; text-transform: uppercase; margin-bottom: 6px; }
.next-card p { color: var(--muted); margin-top: 6px; }
.empty { padding: 24px; color: var(--muted); }
footer { color: var(--muted); font-size: 12px; padding: 22px 2px 0; text-align: center; }
@media (max-width: 980px) {
  .summary-grid, .metadata, .next-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .result-main, .result-detail { grid-template-columns: 1fr; }
}
</style>
'@)
    $null = $sb.AppendLine('</head><body><main class="shell">')

    $null = $sb.AppendLine('<section class="hero">')
    $null = $sb.AppendLine('<div class="eyebrow">Clawpilot read-only tenant assessment</div>')
    $null = $sb.AppendLine('<h1>Purview Tenant Validation</h1>')
    $contextText = if ($Model.AssessmentMode -eq 'PlanComparison') {
        "Compared with Deployment Plan $($Model.Plan.PlanReference)."
    } else {
        'Guide-only Good, Better, and Best assessment. No configuration intent was assumed.'
    }
    $null = $sb.AppendLine(('<p>{0} Proven level: {1}. Provisional level: {2}.</p>' -f `
        (Encode $contextText), (Encode $Model.Summary.ProvenLevel), (Encode $Model.Summary.ProvisionalLevel)))
    $null = $sb.AppendLine('</section>')

    $null = $sb.AppendLine(('<div class="notice"><strong>Configuration alignment, not compliance.</strong> {0}<br><strong>Allow propagation time.</strong> Purview label, DLP, and tenant settings can take up to 24 hours to become visible to a read. Run validation after that window, not immediately after a deployment, or a still-propagating setting will be reported as drift.</div>' -f `
        (Encode $Model.Disclaimer)))

    $null = $sb.AppendLine('<section class="summary-grid">')
    foreach ($metric in @(
        @('matched', 'Matched', $Model.Summary.Matched, 'Every managed field matched'),
        @('drift', 'Drift', $Model.Summary.Drift, 'Final mismatch after retries'),
        @('not-evaluated', 'Not evaluated', $Model.Summary.NotEvaluated, (
            'Prerequisite unmet {0}, unreadable {1}' -f $Model.Summary.PrerequisiteUnmet, $Model.Summary.PrerequisiteUnknown)),
        @('informational', 'Informational', $Model.Summary.Informational, 'Excluded or not configured by the plan'),
        @('collection-failed', 'Collection failed', $Model.Summary.CollectionFailed, 'Read did not succeed')
    )) {
        $null = $sb.AppendLine(('<article class="metric {0}"><div class="label">{1}</div><div class="value">{2}</div><div class="hint">{3}</div></article>' -f `
            $metric[0], (Encode $metric[1]), $metric[2], (Encode $metric[3])))
    }
    $null = $sb.AppendLine('</section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-head"><h2>Validation context</h2>')
    $null = $sb.AppendLine('<p>Correlates plan identity, tenant identity, collector coverage, and observation time.</p></div>')
    $null = $sb.AppendLine('<dl class="metadata">')
    foreach ($item in @(
        @('Tenant', $(if ($Model.Tenant.DisplayName) { $Model.Tenant.DisplayName } else { '(not resolved)' })),
        @('Identity check', $Model.Tenant.IdentityCheck),
        @('Observed at (UTC)', $Model.ObservedAtUtc),
        @('Collection duration', ('{0}s' -f $Model.DurationSeconds)),
        @('Deployment Plan ID', $Model.Plan.PlanId),
        @('Plan schema', $Model.Plan.SchemaVersion),
        @('Plan input SHA-256', $Model.Plan.PlanInputSha256),
        @('Validation run ID', $Model.ValidationRunId),
        @('Configuration SHA-256', $Model.Plan.ConfigurationSha256),
        @('Toolkit version', $Model.ToolkitVersion),
        @('Assessed actions', ('{0} of {0}' -f $Model.Summary.TotalActions)),
        @('Scored actions', $Model.Summary.ScoredActions)
    )) {
        $null = $sb.AppendLine(('<div class="meta-item"><dt>{0}</dt><dd class="mono">{1}</dd></div>' -f `
            (Encode $item[0]), (Encode $item[1])))
    }
    $null = $sb.AppendLine('</dl></section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-head"><h2>Service status</h2><p>Connection and capability status used for this read-only observation.</p></div><dl class="metadata">')
    $serviceProperties = if ($Model.ServiceStatus) { @($Model.ServiceStatus.PSObject.Properties) } else { @() }
    foreach ($property in $serviceProperties) {
        $null = $sb.AppendLine(('<div class="meta-item"><dt>{0}</dt><dd>{1}</dd></div>' -f `
            (Encode $property.Name), (Encode $property.Value)))
    }
    if (@($serviceProperties).Count -eq 0) {
        $null = $sb.AppendLine('<div class="meta-item"><dt>Status</dt><dd>Not recorded</dd></div>')
    }
    $null = $sb.AppendLine('</dl></section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-head"><h2>Guide tiers</h2><p>Proven requires readable evidence for every cumulative control. Provisional allows indeterminate blockers but not a known gap.</p></div>')
    $null = $sb.AppendLine(('<div class="notice"><strong>Proven:</strong> {0}<br><strong>Provisional:</strong> {1}</div>' -f `
        (Encode $Model.Summary.ProvenLevel), (Encode $Model.Summary.ProvisionalLevel)))
    $null = $sb.AppendLine('<table><thead><tr><th>Control</th><th>Tier</th><th>Baseline</th><th>Summary</th></tr></thead><tbody>')
    foreach ($control in @($Model.Guide.Controls)) {
        $null = $sb.AppendLine(('<tr><td><code>{0}</code></td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f `
            (Encode $control.ControlId), (Encode $control.Level), (Encode $control.Baseline), (Encode $control.Summary)))
    }
    $null = $sb.AppendLine('</tbody></table></section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-head"><h2>Module summary</h2>')
    $null = $sb.AppendLine('<p>Result counts for each toolkit module represented in the plan.</p></div>')
    $null = $sb.AppendLine('<table><thead><tr><th>Module</th><th>Actions</th><th>Matched</th><th>Drift</th><th>Not evaluated</th><th>Informational</th><th>Collection failed</th></tr></thead><tbody>')
    foreach ($module in $Model.Modules) {
        $null = $sb.AppendLine(('<tr><td><code>{0}</code></td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f `
            (Encode $module.Module), $module.Total, $module.Matched, $module.Drift, `
            $module.NotEvaluated, $module.Informational, $module.CollectionFailed))
    }
    $null = $sb.AppendLine('</tbody></table></section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-head"><h2>Configuration results</h2>')
    $null = $sb.AppendLine('<p>Expected and observed values are normalized before comparison. Only fields the toolkit owns are scored.</p></div>')
    $null = $sb.AppendLine('<div class="toolbar">')
    $null = $sb.AppendLine(('<button class="filter active" data-filter="all" type="button">All {0}</button>' -f $Model.Summary.TotalActions))
    foreach ($filter in @(
        @('matched', 'Matched', $Model.Summary.Matched),
        @('drift', 'Drift', $Model.Summary.Drift),
        @('not-evaluated', 'Not evaluated', $Model.Summary.NotEvaluated),
        @('informational', 'Informational', $Model.Summary.Informational),
        @('collection-failed', 'Collection failed', $Model.Summary.CollectionFailed)
    )) {
        $null = $sb.AppendLine(('<button class="filter" data-filter="{0}" type="button">{1} {2}</button>' -f `
            $filter[0], (Encode $filter[1]), $filter[2]))
    }
    $null = $sb.AppendLine('<input id="search" class="search" type="search" placeholder="Search action, module, or value">')
    $null = $sb.AppendLine('</div><div id="results">')

    foreach ($module in $Model.Modules) {
        $moduleResults = @($Model.Results | Where-Object Module -eq $module.Module)
        $null = $sb.AppendLine(('<details class="module" open data-module="{0}"><summary>{1} ({2} actions)</summary>' -f `
            (Encode $module.Module), (Encode $module.Module), $moduleResults.Count))

        foreach ($result in $moduleResults) {
            $statusClass = Get-PurviewValidationStatusClass -Status $result.Status
            $searchText = ('{0} {1} {2} {3} {4}' -f $result.Module, $result.ActionId, $result.Title,
                $result.ExpectedSummary, $result.ObservedSummary).ToLowerInvariant()

            $null = $sb.AppendLine(('<article class="result" data-status="{0}" data-search="{1}">' -f `
                $statusClass, (Encode $searchText)))
            $null = $sb.AppendLine('<div class="result-main">')
            $null = $sb.AppendLine(('<div><div class="action-title">{0}</div><div class="action-id mono">{1}</div></div>' -f `
                (Encode $result.Title), (Encode $result.ActionId)))
            $null = $sb.AppendLine(('<div><span class="status {0}">{1}</span></div>' -f `
                $statusClass, (Encode $result.Status)))
            $null = $sb.AppendLine(('<div><div class="cell-label">Expected</div><div class="cell-value mono">{0}</div></div>' -f `
                (Encode $result.ExpectedSummary)))
            $null = $sb.AppendLine(('<div><div class="cell-label">Observed</div><div class="cell-value mono">{0}</div></div>' -f `
                (Encode $result.ObservedSummary)))
            $null = $sb.AppendLine('</div><div class="result-detail">')
            $null = $sb.AppendLine(('<div class="detail-block"><strong>Assessment axes</strong><span>Observation: {0}<br>Intended state: {1}<br>Guide baseline: {2}</span></div>' -f `
                (Encode $result.Observation), (Encode $result.Intended), (Encode $result.Baseline)))

            $readDetail = if ($result.Query) {
                '{0}<br>{1}' -f (Encode $result.Query), (Encode $result.Source)
            } else {
                'No tenant read was attempted for this action.'
            }
            $null = $sb.AppendLine(('<div class="detail-block"><strong>Tenant read</strong><span class="mono">{0}</span><br><span>Attempts: {1} | Elapsed: {2} ms | Prerequisite: {3}</span></div>' -f `
                $readDetail, $result.Attempts, $result.ElapsedMs, (Encode $result.PrerequisiteDisposition)))
            $null = $sb.AppendLine(('<div class="detail-block"><strong>Evidence</strong><span>{0}</span>{1}</div>' -f `
                (Encode $result.Reason),
                $(if ($result.Error) { '<br><span class="mono">' + (Encode $result.Error) + '</span>' } else { '' })))
            $null = $sb.AppendLine(('<div class="detail-block"><strong>Next step</strong><span>{0}</span></div>' -f `
                (Encode $result.NextStep)))

            $unscored = @($result.UnscoredDifferences)
            if ($unscored.Count -gt 0) {
                $null = $sb.AppendLine('<div class="detail-block"><strong>Unscored differences</strong><ul>')
                foreach ($difference in $unscored) {
                    $null = $sb.AppendLine(('<li><code>{0}</code>: expected {1}, observed {2}</li>' -f `
                        (Encode $difference.Field), (Encode $difference.Expected), (Encode $difference.Observed)))
                }
                $null = $sb.AppendLine('</ul></div>')
            } else {
                $null = $sb.AppendLine('<div class="detail-block"><strong>Unscored differences</strong><span>None recorded.</span></div>')
            }

            $fields = @($result.Fields)
            if ($fields.Count -gt 0) {
                $null = $sb.AppendLine('<div class="detail-block"><strong>Managed fields</strong><ul>')
                foreach ($field in $fields) {
                    $null = $sb.AppendLine(('<li><code>{0}</code> [{1}] {2}: expected <span class="mono">{3}</span>, observed <span class="mono">{4}</span></li>' -f `
                        (Encode $field.Field), (Encode $field.Comparator),
                        $(if ($field.Matched) { 'matched' } else { 'differs' }),
                        (Encode $field.ExpectedText), (Encode $field.ObservedText)))
                }
                $null = $sb.AppendLine('</ul></div>')
            }

            $null = $sb.AppendLine('</div></article>')
        }

        $null = $sb.AppendLine('</details>')
    }

    $null = $sb.AppendLine('</div><div id="empty" class="empty" hidden>No validation results match this filter.</div></section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-head"><h2>Recommended next actions</h2>')
    $null = $sb.AppendLine('<p>Derived from final drift, unmet prerequisites, and read failures. This report makes no tenant changes.</p></div>')
    if (@($Model.Recommendations).Count -eq 0 -and
        @($Model.Guide.Blockers).Count -eq 0 -and
        @($Model.ManualChecks).Count -eq 0) {
        $null = $sb.AppendLine('<div class="empty">No follow-up is required. Every scored action matched the plan and no guide blockers remain.</div>')
    } elseif (@($Model.Recommendations).Count -eq 0) {
        $null = $sb.AppendLine('<div class="empty">No drift or read-failure follow-up is required, but guide blockers or manual checks remain in the sections below.</div>')
    } else {
        $null = $sb.AppendLine('<div class="next-grid">')
        foreach ($recommendation in $Model.Recommendations) {
            $null = $sb.AppendLine(('<article class="next-card"><div class="priority">{0}</div><h3>{1}</h3><p>{2}</p><p class="mono">{3}</p></article>' -f `
                (Encode $recommendation.Priority), (Encode $recommendation.Title),
                (Encode $recommendation.Detail), (Encode $recommendation.ActionId)))
        }
        $null = $sb.AppendLine('</div>')
    }
    $null = $sb.AppendLine('</section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-head"><h2>Extensions and manual checks</h2><p>Extensions are outside the primary guide mapping. Manual checks cannot be proven by the available read APIs.</p></div>')
    $null = $sb.AppendLine(('<div class="notice"><strong>Extensions:</strong> {0}<br><strong>Manual checks:</strong> {1}</div>' -f `
        @($Model.Extensions).Count, @($Model.ManualChecks).Count))
    $null = $sb.AppendLine('</section>')

    $null = $sb.AppendLine('<section class="section"><div class="section-head"><h2>Technical appendix</h2><p>Artifact identity, schema, mode, fingerprints, and diagnostics.</p></div><dl class="metadata">')
    foreach ($item in @(
        @('Artifact type', $Model.ArtifactType),
        @('Artifact reference', $Model.ArtifactReference),
        @('Schema version', $Model.SchemaVersion),
        @('Assessment mode', $Model.AssessmentMode),
        @('Plan input SHA-256', $Model.Plan.PlanInputSha256),
        @('Intended-state SHA-256', $Model.Plan.IntendedStateSha256)
    )) {
        $null = $sb.AppendLine(('<div class="meta-item"><dt>{0}</dt><dd class="mono">{1}</dd></div>' -f `
            (Encode $item[0]), (Encode $item[1])))
    }
    $null = $sb.AppendLine('</dl></section>')

    $null = $sb.AppendLine(('<footer>{0}. Validation run {1}. Read-only assessment; no tenant state was changed.</footer>' -f `
        (Encode $Model.ArtifactReference), (Encode $Model.ValidationRunId)))
    $null = $sb.AppendLine('</main>')

    # The only script in the artifact. It filters rows that are already present
    # and encoded in the document; it never receives tenant data as JavaScript.
    $null = $sb.AppendLine(@'
<script>
(function () {
  var active = "all";
  var search = document.getElementById("search");
  var empty = document.getElementById("empty");
  var results = Array.prototype.slice.call(document.querySelectorAll(".result"));
  var modules = Array.prototype.slice.call(document.querySelectorAll(".module"));

  function render() {
    var query = (search.value || "").trim().toLowerCase();
    var visible = 0;
    results.forEach(function (item) {
      var statusOk = active === "all" || item.dataset.status === active;
      var textOk = !query || (item.dataset.search || "").indexOf(query) !== -1;
      var show = statusOk && textOk;
      item.hidden = !show;
      if (show) { visible++; }
    });
    modules.forEach(function (module) {
      var shown = Array.prototype.slice.call(module.querySelectorAll(".result"))
        .filter(function (item) { return !item.hidden; });
      module.hidden = shown.length === 0;
    });
    empty.hidden = visible !== 0;
  }

  Array.prototype.slice.call(document.querySelectorAll(".filter")).forEach(function (button) {
    button.addEventListener("click", function () {
      Array.prototype.slice.call(document.querySelectorAll(".filter")).forEach(function (other) {
        other.classList.remove("active");
      });
      button.classList.add("active");
      active = button.dataset.filter;
      render();
    });
  });
  search.addEventListener("input", render);
  render();
})();
</script>
'@)
    $null = $sb.AppendLine('</body></html>')
    return $sb.ToString()
}

function Write-PurviewValidationReport {
    <#
        Writes the HTML report and the JSON sidecar next to it.

        Writes use -WhatIf:$false because local evidence is not a tenant
        change. A validation run that produced no artifact would be exactly the
        run an operator most needs to read.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [psobject] $Model,
        [Parameter(Mandatory)] [string] $OutputPath
    )

    $extension = [IO.Path]::GetExtension($OutputPath)
    if ($extension -notin @('.html', '.htm')) {
        throw [NotSupportedException]::new(
            "Validation report output path must use an .html or .htm extension: $OutputPath"
        )
    }
    $jsonPath = [IO.Path]::ChangeExtension($OutputPath, '.json')
    $resolvedHtmlPath = [IO.Path]::GetFullPath($OutputPath)
    $resolvedJsonPath = [IO.Path]::GetFullPath($jsonPath)
    if ($resolvedHtmlPath.Equals($resolvedJsonPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Validation report HTML and JSON output paths must be different.'
    }

    $directory = Split-Path -Parent $OutputPath
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force -WhatIf:$false | Out-Null
    }

    $html = ConvertTo-PurviewValidationHtml -Model $Model
    $json = $Model | ConvertTo-Json -Depth 25

    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8 -NoNewline -WhatIf:$false
    Set-Content -LiteralPath $jsonPath -Value $json -Encoding UTF8 -NoNewline -WhatIf:$false

    return [pscustomobject]@{
        HtmlPath = $OutputPath
        JsonPath = $jsonPath
        ValidationRunId = $Model.ValidationRunId
        PlanId = $Model.Plan.PlanId
    }
}
