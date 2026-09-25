#requires -Version 7.0
<#
.SYNOPSIS
    Deploys the Microsoft Intune best-practice baseline.

.DESCRIPTION
    Applies the device enrollment and device management baseline from the
    Device Management Deployment Guide for Small Business (Business Premium /
    Intune Plan 1) using Purview- and Defender-compatible orchestration
    semantics.

    The current release includes five automated assessments, six guarded tenant
    write paths, guided portal tasks, and structured HTML/JSON evidence.
    Standard writes remain pilot-first and every high-risk write requires the
    documented approval gates. The imported policy catalog remains blocked.

.PARAMETER PilotGroupId
    Entra group object ID that policies are assigned to. The toolkit defaults to
    a pilot group rather than the source guide's "add all users" instruction,
    because enrollment restrictions, compliance enforcement, and Conditional
    Access can deny access to every user in the tenant on a first run.

.PARAMETER DelegatedOrganization
    Customer tenant domain for a GDAP delegated run. Graph authenticates
    directly to this tenant rather than the administrator's home tenant.
    Tenant identity is verified against this domain (or, absent it, the
    TenantAdminUpn domain) after connection.

.PARAMETER AutoInstallModules
    Install missing Microsoft Graph modules (Microsoft.Graph.Authentication and
    Microsoft.Graph.DeviceManagement) to CurrentUser without prompting.

.PARAMETER AssignTenantWide
    Opt in to tenant-wide assignment instead of a pilot group. This reproduces
    the source guide literally and is deliberately not the default.

.PARAMETER IncludeHighRisk
    Required before any high-risk baseline item is considered. Requires
    CustomerApprovalId so the customer authorization is recorded in evidence.

.PARAMETER EnableComplianceEnforcement
    Opt in to marking devices with no compliance policy as not compliant. This
    is inert until a device-based Conditional Access policy exists, at which
    point it becomes an access denial. Requires IncludeHighRisk.

.PARAMETER EnableEnrollmentRestrictions
    Opt in to creating device platform enrollment restrictions. A misconfigured
    restriction blocks the enrollment the rest of the baseline depends on.
    Requires IncludeHighRisk.

.PARAMETER EnableConditionalAccessEnforcement
    Opt in to creating the device-based Conditional Access policy. The policy
    uses ConditionalAccess.DefaultState, which is report-only by default.
    Promotion to enabled is a separate configuration and change decision. This
    is the highest blast-radius action in the baseline and requires
    IncludeHighRisk, BreakGlassExclusionsConfirmed, and RollbackAcknowledged.

.PARAMETER BreakGlassExclusionsConfirmed
    Operator confirmation that emergency-access accounts are excluded from the
    Conditional Access policy.

.PARAMETER BreakGlassUserIds
    Emergency-access user object IDs to write into the Conditional Access
    policy exclusion list. At least one user or group ID is required when the
    policy creation gate is selected.

.PARAMETER BreakGlassGroupIds
    Emergency-access group object IDs to write into the Conditional Access
    policy exclusion list. At least one user or group ID is required when the
    policy creation gate is selected.

.PARAMETER EnablePolicyCatalogWrite
    Reserved opt-in for future writes based on the imported 19-payload policy
    catalog. Always denies the run today. The source used Microsoft Graph beta,
    and did not provide this repository's tenant permission, pilot, readback,
    preservation, assignment, or rollback evidence.

.LINK
    https://learn.microsoft.com/intune/intune-service/fundamentals/deployment-guide-enrollment
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')] [string] $TenantAdminUpn,
    [ValidatePattern('^[^@\s]+\.[^@\s]+$')]     [string] $DelegatedOrganization,
    [string] $ConfigPath,
    [switch] $AutoInstallModules,
    [switch] $NonInteractive,
    [switch] $NoLicenseAutoDetect,
    [switch] $AdoptExisting,
    [switch] $SkipPreflight,
    [switch] $SkipEnrollmentPrerequisites,
    [switch] $SkipEnrollmentRestrictions,
    [switch] $SkipComplianceBaseline,
    [switch] $SkipDeviceCompliancePolicies,
    [switch] $SkipAppProtectionPolicies,
    [switch] $SkipAppDeployment,
    [switch] $SkipEnterpriseStateRoaming,
    [switch] $SkipDeviceConditionalAccess,
    [switch] $IncludeHighRisk,
    [string] $CustomerApprovalId,
    [string] $ApprovalArtifactPath,
    [switch] $RollbackAcknowledged,
    [switch] $EnableComplianceEnforcement,
    [switch] $EnableEnrollmentRestrictions,
    [switch] $EnableConditionalAccessEnforcement,
    [switch] $BreakGlassExclusionsConfirmed,
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')]
    [string[]] $BreakGlassUserIds = @(),
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')]
    [string[]] $BreakGlassGroupIds = @(),
    [switch] $AssignTenantWide,
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')] [string] $PilotGroupId,
    [switch] $EnablePolicyCatalogWrite
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleRoot = Join-Path $scriptRoot 'Modules'
$runId = [guid]::NewGuid()
$startTime = [datetime]::UtcNow
$jsonPath = $null
$htmlPath = $null
$resolvedTenantId = $null

. (Join-Path $moduleRoot 'IntuneRunLog.ps1')
. (Join-Path $moduleRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $moduleRoot 'Write-IntuneHtmlReport.ps1')

function Test-IntuneConfigContract {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Config)

    # Sections are verified first. The per-item loop below dereferences
    # LicenseCapabilities, and without this guard a config missing that section
    # dies with "You cannot call a method on a null-valued expression", which is
    # precisely the cryptic failure this function exists to prevent.
    foreach ($section in @('BestPracticeItems', 'LicenseCapabilities', 'Assignment',
                           'Preflight', 'ApplePushCertificate', 'ConditionalAccess',
                           'PolicyCatalog', 'Report', 'Api')) {
        if (-not $Config.ContainsKey($section)) {
            throw "Intune configuration must define a '$section' section."
        }
    }
    if (-not $Config.BestPracticeItems) {
        throw 'Intune configuration must define at least one BestPracticeItems entry.'
    }
    if ([string]::IsNullOrWhiteSpace([string] $Config.PolicyCatalog.ManifestPath)) {
        throw 'PolicyCatalog.ManifestPath must identify the imported catalog manifest.'
    }
    if ($Config.PolicyCatalog.RequiredEntryCount -isnot [int] -or
        $Config.PolicyCatalog.RequiredEntryCount -lt 1) {
        throw 'PolicyCatalog.RequiredEntryCount must be a positive integer.'
    }

    $validRisk = @('Standard', 'High')
    $validDisposition = @('Applicable', 'AlreadyCompliant', 'WillChange', 'GuidedOnly', 'Skipped', 'Blocked')

    # Booleans must be real booleans. A string such as 'false' is truthy in
    # PowerShell, so a quoted value in the data file would silently invert a
    # safety control.
    foreach ($flag in @('RequirePilotGroupForHighRisk', 'AllowTenantWideAssignmentForHighRisk')) {
        if (-not $Config.Assignment.ContainsKey($flag)) {
            throw "Assignment section must define '$flag'."
        }
        if ($Config.Assignment[$flag] -isnot [bool]) {
            throw "Assignment.$flag must be a boolean, not '$($Config.Assignment[$flag].GetType().Name)'. A quoted string is always truthy and would disable this control."
        }
    }

    # Dispositions are passed straight into a ValidateSet parameter. Validating
    # them here fails the run before any connection instead of part-way through
    # preflight.
    foreach ($key in @($Config.Preflight.Keys)) {
        if ($Config.Preflight[$key] -notin $validDisposition) {
            throw "Preflight.$key is '$($Config.Preflight[$key])', which is not a valid disposition. Valid values: $($validDisposition -join ', ')."
        }
    }

    if (-not $Config.ApplePushCertificate.ContainsKey('RenewalWarningDays') -or
        $Config.ApplePushCertificate.RenewalWarningDays -isnot [int] -or
        $Config.ApplePushCertificate.RenewalWarningDays -lt 1 -or
        $Config.ApplePushCertificate.RenewalWarningDays -gt 90) {
        throw 'ApplePushCertificate.RenewalWarningDays must be an integer from 1 through 90.'
    }

    if (-not $Config.ConditionalAccess.ContainsKey('DefaultState') -or
        [string]::IsNullOrWhiteSpace([string] $Config.ConditionalAccess.DefaultState)) {
        throw 'ConditionalAccess section must define DefaultState.'
    }
    # Validated by value, not just presence. This is the state the highest
    # blast-radius policy is created in, so a typo must fail the run rather than
    # be carried into a Conditional Access decision.
    $validConditionalAccessState = 'enabledForReportingButNotEnforced'
    if ($Config.ConditionalAccess.DefaultState -ne $validConditionalAccessState) {
        throw "ConditionalAccess.DefaultState must remain '$validConditionalAccessState' in the current release. Enforcement is a separate portal change after exclusions, sign-in evidence, and rollback are verified."
    }
    foreach ($key in @('OutputDirectory', 'JsonLogFileName', 'HtmlReportFileName')) {
        if ([string]::IsNullOrWhiteSpace([string] $Config.Report[$key])) {
            throw "Report section must define '$key'."
        }
    }

    $keys = @()
    $guideTasks = @()
    foreach ($item in @($Config.BestPracticeItems)) {
        foreach ($property in @('Key', 'Name', 'Module', 'Risk')) {
            if ([string]::IsNullOrWhiteSpace([string] $item[$property])) {
                throw "BestPracticeItems entries must define '$property'."
            }
        }
        if ([string]::IsNullOrWhiteSpace([string] $item.LicenseCapability) -or
            -not $Config.LicenseCapabilities.ContainsKey([string] $item.LicenseCapability)) {
            throw "BestPracticeItems entry '$($item.Key)' must reference a configured LicenseCapability."
        }
        if ($item.Key -notmatch '^[a-z0-9]+(?:-[a-z0-9]+)+$') {
            throw "BestPracticeItems key '$($item.Key)' must be lowercase kebab-case."
        }
        if ($keys -contains $item.Key) {
            throw "Duplicate BestPracticeItems key '$($item.Key)'."
        }
        if ($item.Priority -notin @(1, 2, 3)) {
            throw "BestPracticeItems entry '$($item.Key)' must declare Priority 1, 2, or 3."
        }
        if ($item.Risk -notin $validRisk) {
            throw "BestPracticeItems entry '$($item.Key)' declares Risk '$($item.Risk)'; valid values are $($validRisk -join ', ')."
        }
        if ($item.RequiresHighRiskGate -isnot [bool]) {
            throw "BestPracticeItems entry '$($item.Key)' must declare RequiresHighRiskGate as a boolean."
        }
        # Risk and the gate flag drive real enforcement below, so an
        # inconsistent pair would silently under-gate a dangerous item.
        if ($item.Risk -eq 'High' -and -not $item.RequiresHighRiskGate) {
            throw "BestPracticeItems entry '$($item.Key)' is Risk High but does not set RequiresHighRiskGate."
        }
        if ($guideTasks -contains $item.GuideTask) {
            throw "Duplicate GuideTask '$($item.GuideTask)' on BestPracticeItems entry '$($item.Key)'."
        }
        $keys += $item.Key
        $guideTasks += $item.GuideTask
    }
}

function Deny-IntuneRun {
    <#
        Records a refused run as evidence, then throws. A gate failure is a
        deployment outcome the operator needs in the report, not just a console
        exception, so the refusal is logged with a Blocked disposition before
        the run terminates.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Gate,
        [Parameter(Mandatory)] [string] $Reason
    )

    if (Test-IntuneRunLogInitialized) {
        Add-IntuneRunLogEntry -Module 'Deploy-IntuneBestPractice' `
            -Action $Gate -Status 'Skipped' -Disposition 'Blocked' `
            -Detail $Reason
    }
    throw $Reason
}

$tasks = @()
try {
    # Config and evidence are established before any gate is evaluated, so that
    # a rejected run still produces a report. Previously the run log was
    # initialised after gate validation, which meant a blocked high-risk
    # invocation left no JSON and no HTML at all - the operator got a bare
    # exception and no record of what was refused or why.
    if (-not $ConfigPath) {
        $ConfigPath = Join-Path $scriptRoot 'Config\IntuneConfig.psd1'
    }
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Config file not found: $ConfigPath"
    }

    $config = Import-PowerShellDataFile -Path $ConfigPath
    Test-IntuneConfigContract -Config $config

    $reportDirectory = Join-Path $scriptRoot $config.Report.OutputDirectory
    $jsonPath = Join-Path $reportDirectory $config.Report.JsonLogFileName
    $htmlPath = Join-Path $reportDirectory $config.Report.HtmlReportFileName
    Initialize-IntuneRunLog -JsonPath $jsonPath -RunId $runId `
        -StartTime $startTime -ScriptVersion $config.ProductVersion `
        -TenantAdminUpn $TenantAdminUpn

    $tasks = @(
        @{ Name = 'Setup-IntunePreflight'; Script = 'Setup-IntunePreflight.ps1'; Skip = $SkipPreflight; Args = @{ Config = $config; TenantAdminUpn = $TenantAdminUpn; NoLicenseAutoDetect = $NoLicenseAutoDetect } }
        @{ Name = 'Setup-EnrollmentPrerequisites'; Script = 'Setup-EnrollmentPrerequisites.ps1'; Skip = $SkipEnrollmentPrerequisites; Args = @{ Config = $config; AdoptExisting = $AdoptExisting } }
        @{ Name = 'Setup-ComplianceBaseline'; Script = 'Setup-ComplianceBaseline.ps1'; Skip = $SkipComplianceBaseline; Args = @{ Config = $config; AdoptExisting = $AdoptExisting; IncludeHighRisk = $IncludeHighRisk; EnableComplianceEnforcement = $EnableComplianceEnforcement } }
        @{ Name = 'Setup-DeviceCompliancePolicies'; Script = 'Setup-DeviceCompliancePolicies.ps1'; Skip = $SkipDeviceCompliancePolicies; Args = @{ Config = $config; AdoptExisting = $AdoptExisting; IncludeHighRisk = $IncludeHighRisk } }
        @{ Name = 'Setup-EnrollmentRestrictions'; Script = 'Setup-EnrollmentRestrictions.ps1'; Skip = $SkipEnrollmentRestrictions; Args = @{ Config = $config; AdoptExisting = $AdoptExisting; IncludeHighRisk = $IncludeHighRisk; EnableEnrollmentRestrictions = $EnableEnrollmentRestrictions } }
        @{ Name = 'Setup-AppProtectionPolicies'; Script = 'Setup-AppProtectionPolicies.ps1'; Skip = $SkipAppProtectionPolicies; Args = @{ Config = $config; AdoptExisting = $AdoptExisting; PilotGroupId = $PilotGroupId } }
        @{ Name = 'Setup-AppDeployment'; Script = 'Setup-AppDeployment.ps1'; Skip = $SkipAppDeployment; Args = @{ Config = $config; AdoptExisting = $AdoptExisting } }
        @{ Name = 'Setup-EnterpriseStateRoaming'; Script = 'Setup-EnterpriseStateRoaming.ps1'; Skip = $SkipEnterpriseStateRoaming; Args = @{ Config = $config } }
        @{ Name = 'Setup-DeviceConditionalAccess'; Script = 'Setup-DeviceConditionalAccess.ps1'; Skip = $SkipDeviceConditionalAccess; Args = @{ Config = $config; IncludeHighRisk = $IncludeHighRisk; EnableConditionalAccessEnforcement = $EnableConditionalAccessEnforcement; BreakGlassExclusionsConfirmed = $BreakGlassExclusionsConfirmed; RollbackAcknowledged = $RollbackAcknowledged } }
    )

    Add-IntuneRunLogEntry -Module 'Deploy-IntuneBestPractice' `
        -Action 'Run' -Status 'Started' -Detail 'Intune scaffold run started.'

    # The imported 19-payload policy catalog remains apply-blocked pending API
    # and tenant-permission verification, pilot-only assignment, readback,
    # preservation, rollback, and recovery evidence.
    if ($EnablePolicyCatalogWrite) {
        Deny-IntuneRun -Gate 'EnablePolicyCatalogWrite' `
            -Reason 'EnablePolicyCatalogWrite is not yet supported. Imported policy payloads remain blocked pending API and tenant-permission verification, pilot-only assignment, readback, preservation, rollback, and recovery evidence.'
    }

    if ($IncludeHighRisk -and [string]::IsNullOrWhiteSpace($CustomerApprovalId)) {
        Deny-IntuneRun -Gate 'IncludeHighRisk' -Reason 'IncludeHighRisk requires CustomerApprovalId.'
    }
    if ($ApprovalArtifactPath) {
        if (-not (Test-Path -LiteralPath $ApprovalArtifactPath -PathType Leaf)) {
            Deny-IntuneRun -Gate 'ApprovalArtifact' `
                -Reason 'The configured approval artifact was not found.'
        }
        if ((Get-Item -LiteralPath $ApprovalArtifactPath).Length -eq 0) {
            Deny-IntuneRun -Gate 'ApprovalArtifact' `
                -Reason 'The configured approval artifact is empty.'
        }
    }

    # Record the customer authorisation itself. Without this the approval is
    # accepted but never appears in evidence, so the report cannot show who
    # authorised a high-risk change.
    if ($IncludeHighRisk) {
        $approvalReferenceHash = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                [Text.Encoding]::UTF8.GetBytes($CustomerApprovalId)
            )
        )
        $approvalDetail = "High-risk operations authorised. CustomerApprovalReferenceSha256=$approvalReferenceHash."
        if ($ApprovalArtifactPath) {
            $artifactHash = (Get-FileHash -LiteralPath $ApprovalArtifactPath -Algorithm SHA256).Hash
            $approvalDetail += " ApprovalArtifactSha256=$artifactHash."
        }
        Add-IntuneRunLogEntry -Module 'Deploy-IntuneBestPractice' `
            -Action 'HighRiskApproval' -Status 'Info' -Disposition 'Applicable' `
            -Detail $approvalDetail
    }

    $categoryGates = @(
        @{ Enabled = $EnableComplianceEnforcement; Name = 'EnableComplianceEnforcement' }
        @{ Enabled = $EnableEnrollmentRestrictions; Name = 'EnableEnrollmentRestrictions' }
        @{ Enabled = $EnableConditionalAccessEnforcement; Name = 'EnableConditionalAccessEnforcement' }
    )
    foreach ($gate in $categoryGates) {
        if ($gate.Enabled -and -not $IncludeHighRisk) {
            Deny-IntuneRun -Gate $gate.Name -Reason "$($gate.Name) requires IncludeHighRisk."
        }
    }

    # Conditional Access is the only item that can lock an administrator out of
    # the tenant, so it carries the strictest gate in the product.
    if ($EnableConditionalAccessEnforcement) {
        if (-not $BreakGlassExclusionsConfirmed) {
            Deny-IntuneRun -Gate 'EnableConditionalAccessEnforcement' `
                -Reason 'EnableConditionalAccessEnforcement requires BreakGlassExclusionsConfirmed.'
        }
        if (-not $RollbackAcknowledged) {
            Deny-IntuneRun -Gate 'EnableConditionalAccessEnforcement' `
                -Reason 'EnableConditionalAccessEnforcement requires RollbackAcknowledged.'
        }
        if (@($BreakGlassUserIds).Count -eq 0 -and
            @($BreakGlassGroupIds).Count -eq 0) {
            Deny-IntuneRun -Gate 'EnableConditionalAccessEnforcement' `
                -Reason 'EnableConditionalAccessEnforcement requires at least one BreakGlassUserIds or BreakGlassGroupIds value so the exclusion is written into the policy.'
        }
    }

    # Tenant-wide assignment reproduces the source guide literally and removes
    # the pilot blast-radius control, so it is an explicit acknowledged opt-in.
    if ($AssignTenantWide -and -not $RollbackAcknowledged) {
        Deny-IntuneRun -Gate 'AssignTenantWide' -Reason 'AssignTenantWide requires RollbackAcknowledged.'
    }

    if ($IncludeHighRisk -and
        $config.Assignment.RequirePilotGroupForHighRisk -and
        -not $AssignTenantWide -and
        [string]::IsNullOrWhiteSpace($PilotGroupId)) {
        Deny-IntuneRun -Gate 'PilotGroup' `
            -Reason 'High-risk items require PilotGroupId, or AssignTenantWide with RollbackAcknowledged.'
    }
    # The configuration key is named for exactly what it controls: whether a
    # high-risk run may go tenant-wide. It is not an absolute veto, and naming
    # it as one would mislead a config author into relying on it.
    if ($AssignTenantWide -and -not $config.Assignment.AllowTenantWideAssignmentForHighRisk) {
        Deny-IntuneRun -Gate 'AssignTenantWide' `
            -Reason 'AssignTenantWide is disabled by Assignment.AllowTenantWideAssignmentForHighRisk in configuration.'
    }

    if ($WhatIfPreference) {
        Add-IntuneRunLogEntry -Module 'Deploy-IntuneBestPractice' `
            -Action 'WhatIf' -Status 'Info' `
            -Detail 'WhatIf preview enabled; child modules may not change tenant state.'
    }

    $assignmentScope = if ($AssignTenantWide) { 'TenantWide' } else { 'PilotGroup' }
    Add-IntuneRunLogEntry -Module 'Deploy-IntuneBestPractice' `
        -Action 'AssignmentScope' -Status 'Info' `
        -Detail "Assignment scope is $assignmentScope. The source guide recommends all users; this toolkit defaults to a pilot group."

    # Risk and RequiresHighRiskGate drive real enforcement rather than being
    # descriptive metadata. An item that needs the high-risk gate and did not
    # get it is recorded as blocked here and named in the context, so a module
    # cannot act on it even when the module itself was not skipped. Modules map
    # to more than one baseline item, so this has to be per item, not per
    # module.
    #
    # Global approval is necessary but not sufficient. Each high-risk category
    # also has its own enable switch, and the blocklist has to agree with the
    # gate a module will apply. Evaluating both here keeps one answer to
    # "may this item be acted on", instead of leaving a module free to act on an
    # item whose category approval was never given.
    $categorySwitchByItemKey = @{
        'default-compliance-settings' = @{ Name = 'EnableComplianceEnforcement'; Enabled = [bool] $EnableComplianceEnforcement }
        'enrollment-restrictions' = @{ Name = 'EnableEnrollmentRestrictions'; Enabled = [bool] $EnableEnrollmentRestrictions }
        'device-conditional-access' = @{ Name = 'EnableConditionalAccessEnforcement'; Enabled = [bool] $EnableConditionalAccessEnforcement }
    }

    $blockedItemKeys = @()
    $writeBlockedItemKeys = @()
    foreach ($item in @($config.BestPracticeItems | Sort-Object Priority, GuideTask)) {
        Add-IntuneRunLogEntry -Module $item.Module -Action 'ConfiguredItem' `
            -BestPracticeKey $item.Key -Status 'Info' `
            -Detail "Configured recommendation (priority $($item.Priority), guide task $($item.GuideTask), risk $($item.Risk)): $($item.Name)."

        $blockReason = $null
        if ($item.RequiresHighRiskGate -and -not $IncludeHighRisk) {
            $blockReason = "item is Risk $($item.Risk) and requires IncludeHighRisk, which was not supplied"
        }
        elseif ($categorySwitchByItemKey.ContainsKey([string] $item.Key) -and
                -not $categorySwitchByItemKey[[string] $item.Key].Enabled) {
            $blockReason = "item requires $($categorySwitchByItemKey[[string] $item.Key].Name), which was not supplied"
        }

        if ($blockReason -and [string] $item.Key -in @(
                'default-compliance-settings',
                    'enrollment-restrictions',
                    'device-compliance-policies'
            )) {
            $writeBlockedItemKeys += $item.Key
            Add-IntuneRunLogEntry -Module $item.Module -Action 'WriteRiskGate' `
                -BestPracticeKey $item.Key -Status 'Info' `
                -Detail "Write authorization withheld: $blockReason."
        }
        elseif ($blockReason) {
            $blockedItemKeys += $item.Key
            Add-IntuneRunLogEntry -Module $item.Module -Action 'RiskGate' `
                -BestPracticeKey $item.Key -Status 'Skipped' -Disposition 'Blocked' `
                -Detail "Blocked: $blockReason."
        }
    }

    $connectScript = Join-Path $moduleRoot 'Connect-IntuneServices.ps1'
    $connectArgs = @{
        TenantAdminUpn = $TenantAdminUpn
        DelegatedOrganization = $DelegatedOrganization
        Scopes = $config.Api.GraphScopes
        GraphBaseUri = $config.Api.GraphBaseUri
        NonInteractive = $NonInteractive
        ConnectGraph = $true
    }
    if ($AutoInstallModules) { $connectArgs.AutoInstallModules = $true }
    $connectionInfo = & $connectScript @connectArgs
    $resolvedTenantId = [string]$connectionInfo.TenantIdentity.TenantId
    if ([string]::IsNullOrWhiteSpace($resolvedTenantId)) {
        throw 'The verified Microsoft Graph connection did not return a tenant ID.'
    }
    Set-IntuneRunTenantId -TenantId $resolvedTenantId

    $commonContext = @{
        TenantAdminUpn = $TenantAdminUpn
        TenantId = $resolvedTenantId
        ConnectionInfo = $connectionInfo
        DelegatedOrganization = $DelegatedOrganization
        CustomerApprovalId = $CustomerApprovalId
        ApprovalArtifactPath = $ApprovalArtifactPath
        IncludeHighRisk = [bool] $IncludeHighRisk
        RollbackAcknowledged = [bool] $RollbackAcknowledged
        PilotGroupId = $PilotGroupId
        BreakGlassUserIds = @($BreakGlassUserIds)
        BreakGlassGroupIds = @($BreakGlassGroupIds)
        AssignmentScope = $assignmentScope
        BlockedItemKeys = $blockedItemKeys
        WriteBlockedItemKeys = $writeBlockedItemKeys
        ApplicabilityPath = (Join-Path $reportDirectory 'intune-applicability.json')
        WhatIf = [bool] $WhatIfPreference
        NonInteractive = [bool] $NonInteractive
    }

    foreach ($task in $tasks) {
        if ($task.Skip) {
            Add-IntuneRunLogEntry -Module $task.Name -Action 'Module' `
                -Status 'Skipped' -Detail 'Skip switch was supplied.'
            continue
        }

        $taskPath = Join-Path $moduleRoot $task.Script
        if (-not (Test-Path -LiteralPath $taskPath -PathType Leaf)) {
            Add-IntuneRunLogEntry -Module $task.Name -Action 'Module' `
                -Status 'Failed' -Detail "Module script not found: $taskPath"
            throw "Module script not found: $taskPath"
        }
        Add-IntuneRunLogEntry -Module $task.Name -Action 'Module' `
            -Status 'Started' -Detail 'Module process started.'
        $taskArgs = $task.Args
        $taskArgs.Context = $commonContext
        if ($WhatIfPreference) {
            $taskArgs['WhatIf'] = $true
        }
        try {
            & $taskPath @taskArgs
            Add-IntuneRunLogEntry -Module $task.Name -Action 'Module' `
                -Status 'Succeeded' -Detail 'Module process completed.'

            # Preflight determines which baseline items the tenant can actually
            # support. Fold its result into the blocked set so later modules
            # cannot act on an unlicensed item. Without this the preflight only
            # produces commentary and every module runs regardless.
            if ($task.Name -eq 'Setup-IntunePreflight' -and
                (Test-Path -LiteralPath $commonContext.ApplicabilityPath -PathType Leaf)) {
                $applicability = Get-Content -LiteralPath $commonContext.ApplicabilityPath -Raw |
                    ConvertFrom-Json
                foreach ($key in @($applicability.unavailableItemKeys)) {
                    if ($blockedItemKeys -notcontains $key) { $blockedItemKeys += $key }
                }
                $commonContext.BlockedItemKeys = $blockedItemKeys
                # Later tasks receive this updated blocklist through the
                # shared context at dispatch.
                Add-IntuneRunLogEntry -Module 'Deploy-IntuneBestPractice' `
                    -Action 'Applicability' -Status 'Info' `
                    -Detail "Blocked baseline items after preflight: $(@($blockedItemKeys).Count)."
            }
        }
        catch {
            $status = Get-IntuneHttpStatusCode -ErrorRecord $_
            Add-IntuneRunLogEntry -Module $task.Name -Action 'Module' `
                -Status 'Failed' -HttpStatusCode $status `
                -Detail $_.Exception.Message
            throw
        }
    }

    Add-IntuneRunLogEntry -Module 'Deploy-IntuneBestPractice' `
        -Action 'Run' -Status 'Succeeded' -Detail 'Intune scaffold run completed.'
}
catch {
    $status = Get-IntuneHttpStatusCode -ErrorRecord $_
    if (Test-IntuneRunLogInitialized) {
        Add-IntuneRunLogEntry -Module 'Deploy-IntuneBestPractice' `
            -Action 'Run' -Status 'Failed' -HttpStatusCode $status `
            -Detail $_.Exception.Message
        $entries = Get-IntuneRunLog
        $recordedModules = @($entries | Where-Object Action -eq 'Module' | Select-Object -ExpandProperty Module -Unique)
        foreach ($task in $tasks) {
            if ($task.Name -in $recordedModules) { continue }
            $disposition = if ($task.Skip) { 'Skipped' } else { 'Blocked' }
            $detail = if ($task.Skip) { 'Skip switch was supplied.' } else {
                'Not started because an earlier prerequisite or module failed. No assessment or deployment was performed by this module.'
            }
            Add-IntuneRunLogEntry -Module $task.Name -Action 'Module' -Status 'Skipped' `
                -Disposition $disposition -Detail $detail
        }
    }
    throw
}
finally {
    if (Test-IntuneRunLogInitialized) {
        $endTime = [datetime]::UtcNow
        try {
            $writtenJsonPath = Save-IntuneRunLogJson -EndTime $endTime -PassThru
            if ($writtenJsonPath) {
                Write-Host ("`nJSON run log written: {0}" -f $writtenJsonPath) -ForegroundColor Cyan
            }
            try {
                Write-IntuneHtmlReport -Path $htmlPath -Entries (Get-IntuneRunLog) `
                    -RunId $runId -StartTime $startTime -EndTime $endTime `
                    -TenantId $resolvedTenantId -TenantAdminUpn $TenantAdminUpn `
                    -ScriptVersion $config.ProductVersion `
                    -WhatIfRun:([bool] $WhatIfPreference)
                $writtenHtmlPath = (Resolve-Path -LiteralPath $htmlPath -ErrorAction Stop).ProviderPath
                Write-Host ("HTML report written: {0}" -f $writtenHtmlPath) -ForegroundColor Cyan
                Write-Host ("Open report: Invoke-Item -LiteralPath '{0}'" -f $writtenHtmlPath.Replace("'", "''")) -ForegroundColor Cyan
            }
            catch {
                Write-Warning ("HTML report could not be written: {0}" -f $_.Exception.Message) -WarningAction Continue
            }
        }
        finally {
            Clear-IntuneRunLog
        }
    }
}
