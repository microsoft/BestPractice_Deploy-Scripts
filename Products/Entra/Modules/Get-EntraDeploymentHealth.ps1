#requires -Version 7.0
<#
.SYNOPSIS
    Read-only post-deployment health check for the Entra Conditional Access
    baseline.

.DESCRIPTION
    Answers one question an operator cannot answer by re-running the deployment:
    has anything drifted since the baseline was deployed, in a way that could
    lock administrators out of the tenant?

    The check that matters most is break-glass exclusion drift. Every policy the
    toolkit creates excludes the emergency-access principals. If someone later
    edits a policy and drops that exclusion, nothing breaks while the policy is
    report-only, and then the tenant locks every administrator out the moment
    that policy is promoted to enforcing. A report-only policy missing its
    exclusion is a warning; an enforcing policy missing its exclusion is an
    active lockout risk.

    Read-only by construction. It issues GET requests only, changes no tenant
    state, and is therefore safe to run on a schedule. It reports findings
    rather than throwing on them, because an operator needs the whole picture,
    not the first problem. It does throw when it cannot read the policy list at
    all, since a partial answer about lockout risk is worse than no answer.

    Break-glass ROLE verification (permanently assigned Global Administrator)
    runs both before deployment and again here, so losing the role after
    deployment cannot leave an enabled but unusable emergency account looking
    healthy. Both modules use the same shared recovery check.

    Uses only Graph scopes the product already requests. It adds no permission.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'None')]
param(
    [Parameter(Mandatory)] [hashtable] $Config,
    [hashtable] $Context
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'EntraRunLog.ps1')
. (Join-Path $PSScriptRoot 'EntraGraphClient.ps1')
. (Join-Path $PSScriptRoot 'Invoke-WithTransientRetry.ps1')
. (Join-Path $PSScriptRoot 'EntraPolicyComparison.ps1')
. (Join-Path $PSScriptRoot 'EntraDirectoryReads.ps1')
. (Join-Path $PSScriptRoot 'EntraSecurityDefaults.ps1')

$module = 'Get-EntraDeploymentHealth'
$bestPracticeKey = 'deployment-health'
$ca = $Config.ConditionalAccess
Assert-EntraPolicyMigrationConfig -ConditionalAccess $ca

$v1 = $Config.Api.GraphBaseUri
$securityDefaultsState = Get-EntraSecurityDefaultsState -BaseUri $v1 -Module $module
$breakGlassUsers = @(@($Context.BreakGlassUserIds) | Where-Object { $_ })
$breakGlassGroups = @(@($Context.BreakGlassGroupIds) | Where-Object { $_ })

Add-EntraRunLogEntry -Module $module -Action 'HealthCheck' -BestPracticeKey $bestPracticeKey `
    -Status 'Started' -Detail 'Read-only deployment health check started. No tenant state is changed.'

# Fail closed on the read. Reporting "no lockout risk found" after a failed or
# partial enumeration would be actively misleading, so stop instead. Every page
# is followed: a tenant with more policies than fit in one response could
# otherwise hide an enforcing policy with a missing exclusion on page two.
try {
    $allPolicies = Get-EntraGraphCollection -BaseUri $v1 `
        -Uri "$v1/identity/conditionalAccess/policies" `
        -Description 'Read Conditional Access policies for health check'
}
catch {
    Add-EntraRunLogEntry -Module $module -Action 'ReadPolicies' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' `
        -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
        -Detail "Could not enumerate Conditional Access policies, so no health verdict can be given: $($_.Exception.Message)"
    throw
}

# Index by display name, keeping every match so a duplicate name is visible
# rather than silently collapsing to one policy.
$byName = @{}
foreach ($p in $allPolicies) {
    $name = [string] (Get-EntraPolicyProperty -InputObject $p -Name 'displayName')
    if ([string]::IsNullOrWhiteSpace($name)) { continue }
    if (-not $byName.ContainsKey($name)) { $byName[$name] = [System.Collections.Generic.List[object]]::new() }
    $byName[$name].Add($p)
}

$templateDir = Join-Path (Split-Path -Parent $PSScriptRoot) $ca.PolicyTemplateDirectory

$presentCount = 0
$missingCount = 0
$duplicateCount = 0
$legacyPolicyCount = 0
$enforcingCount = 0
$disabledCount = 0
$unknownStateCount = 0
$exclusionGapCount = 0
$lockoutRiskCount = 0
$unevaluableTemplateCount = 0
# Managed display names seen, so unmanaged policies can be distinguished below.
$managedDisplayNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

$canEvaluateExclusions = ($breakGlassUsers.Count + $breakGlassGroups.Count) -gt 0
if (-not $canEvaluateExclusions) {
    Add-EntraRunLogEntry -Module $module -Action 'BreakGlassExclusion' -BestPracticeKey $bestPracticeKey `
        -Status 'Skipped' -Disposition 'Blocked' `
        -Detail 'No break-glass principals are configured or resolvable, so exclusion drift cannot be evaluated. Configure ConditionalAccess.BreakGlass, or run Setup-EmergencyAccess first, then rerun this check.'
}

$selectedPolicies = @($ca.Policies | Where-Object { Test-EntraPolicySelected -PolicyReference $_ })
foreach ($policyRef in $selectedPolicies) {
    $templatePath = Join-Path $templateDir $policyRef.File
    if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
        # Cannot resolve the managed policy name, so this policy's health is
        # unknown. Count it, so the run cannot report Healthy while silently
        # having skipped one of the policies it was supposed to check.
        $unevaluableTemplateCount++
        Add-EntraRunLogEntry -Module $module -Action 'PolicyHealth' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' -Target $policyRef.Key `
            -Detail "Policy template not found, so this policy could not be evaluated: $($policyRef.File)"
        continue
    }

    $template = Get-Content -Raw -LiteralPath $templatePath | ConvertFrom-Json -AsHashtable
    $templateName = [string] $template.displayName
    $displayName = Get-EntraPolicyDisplayName -DisplayName $templateName -PolicyReference $policyRef -ConditionalAccess $ca
    $candidateNames = Get-EntraPolicyDisplayNames -DisplayName $templateName -PolicyReference $policyRef -ConditionalAccess $ca
    foreach ($name in $candidateNames) { $null = $managedDisplayNames.Add($name) }
    # Deliberately not named $matches; that is a PowerShell automatic variable
    # and assigning it silently corrupts regex state for the rest of the scope.
    $policyMatches = @()
    foreach ($name in $candidateNames) {
        if ($byName.ContainsKey($name)) { $policyMatches += @($byName[$name]) }
    }
    $migrationNames = @(Get-EntraPolicyProperty $policyRef 'LegacyDisplayNames')
    if ($policyRef.Key -eq 'require-approved-client-apps' -and @($policyMatches | Where-Object {
        (Get-EntraPolicyProperty $_ 'displayName') -in $migrationNames
    }).Count -gt 0) {
        $legacyPolicyCount++
        Add-EntraRunLogEntry -Module $module -Action 'LegacyPolicy' -BestPracticeKey $bestPracticeKey `
            -Status 'Info' -Disposition 'GuidedOnly' -Target $policyRef.Key `
            -Detail 'A legacy-named policy is present. Review the app-protection migration guide; presence is not proof that the mobile platform filters or grant controls are correct.'
    }

    if ($policyMatches.Count -eq 0) {
        $missingCount++
        Add-EntraRunLogEntry -Module $module -Action 'PolicyHealth' -BestPracticeKey $bestPracticeKey `
            -Status 'Info' -Disposition 'WillChange' -Readback 'Mismatch' -Target $policyRef.Key `
            -Detail 'Managed policy is not present in the tenant. Either the baseline has not been deployed, or the policy was removed after deployment.'
        continue
    }

    $presentCount++
    if ($policyMatches.Count -gt 1) {
        $duplicateCount++
        Add-EntraRunLogEntry -Module $module -Action 'PolicyHealth' -BestPracticeKey $bestPracticeKey `
            -Status 'Info' -Disposition 'WillChange' -Target $policyRef.Key `
            -Detail "$($policyMatches.Count) policies share this managed display name. Reconcile the duplicates in the portal, because the toolkit cannot tell which one it owns."
    }

    foreach ($policy in $policyMatches) {
        $state = [string] (Get-EntraPolicyProperty -InputObject $policy -Name 'state')
        $isEnforcing = $state -eq 'enabled'
        $isDisabled = $state -eq 'disabled'
        $isReportOnly = $state -eq 'enabledForReportingButNotEnforced'
        # Anything outside the three documented states is not understood. Treat
        # it as potentially enforcing rather than quietly describing it as
        # report-only, because assuming the safe case is exactly how a real
        # lockout ends up reported as healthy.
        $isUnknownState = -not ($isEnforcing -or $isDisabled -or $isReportOnly)
        if ($isEnforcing) { $enforcingCount++ }
        if ($isDisabled) { $disabledCount++ }
        if ($isUnknownState) {
            $unknownStateCount++
            $shownState = if ([string]::IsNullOrWhiteSpace($state)) { '<absent>' } else { $state }
            Add-EntraRunLogEntry -Module $module -Action 'PolicyHealth' -BestPracticeKey $bestPracticeKey `
                -Status 'Info' -Disposition 'Blocked' -Readback 'Mismatch' -Target $policyRef.Key `
                -Detail "Policy state '$shownState' is not one of the documented Conditional Access states. It is treated as potentially enforcing until reviewed in the portal."
        }

        if (-not $canEvaluateExclusions) {
            Add-EntraRunLogEntry -Module $module -Action 'PolicyHealth' -BestPracticeKey $bestPracticeKey `
                -Status 'Info' -Disposition 'GuidedOnly' -Readback 'NotAttempted' -Target $policyRef.Key `
                -Detail "Policy is present in state '$state'. Break-glass exclusion was not evaluated because no emergency-access principal is available."
            continue
        }

        $exclusion = Get-EntraBreakGlassExclusionState -Policy $policy `
            -BreakGlassUsers $breakGlassUsers -BreakGlassGroups $breakGlassGroups

        if ($exclusion.Excluded) {
            Add-EntraRunLogEntry -Module $module -Action 'PolicyHealth' -BestPracticeKey $bestPracticeKey `
                -Status 'Succeeded' -Disposition 'AlreadyCompliant' -Readback 'Verified' -Target $policyRef.Key `
                -Detail "Policy is present in state '$state' and excludes every configured break-glass principal."
            continue
        }

        $exclusionGapCount++
        $missingDetail = "MissingBreakGlassUsers=$($exclusion.MissingUserCount); MissingBreakGlassGroups=$($exclusion.MissingGroupCount)"

        if ($isEnforcing -or $isUnknownState) {
            # The dangerous combination: enforcing right now (or in a state we
            # cannot rule out as enforcing), with no emergency way back in.
            $lockoutRiskCount++
            $riskPrefix = if ($isEnforcing) { 'policy is enforcing' } else { "policy is in unrecognized state '$state'" }
            Add-EntraRunLogEntry -Module $module -Action 'PolicyHealth' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $policyRef.Key `
                -Detail "LOCKOUT RISK: $riskPrefix and does not exclude every break-glass principal. $missingDetail. Restore the exclusion in the portal before relying on emergency access."
        }
        elseif ($isDisabled) {
            Add-EntraRunLogEntry -Module $module -Action 'PolicyHealth' -BestPracticeKey $bestPracticeKey `
                -Status 'Info' -Disposition 'WillChange' -Readback 'Mismatch' -Target $policyRef.Key `
                -Detail "Policy is disabled and does not exclude every break-glass principal. $missingDetail. Restore the exclusion before re-enabling it."
        }
        else {
            Add-EntraRunLogEntry -Module $module -Action 'PolicyHealth' -BestPracticeKey $bestPracticeKey `
                -Status 'Info' -Disposition 'WillChange' -Readback 'Mismatch' -Target $policyRef.Key `
                -Detail "Policy is report-only and does not exclude every break-glass principal. $missingDetail. This is not blocking access today, but promoting this policy to enforcing would risk locking administrators out."
        }
    }
}

# An UNMANAGED enforcing policy that does not exclude the break-glass principals
# can lock the tenant out exactly as easily as a managed one. The toolkit does
# not own these policies and will not touch them, but a health check that only
# looked at its own policies would be answering the wrong question.
#
# The policy display name is customer data, so it is not written to evidence.
# The operator is pointed at the portal instead.
$unmanagedRiskCount = 0
$enforcingInTenantCount = 0
$unmanagedPoliciesEvaluated = $canEvaluateExclusions -and
    $unevaluableTemplateCount -eq 0
if ($canEvaluateExclusions -and -not $unmanagedPoliciesEvaluated) {
    Add-EntraRunLogEntry -Module $module -Action 'UnmanagedPolicyHealth' -BestPracticeKey $bestPracticeKey `
        -Status 'Skipped' -Disposition 'Blocked' -Readback 'NotAttempted' `
        -Detail 'Unmanaged-policy classification was skipped because at least one managed policy template could not be resolved. Without the complete managed-name set, a toolkit policy could be mislabeled as customer-authored.'
}
foreach ($policy in $allPolicies) {
    if ([string] (Get-EntraPolicyProperty -InputObject $policy -Name 'state') -ne 'enabled') { continue }
    # Counted for every tenant, evaluated only when there is something to
    # evaluate against. An operator needs to know how much of the tenant is
    # enforcing even when emergency access cannot be checked.
    $enforcingInTenantCount++

    if (-not $unmanagedPoliciesEvaluated) { continue }

    $name = [string] (Get-EntraPolicyProperty -InputObject $policy -Name 'displayName')
    if (-not [string]::IsNullOrWhiteSpace($name) -and $managedDisplayNames.Contains($name)) { continue }

    $unmanagedExclusion = Get-EntraBreakGlassExclusionState -Policy $policy `
        -BreakGlassUsers $breakGlassUsers -BreakGlassGroups $breakGlassGroups
    if ($unmanagedExclusion.Excluded) { continue }

    $unmanagedRiskCount++
    Add-EntraRunLogEntry -Module $module -Action 'UnmanagedPolicyHealth' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' `
        -Detail "LOCKOUT RISK: an enforcing Conditional Access policy this toolkit does not manage does not exclude every break-glass principal. MissingBreakGlassUsers=$($unmanagedExclusion.MissingUserCount); MissingBreakGlassGroups=$($unmanagedExclusion.MissingGroupCount). Review enforcing policies in Entra admin center > Protection > Conditional Access and restore the emergency-access exclusion."
}

# Say plainly when a tenant is enforcing access with no verifiable way back in.
# Reporting only "exclusions not evaluated" would understate this.
if (-not $canEvaluateExclusions -and $enforcingInTenantCount -gt 0) {
    Add-EntraRunLogEntry -Module $module -Action 'UnmanagedPolicyHealth' -BestPracticeKey $bestPracticeKey `
        -Status 'Failed' -Disposition 'Blocked' -Readback 'NotAttempted' `
        -Detail "The tenant has $enforcingInTenantCount enforcing Conditional Access policy(ies) and no configured break-glass principal, so emergency access could not be verified against any of them. Configure ConditionalAccess.BreakGlass and rerun before relying on emergency access."
}

# Break-glass drift. Setup-EmergencyAccess establishes recoverability before a
# deployment; this reports whether it still holds afterwards. An account that is
# enabled but has lost Global Administrator is not a recovery path, so the role
# is verified here too, using the same shared read the setup module uses.
$breakGlassDisabledCount = 0
$breakGlassUnreadableCount = 0
$breakGlassNoRoleCount = 0
$gaPrincipalIds = $null

foreach ($userId in $breakGlassUsers) {
    try {
        $account = Invoke-WithTransientRetry -Description 'Read break-glass account state' -Action {
            Invoke-MgGraphRequest -Method GET -Uri "$v1/users/$userId`?`$select=id,accountEnabled"
        }
    }
    catch {
        $breakGlassUnreadableCount++
        Add-EntraRunLogEntry -Module $module -Action 'BreakGlassHealth' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $userId `
            -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
            -Detail "Configured break-glass account could not be read, so its availability for an emergency cannot be confirmed: $($_.Exception.Message)"
        continue
    }

    if (-not [bool] (Get-EntraPolicyProperty -InputObject $account -Name 'accountEnabled')) {
        $breakGlassDisabledCount++
        Add-EntraRunLogEntry -Module $module -Action 'BreakGlassHealth' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $userId `
            -Detail 'Break-glass account is disabled. A disabled account cannot recover the tenant in an emergency. Enable it before enforcing any Conditional Access policy.'
        continue
    }

    # Enabled is not the same as usable. Confirm the account still holds a
    # permanently assigned Global Administrator role, directly or through a
    # role-assignable group. If the role cannot be read, treat it as unproven
    # rather than assuming it is intact.
    try {
        if ($null -eq $gaPrincipalIds) { $gaPrincipalIds = Get-EntraGlobalAdminPrincipalId -BaseUri $v1 }
        $roleState = Get-EntraGlobalAdminRecoveryState -BaseUri $v1 `
            -PrincipalId ([string] $userId) -PrincipalType User `
            -GlobalAdminPrincipalIds @($gaPrincipalIds)
    }
    catch {
        $breakGlassUnreadableCount++
        Add-EntraRunLogEntry -Module $module -Action 'BreakGlassHealth' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $userId `
            -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
            -Detail "Could not confirm the break-glass account's Global Administrator role, so its ability to recover the tenant is unproven: $($_.Exception.Message)"
        continue
    }

    if ($roleState.HasGlobalAdmin) {
        Add-EntraRunLogEntry -Module $module -Action 'BreakGlassHealth' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'AlreadyCompliant' -Readback 'Verified' -Target $userId `
            -Detail "Break-glass account is enabled and still holds a permanently assigned Global Administrator role ($($roleState.RoleVia))."
    }
    else {
        $breakGlassNoRoleCount++
        Add-EntraRunLogEntry -Module $module -Action 'BreakGlassHealth' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $userId `
            -Detail 'Break-glass account is enabled but no longer holds a permanently assigned Global Administrator role. It is excluded from Conditional Access but cannot actually recover the tenant. Reassign the role.'
    }
}

# A break-glass GROUP is only a recovery path if it still contains at least one
# enabled account. An empty or deleted group excludes nobody, so a tenant that
# relies solely on a group exclusion would otherwise be reported healthy while
# having no way back in. Membership is paginated: the first enabled member could
# be on any page, and stopping early would report a false lockout risk.
$breakGlassGroupUnusableCount = 0
$breakGlassGroupNoRoleCount = 0
foreach ($groupId in $breakGlassGroups) {
    try {
        $members = Get-EntraGraphCollection -BaseUri $v1 `
            -Uri "$v1/groups/$groupId/transitiveMembers/microsoft.graph.user`?`$select=id,accountEnabled" `
            -Description 'Read break-glass group members'
    }
    catch {
        $breakGlassUnreadableCount++
        Add-EntraRunLogEntry -Module $module -Action 'BreakGlassHealth' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $groupId `
            -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
            -Detail "Configured break-glass group could not be read, so its availability for an emergency cannot be confirmed: $($_.Exception.Message)"
        continue
    }

    $enabledMembers = @(@($members) |
            Where-Object { $_ -and [bool] (Get-EntraPolicyProperty -InputObject $_ -Name 'accountEnabled') })

    if ($enabledMembers.Count -gt 0) {
        try {
            if ($null -eq $gaPrincipalIds) {
                $gaPrincipalIds = Get-EntraGlobalAdminPrincipalId -BaseUri $v1
            }
            $enabledMemberIds = @($enabledMembers | ForEach-Object {
                    [string] (Get-EntraPolicyProperty -InputObject $_ -Name 'id')
                } | Where-Object { $_ })
            $roleState = Get-EntraGlobalAdminRecoveryState -BaseUri $v1 `
                -PrincipalId ([string] $groupId) -PrincipalType Group `
                -GlobalAdminPrincipalIds @($gaPrincipalIds) `
                -EnabledMemberIds $enabledMemberIds
        }
        catch {
            $breakGlassUnreadableCount++
            Add-EntraRunLogEntry -Module $module -Action 'BreakGlassHealth' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $groupId `
                -HttpStatusCode (Get-EntraHttpStatusCode -ErrorRecord $_) `
                -Detail "Could not confirm the break-glass group's Global Administrator role, so its ability to recover the tenant is unproven: $($_.Exception.Message)"
            continue
        }

        if (-not $roleState.HasGlobalAdmin) {
            $breakGlassGroupNoRoleCount++
            Add-EntraRunLogEntry -Module $module -Action 'BreakGlassHealth' -BestPracticeKey $bestPracticeKey `
                -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $groupId `
                -Detail 'Break-glass group has enabled members but neither the group nor an enabled member holds a permanently assigned Global Administrator role. It cannot recover the tenant. Reassign the role.'
            continue
        }

        Add-EntraRunLogEntry -Module $module -Action 'BreakGlassHealth' -BestPracticeKey $bestPracticeKey `
            -Status 'Succeeded' -Disposition 'AlreadyCompliant' -Readback 'Verified' -Target $groupId `
            -Detail "Break-glass group contains $($enabledMembers.Count) enabled member(s) and still provides a permanently assigned Global Administrator role ($($roleState.RoleVia))."
    }
    else {
        $breakGlassGroupUnusableCount++
        Add-EntraRunLogEntry -Module $module -Action 'BreakGlassHealth' -BestPracticeKey $bestPracticeKey `
            -Status 'Failed' -Disposition 'Blocked' -Readback 'Mismatch' -Target $groupId `
            -Detail 'Break-glass group contains no enabled member. Excluding an empty group from Conditional Access provides no emergency access. Add an enabled emergency-access account to the group.'
    }
}

$verdict = if (($lockoutRiskCount + $unmanagedRiskCount + $breakGlassDisabledCount +
        $breakGlassNoRoleCount + $breakGlassUnreadableCount +
        $breakGlassGroupUnusableCount + $breakGlassGroupNoRoleCount) -gt 0) {
    'LockoutRisk'
}
elseif ((-not $canEvaluateExclusions) -or $unevaluableTemplateCount -gt 0 -or $securityDefaultsState -eq 'Unknown') {
    # Never report Healthy when the lockout control could not be evaluated, in
    # whole or in part. A clean-looking verdict here would be the most dangerous
    # output this check could produce.
    'Indeterminate'
}
elseif (($missingCount + $duplicateCount + $exclusionGapCount + $unknownStateCount + $legacyPolicyCount) -gt 0 -or
    $securityDefaultsState -eq 'Enabled') { 'DriftDetected' }
else { 'Healthy' }

$summary = 'Verdict={0}; ExclusionsEvaluated={1}; UnmanagedPoliciesEvaluated={2}; ManagedPoliciesConfigured={3}; Present={4}; Missing={5}; Unevaluable={6}; DuplicateNames={7}; Enforcing={8}; Disabled={9}; UnknownState={10}; EnforcingPoliciesInTenant={11}; BreakGlassExclusionGaps={12}; LockoutRisks={13}; UnmanagedEnforcingRisks={14}; BreakGlassAccountsDisabled={15}; BreakGlassAccountsWithoutRole={16}; BreakGlassGroupsUnusable={17}; BreakGlassGroupsWithoutRole={18}; BreakGlassPrincipalsUnreadable={19}; Assessment=ReadOnly.' -f `
    $verdict,
    $canEvaluateExclusions,
    $unmanagedPoliciesEvaluated,
    $selectedPolicies.Count,
    $presentCount,
    $missingCount,
    $unevaluableTemplateCount,
    $duplicateCount,
    $enforcingCount,
    $disabledCount,
    $unknownStateCount,
    $enforcingInTenantCount,
    $exclusionGapCount,
    $lockoutRiskCount,
    $unmanagedRiskCount,
    $breakGlassDisabledCount,
    $breakGlassNoRoleCount,
    $breakGlassGroupUnusableCount,
    $breakGlassGroupNoRoleCount,
    $breakGlassUnreadableCount
$summary += " SecurityDefaultsState=$securityDefaultsState; TenantWritesAllowed=$($securityDefaultsState -eq 'Disabled'); LegacyPolicies=$legacyPolicyCount."

$summaryStatus = if ($verdict -eq 'LockoutRisk' -or
    ($verdict -eq 'Indeterminate' -and $enforcingInTenantCount -gt 0)) {
    'Failed'
}
else {
    'Succeeded'
}
$summaryDisposition = switch ($verdict) {
    'Healthy' { 'AlreadyCompliant' }
    'Indeterminate' { 'GuidedOnly' }
    'LockoutRisk' { 'Blocked' }
    default { 'WillChange' }
}
if ($securityDefaultsState -ne 'Disabled') { $summaryDisposition = 'Blocked' }

Add-EntraRunLogEntry -Module $module -Action 'HealthSummary' -BestPracticeKey $bestPracticeKey `
    -Status $summaryStatus -Disposition $summaryDisposition -Detail $summary
