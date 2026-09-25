#requires -Version 7.0
<#
.SYNOPSIS
    Shared read-modify-write planning for Defender objects.

.DESCRIPTION
    Keeps state decisions deterministic before a supported Defender write is
    enabled. The helper preserves unrelated customer properties, recognizes
    toolkit-managed objects, and fails closed on unmanaged collisions.
#>

# Resolve-DefenderRecoveryAction reuses the shared continuation-command
# phrasing so operator guidance stays identical to the safety-gate messages.
. (Join-Path $PSScriptRoot 'DefenderSafetyGates.ps1')

function Get-DefenderPropertyValue {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $InputObject,
        [Parameter(Mandatory)] [string] $PropertyName
    )

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($PropertyName)) { return $InputObject[$PropertyName] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($property) { return $property.Value }
    return $null
}

function Get-DefenderManagedTag {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Config)

    if ([string]::IsNullOrWhiteSpace([string] $Config.ManagedByTag)) {
        throw 'Defender configuration must define ManagedByTag.'
    }
    return [string] $Config.ManagedByTag
}

function Get-DefenderStableIdentifier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Object,
        [Parameter(Mandatory)] [hashtable] $Definition
    )

    $parts = foreach ($propertyName in @($Definition.IdentifierProperties)) {
        $value = Get-DefenderPropertyValue -InputObject $Object -PropertyName $propertyName
        if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string] $value)) {
            throw "Defender object is missing stable identifier property '$propertyName'."
        }
        ([string] $value).Trim().ToLowerInvariant()
    }
    return ($parts -join '|')
}

function ConvertTo-DefenderComparableValue {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in ($Value.Keys | Sort-Object)) {
            $result[[string] $key] = ConvertTo-DefenderComparableValue -Value $Value[$key]
        }
        return $result
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return @($Value | ForEach-Object { ConvertTo-DefenderComparableValue -Value $_ })
    }
if ($Value -is [string]) { return $Value }
    $properties = @($Value.PSObject.Properties | Where-Object {
        $_.MemberType -in @('NoteProperty', 'Property')
    })
    if ($properties.Count -gt 0) {
        foreach ($property in ($properties | Sort-Object Name)) {
            $result[$property.Name] = ConvertTo-DefenderComparableValue -Value $property.Value
        }
        return $result
    }
    return $Value
}

function Test-DefenderDesiredState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Current,
        [Parameter(Mandatory)] [object] $Desired,
        [Parameter(Mandatory)] [hashtable] $Definition
    )

    foreach ($propertyName in @($Definition.ManagedProperties)) {
        $currentValue = ConvertTo-DefenderComparableValue (
            Get-DefenderPropertyValue -InputObject $Current -PropertyName $propertyName
        )
        $desiredValue = ConvertTo-DefenderComparableValue (
            Get-DefenderPropertyValue -InputObject $Desired -PropertyName $propertyName
        )
        $currentJson = $currentValue | ConvertTo-Json -Depth 20 -Compress
        $desiredJson = $desiredValue | ConvertTo-Json -Depth 20 -Compress
        if ($currentJson -cne $desiredJson) { return $false }
    }
    return $true
}

function Merge-DefenderManagedState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Current,
        [Parameter(Mandatory)] [object] $Desired,
        [Parameter(Mandatory)] [hashtable] $Definition,
        [Parameter(Mandatory)] [hashtable] $Config
    )

    $merged = [ordered]@{}
    foreach ($property in @($Current.PSObject.Properties | Where-Object {
        $_.MemberType -in @('NoteProperty', 'Property')
    })) {
        $merged[$property.Name] = $property.Value
    }
    if ($Current -is [System.Collections.IDictionary]) {
        foreach ($key in $Current.Keys) { $merged[[string] $key] = $Current[$key] }
    }
    foreach ($propertyName in @($Definition.ManagedProperties)) {
        $desiredValue = Get-DefenderPropertyValue -InputObject $Desired -PropertyName $propertyName
        if ($null -ne $desiredValue) { $merged[$propertyName] = $desiredValue }
    }
    $managedProperty = [string] $Definition.ManagedTagProperty
    $merged[$managedProperty] = Get-DefenderManagedTag -Config $Config
    return $merged
}

function Resolve-DefenderStatePlan {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Current,
        [Parameter(Mandatory)] [object] $Desired,
        [Parameter(Mandatory)] [hashtable] $Definition,
        [Parameter(Mandatory)] [hashtable] $Config,
        [switch] $AdoptExisting,
        [switch] $BuiltInObject
    )

    $identifier = Get-DefenderStableIdentifier -Object $Desired -Definition $Definition
    if ($BuiltInObject) {
        if ($null -eq $Current) {
            throw "Built-in Defender object '$identifier' was not found; creation and adoption are not permitted."
        }
        $currentIdentifier = Get-DefenderStableIdentifier -Object $Current -Definition $Definition
        if ($currentIdentifier -cne $identifier) {
            throw "Defender state collision: current identifier '$currentIdentifier' does not match desired '$identifier'."
        }
        if (Test-DefenderDesiredState -Current $Current -Desired $Desired -Definition $Definition) {
            return [pscustomobject]@{
                Action = 'NoOp'
                Status = 'Succeeded'
                Disposition = 'AlreadyCompliant'
                StableIdentifier = $identifier
                State = $Current
                Detail = 'Existing built-in object already matches the managed intent.'
            }
        }
        return [pscustomobject]@{
            Action = 'Update'
            Status = 'Updated'
            Disposition = 'WillChange'
            StableIdentifier = $identifier
            State = $Desired
            Detail = 'Existing built-in object will be updated without toolkit ownership or adoption.'
        }
    }

    if ($null -eq $Current) {
        return [pscustomobject]@{
            Action = 'Create'
            Status = 'Created'
            Disposition = 'WillChange'
            StableIdentifier = $identifier
            State = Merge-DefenderManagedState -Current @{} -Desired $Desired -Definition $Definition -Config $Config
            Detail = 'No existing object matched the stable identifier.'
        }
    }

    $currentIdentifier = Get-DefenderStableIdentifier -Object $Current -Definition $Definition
    if ($currentIdentifier -cne $identifier) {
        throw "Defender state collision: current identifier '$currentIdentifier' does not match desired '$identifier'."
    }

    $managedTag = Get-DefenderManagedTag -Config $Config
    $currentTag = [string] (Get-DefenderPropertyValue -InputObject $Current -PropertyName $Definition.ManagedTagProperty)
    if ($currentTag -ne $managedTag -and -not $AdoptExisting) {
        throw "Unmanaged Defender object collision for '$identifier'. Supply -AdoptExisting only after reviewing the existing object."
    }

    if (Test-DefenderDesiredState -Current $Current -Desired $Desired -Definition $Definition) {
        return [pscustomobject]@{
            Action = 'NoOp'
            Status = 'Succeeded'
            Disposition = 'AlreadyCompliant'
            StableIdentifier = $identifier
            State = $Current
            Detail = 'Existing object already matches the managed intent.'
        }
    }

    $action = if ($currentTag -eq $managedTag) { 'Update' } else { 'Adopt' }
    $status = if ($action -eq 'Adopt') { 'Adopted' } else { 'Updated' }
    return [pscustomobject]@{
        Action = $action
        Status = $status
        Disposition = 'WillChange'
        StableIdentifier = $identifier
        State = Merge-DefenderManagedState -Current $Current -Desired $Desired -Definition $Definition -Config $Config
        Detail = if ($action -eq 'Adopt') {
            'Existing unmanaged object was explicitly adopted; unrelated properties were preserved.'
        } else {
            'Existing managed object will be updated; unrelated properties were preserved.'
        }
    }
}

function Test-DefenderReadback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Expected,
        [Parameter(Mandatory)] [object] $Actual,
        [Parameter(Mandatory)] [hashtable] $Definition
    )

    if (-not (Test-DefenderDesiredState -Current $Actual -Desired $Expected -Definition $Definition)) {
        throw "Defender readback mismatch for stable identifier '$(Get-DefenderStableIdentifier -Object $Expected -Definition $Definition)'."
    }
    return $true
}

function Resolve-DefenderRecoveryAction {
    <#
    .SYNOPSIS
        The shared recovery contract: turns a write outcome plus readback
        result into one deterministic next action, instead of leaving that
        decision to per-module ad hoc prose.

    .DESCRIPTION
        Every Setup-* module reaches one of the same handful of situations
        after attempting a write: the write itself failed, the write
        succeeded but readback could not confirm it, or the write succeeded
        and readback confirmed it. This helper is the single place that maps
        those situations to a run-log-ready Disposition/Readback pair and an
        operator-actionable continuation command, so recovery guidance is
        consistent and testable rather than duplicated as free text per
        module.

        This function only classifies and recommends; it never retries,
        rolls back, or mutates tenant state itself. Retrying belongs to
        Invoke-WithTransientRetry, and rollback execution is always a human
        decision gated by Assert-DefenderSafetyGates.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('Succeeded', 'Failed')] [string] $WriteOutcome,
        [ValidateSet('NotApplicable', 'Succeeded', 'Failed')] [string] $ReadbackOutcome = 'NotApplicable',
        [Parameter(Mandatory)] [string] $ModuleName,
        [Parameter(Mandatory)] [string] $RollbackGuidance
    )

    if ($WriteOutcome -eq 'Failed' -and $ReadbackOutcome -ne 'NotApplicable') {
        throw "Resolve-DefenderRecoveryAction: WriteOutcome 'Failed' is incompatible with ReadbackOutcome '$ReadbackOutcome'. Readback only applies after a successful write; pass 'NotApplicable' when the write failed."
    }

    if ($WriteOutcome -eq 'Failed') {
        return [pscustomobject]@{
            RecoveryAction = 'RetryOrEscalate'
            Disposition = 'Blocked'
            Readback = 'NotApplicable'
            RunLogStatus = 'Failed'
            ContinuationCommand = (Get-DefenderContinuationCommand `
                -Reason "$ModuleName write failed; $RollbackGuidance")
        }
    }

    if ($ReadbackOutcome -eq 'Failed') {
        return [pscustomobject]@{
            RecoveryAction = 'ManualVerificationRequired'
            Disposition = 'Blocked'
            Readback = 'Failed'
            RunLogStatus = 'Failed'
            ContinuationCommand = (Get-DefenderContinuationCommand `
                -Reason "$ModuleName write succeeded but readback could not confirm the change; $RollbackGuidance")
        }
    }

    if ($ReadbackOutcome -eq 'NotApplicable') {
        return [pscustomobject]@{
            RecoveryAction = 'None'
            Disposition = 'WillChange'
            Readback = 'NotApplicable'
            RunLogStatus = 'Succeeded'
            ContinuationCommand = $null
        }
    }

    return [pscustomobject]@{
        RecoveryAction = 'None'
        Disposition = 'WillChange'
        Readback = 'Succeeded'
        RunLogStatus = 'Succeeded'
        ContinuationCommand = $null
    }
}

function Invoke-DefenderManagedWrite {
    <#
    .SYNOPSIS
        Shared batch write contract: plan, ShouldProcess, retry, readback, and
        recovery classification for one or more Defender objects.

    .DESCRIPTION
        Wires the previously separate building blocks (Resolve-DefenderStatePlan,
        Invoke-WithTransientRetry, Resolve-DefenderRecoveryAction) into one
        reusable batch operation so a Setup-* module does not have to hand-roll
        its own WhatIf/retry/recovery loop. Each item is independent: a failure
        on one item is recorded and processing continues to the remaining
        items rather than aborting the whole batch (partial-failure isolation).
        -WhatIf/-Confirm are honored per item via ShouldProcess before
        WriteAction ever runs.

        This function does not itself call any tenant API. WriteAction and
        ReadbackAction are supplied scriptblocks so the same contract works
        for every workload without hardcoding a specific cmdlet or endpoint.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)] [object[]] $Items,
        [Parameter(Mandatory)] [hashtable] $Definition,
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [string] $ModuleName,
        [Parameter(Mandatory)] [string] $RollbackGuidance,
        [Parameter(Mandatory)] [scriptblock] $WriteAction,
        [scriptblock] $ReadbackAction,
        [switch] $AdoptExisting,
        [switch] $BuiltInObject
    )

    $results = foreach ($item in $Items) {
        # Identifier resolution and plan resolution are both wrapped by the
        # same try/catch so a malformed item (missing identifier properties,
        # bad shape, etc.) is recorded as a Failed batch item instead of
        # aborting the remaining items in the batch (partial-failure
        # isolation applies to every failure mode, not just plan errors).
        $identifier = $null
        try {
            $current = Get-DefenderPropertyValue -InputObject $item -PropertyName 'Current'
            $desired = Get-DefenderPropertyValue -InputObject $item -PropertyName 'Desired'
            if ($null -eq $desired) { $desired = $item }
            $identifier = Get-DefenderStableIdentifier -Object $desired -Definition $Definition
            $plan = Resolve-DefenderStatePlan -Current $current -Desired $desired `
                -Definition $Definition -Config $Config -AdoptExisting:$AdoptExisting `
                -BuiltInObject:$BuiltInObject
        }
        catch {
            [pscustomobject]@{
                StableIdentifier = $identifier
                Action = 'Error'
                WriteOutcome = 'Failed'
                Readback = 'NotApplicable'
                Recovery = Resolve-DefenderRecoveryAction -WriteOutcome 'Failed' `
                    -ModuleName $ModuleName -RollbackGuidance $RollbackGuidance
                Detail = $_.Exception.Message
            }
            continue
        }

        if ($plan.Action -eq 'NoOp') {
            # Preserve Resolve-DefenderStatePlan's own AlreadyCompliant
            # classification instead of reusing Resolve-DefenderRecoveryAction's
            # generic Succeeded/NotApplicable mapping (which reports
            # Disposition='WillChange' - correct for a real write, wrong for a
            # rerun that changed nothing).
            [pscustomobject]@{
                StableIdentifier = $plan.StableIdentifier
                Action = $plan.Action
                WriteOutcome = 'Succeeded'
                Readback = 'NotApplicable'
                Recovery = [pscustomobject]@{
                    RecoveryAction = 'None'
                    Disposition = 'AlreadyCompliant'
                    Readback = 'NotApplicable'
                    RunLogStatus = 'Succeeded'
                    ContinuationCommand = $null
                }
                Detail = $plan.Detail
            }
            continue
        }

        $target = "$ModuleName : $($plan.StableIdentifier)"
        if (-not $PSCmdlet.ShouldProcess($target, "Apply $($plan.Action)")) {
            [pscustomobject]@{
                StableIdentifier = $plan.StableIdentifier
                Action = $plan.Action
                WriteOutcome = 'Skipped'
                Readback = 'NotApplicable'
                Recovery = $null
                Detail = 'Skipped by -WhatIf; no write was attempted.'
            }
            continue
        }

        $writeOutcome = 'Succeeded'
        $writeError = $null
        try {
            Invoke-WithTransientRetry -Description "$ModuleName write for $($plan.StableIdentifier)" -Action {
                & $WriteAction $plan
            } | Out-Null
        }
        catch {
            $writeOutcome = 'Failed'
            $writeError = $_.Exception.Message
        }

        if ($writeOutcome -eq 'Failed') {
            [pscustomobject]@{
                StableIdentifier = $plan.StableIdentifier
                Action = $plan.Action
                WriteOutcome = 'Failed'
                Readback = 'NotApplicable'
                Recovery = Resolve-DefenderRecoveryAction -WriteOutcome 'Failed' `
                    -ModuleName $ModuleName -RollbackGuidance $RollbackGuidance
                Detail = $writeError
            }
            continue
        }

        $readbackOutcome = 'NotApplicable'
        $readbackDetail = $plan.Detail
        if ($ReadbackAction) {
            try {
                $actual = & $ReadbackAction $plan
                Test-DefenderReadback -Expected $plan.State -Actual $actual -Definition $Definition | Out-Null
                $readbackOutcome = 'Succeeded'
            }
            catch {
                $readbackOutcome = 'Failed'
                $readbackDetail = $_.Exception.Message
            }
        }

        [pscustomobject]@{
            StableIdentifier = $plan.StableIdentifier
            Action = $plan.Action
            WriteOutcome = $writeOutcome
            Readback = $readbackOutcome
            Recovery = Resolve-DefenderRecoveryAction -WriteOutcome $writeOutcome `
                -ReadbackOutcome $readbackOutcome -ModuleName $ModuleName -RollbackGuidance $RollbackGuidance
            Detail = $readbackDetail
        }
    }

    return $results
}
