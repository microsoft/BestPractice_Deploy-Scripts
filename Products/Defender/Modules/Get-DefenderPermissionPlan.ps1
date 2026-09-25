#requires -Version 7.0
<#
.SYNOPSIS
    Resolves and validates the least-privilege permission plan for Defender.
#>

function Assert-DefenderPermissionManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config
    )

    if (-not $Config.PermissionModel) {
        throw 'Defender configuration must define PermissionModel.'
    }
    foreach ($profileName in @('ReadOnlyPreflight', 'WriteApply')) {
        $profile = $Config.PermissionModel.Profiles[$profileName]
        if (-not $profile) {
            throw "Defender PermissionModel is missing profile '$profileName'."
        }
        foreach ($property in @(
            'MinimumRoles',
            'MinimumGdapRoles',
            'ConsentOwner',
            'Status'
        )) {
            if ($null -eq $profile[$property]) {
                throw "PermissionModel profile '$profileName' is missing '$property'."
            }
        }
        if ($profileName -eq 'ReadOnlyPreflight' -and $profile.Status -ne 'Verified') {
            throw "ReadOnlyPreflight profile must have Status='Verified'."
        }
        if ($profileName -eq 'WriteApply' -and $profile.Status -notin @('GuidedOnly', 'Verified')) {
            throw "WriteApply profile must have Status='GuidedOnly' or 'Verified'."
        }
    }
    if (-not $Config.PermissionModel.Operations) {
        throw 'Defender PermissionModel must define at least one operation.'
    }
    $operationKeys = @()
    foreach ($operation in @($Config.PermissionModel.Operations)) {
        foreach ($property in @(
            'Key',
            'Module',
            'Phase',
            'ReadWrite',
            'Endpoint',
            'License',
            'GraphDelegatedScopes',
            'GraphApplicationPermissions',
            'MinimumRoles',
            'MinimumGdapRoles',
            'VerificationStatus',
            'Readback',
            'Rollback'
        )) {
            if ($null -eq $operation[$property]) {
                throw "Defender permission operation is missing '$property'."
            }
        }
        if ($operation.Key -notmatch '^[a-z0-9]+(?:-[a-z0-9]+)+$') {
            throw "Permission operation '$($operation.Key)' must be lowercase kebab-case."
        }
        if ($operation.Key -in $operationKeys) {
            throw "Duplicate Defender permission operation key '$($operation.Key)'."
        }
        $operationKeys += $operation.Key
        if ($operation.Phase -notin @('ReadOnlyPreflight', 'WriteApply', 'GuidedOnly')) {
            throw "Permission operation '$($operation.Key)' has an unsupported phase."
        }
        if ($operation.ReadWrite -notin @('Read', 'Write', 'Readback')) {
            throw "Permission operation '$($operation.Key)' has an unsupported read/write classification."
        }
        if ($operation.Phase -eq 'ReadOnlyPreflight' -and $operation.ReadWrite -ne 'Read') {
            throw "Read-only operation '$($operation.Key)' must use ReadWrite='Read'."
        }
        if ($operation.Phase -in @('WriteApply', 'GuidedOnly') -and $operation.ReadWrite -ne 'Write') {
            throw "Write operation '$($operation.Key)' must use ReadWrite='Write'."
        }
        if ($operation.VerificationStatus -notin @('Verified', 'GuidedOnly', 'Deferred')) {
            throw "Permission operation '$($operation.Key)' has an unsupported verification status."
        }
        if ([string]::IsNullOrWhiteSpace([string] $operation.Readback) -or
            [string]::IsNullOrWhiteSpace([string] $operation.Rollback)) {
            throw "Permission operation '$($operation.Key)' must declare Readback and Rollback guidance."
        }
        if ($operation.Phase -eq 'ReadOnlyPreflight') {
            $hasDelegatedGraph = @($operation.GraphDelegatedScopes).Count -gt 0
            $hasApplicationGraph = @($operation.GraphApplicationPermissions).Count -gt 0
            $hasWorkloadPermission = @($operation.WorkloadDelegatedPermissions).Count -gt 0 -or
                @($operation.WorkloadApplicationPermissions).Count -gt 0
            if ($hasDelegatedGraph -ne $hasApplicationGraph) {
                throw "Authorized Graph read-only operation '$($operation.Key)' must declare delegated and application permissions."
            }
            if (-not $hasDelegatedGraph -and -not $hasWorkloadPermission) {
                throw "Authorized read-only operation '$($operation.Key)' must declare Graph or workload permissions."
            }
        }
    }
    foreach ($item in @($Config.BestPracticeItems)) {
        if ($null -eq $item.PermissionOperations) {
            throw "BestPracticeItems entry '$($item.Key)' must declare PermissionOperations, even when it is empty."
        }
        foreach ($operationKey in @($item.PermissionOperations)) {
            if ($operationKey -notin $operationKeys) {
                throw "BestPracticeItems entry '$($item.Key)' references unknown permission operation '$operationKey'."
            }
            $operation = @($Config.PermissionModel.Operations | Where-Object Key -eq $operationKey)[0]
            if ($operation.Phase -eq 'GuidedOnly') {
                throw "BestPracticeItems entry '$($item.Key)' cannot reference guided-only write operation '$operationKey' until its permission and workload evidence is verified."
            }
        }
    }
}

function Get-DefenderPermissionPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Config,
        [Parameter(Mandatory)] [string[]] $OperationKeys
    )

    Assert-DefenderPermissionManifest -Config $Config
    $operations = @($Config.PermissionModel.Operations | Where-Object {
        $_.Key -in $OperationKeys
    })
    $missing = @($OperationKeys | Where-Object {
        $_ -notin @($operations | ForEach-Object { $_.Key })
    })
    if ($missing.Count -gt 0) {
        throw "Defender permission manifest has no operation entries for: $($missing -join ', ')."
    }

    $profiles = @($operations | ForEach-Object { $_.Phase } | Sort-Object -Unique)
    $guidedWrites = @($operations | Where-Object {
        $_.Phase -eq 'GuidedOnly' -and $_.ReadWrite -eq 'Write'
    })
    if ($profiles -contains 'WriteApply' -or $guidedWrites.Count -gt 0) {
        if ($guidedWrites.Count -gt 0) {
            throw "Write-capable Defender operations are guided-only and cannot be authorized: $($guidedWrites.Key -join ', ')."
        }
        $unverifiedWrites = @($operations | Where-Object {
            $_.Phase -eq 'WriteApply' -and $_.VerificationStatus -ne 'Verified'
        })
        if ($unverifiedWrites.Count -gt 0) {
            throw "Write-capable Defender operations are not verified and cannot be authorized: $($unverifiedWrites.Key -join ', ')."
        }
    }

    $scopes = @($operations | ForEach-Object {
        @($_.GraphDelegatedScopes)
    } | Sort-Object -Unique)
    [pscustomobject]@{
        Operations = $operations
        Profiles = $profiles
        GraphDelegatedScopes = $scopes
        GraphApplicationPermissions = @($operations | ForEach-Object {
            @($_.GraphApplicationPermissions)
        } | Sort-Object -Unique)
        MinimumRoles = @($operations | ForEach-Object {
            @($_.MinimumRoles)
        } | Sort-Object -Unique)
        MinimumGdapRoles = @($operations | ForEach-Object {
            @($_.MinimumGdapRoles)
        } | Sort-Object -Unique)
        Status = 'Ready'
    }
}

function Test-DefenderGraphConsent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $GraphContext,
        [Parameter(Mandatory)] [string[]] $RequiredDelegatedScopes
    )

    if ($GraphContext.AuthType -eq 'Delegated') {
        $granted = @($GraphContext.Scopes | ForEach-Object { [string] $_ })
        $missing = @($RequiredDelegatedScopes | Where-Object { $_ -notin $granted })
        if ($missing.Count -gt 0) {
            throw "Missing delegated Microsoft Graph consent for: $($missing -join ', ')."
        }
        return [pscustomobject]@{
            AuthType = 'Delegated'
            Missing = @()
            Status = 'Verified'
        }
    }

    if ($GraphContext.AuthType -eq 'AppOnly') {
        throw 'App-only Microsoft Graph authorization is not verified for the Defender least-privilege consent model; certificate-based runs are blocked until operation-level application permission evidence is supplied.'
    }

    throw "Unsupported Microsoft Graph authentication type '$($GraphContext.AuthType)'."
}
