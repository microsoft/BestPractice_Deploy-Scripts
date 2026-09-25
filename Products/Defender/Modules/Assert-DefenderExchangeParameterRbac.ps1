#requires -Version 7.0

function Assert-DefenderExchangeParameterRbac {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $RoleAssignee,
        [Parameter(Mandatory)] [string] $Command,
        [Parameter(Mandatory)] [string] $Parameter,
        [AllowEmptyCollection()] [object[]] $RoleAssignments
    )

    $roles = @(Get-ManagementRole -Cmdlet $Command `
        -CmdletParameters $Parameter -ErrorAction Stop |
        Select-Object -ExpandProperty Name)
    $candidateAssignments = if ($PSBoundParameters.ContainsKey('RoleAssignments')) {
        @($RoleAssignments)
    }
    else {
        @(Get-ManagementRoleAssignment -RoleAssignee $RoleAssignee `
            -Delegating:$false -ErrorAction Stop)
    }
    $assignments = @($candidateAssignments |
        Where-Object { $_.Enabled -and $_.Role -in $roles })
    if ($roles.Count -eq 0 -or $assignments.Count -eq 0) {
        throw "The connected operator does not have effective Exchange RBAC for $Command -$Parameter."
    }
    return $assignments
}