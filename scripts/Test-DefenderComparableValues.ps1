#requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Products\Defender\Modules\DefenderStateManagement.ps1')
$assertions = 0
function Assert-Equal {
    param($Actual, $Expected, [string] $Message)
    if ($Actual -cne $Expected) { throw $Message }
    $script:assertions++
}

Assert-Equal (ConvertTo-DefenderComparableValue 'abc') 'abc' 'String content was lost'
Assert-Equal (Test-DefenderDesiredState -Current @{Mode='abc'} -Desired @{Mode='xyz'} `
    -Definition @{ManagedProperties=@('Mode')}) $false 'Equal-length strings compared equal'
Assert-Equal ((ConvertTo-DefenderComparableValue ([pscustomobject]@{Mode='Audit'})) |
    ConvertTo-Json -Compress) '{"Mode":"Audit"}' 'PSObject conversion failed'
Assert-Equal ((ConvertTo-DefenderComparableValue @{Z=2; A=1}) |
    ConvertTo-Json -Compress) '{"A":1,"Z":2}' 'Dictionary order was not normalized'
Assert-Equal (ConvertTo-DefenderComparableValue $null) $null 'Null conversion changed'
foreach ($value in @(
    @{Mode='Audit'},
    [pscustomobject]@{Mode='Audit'},
    @{Mode=[pscustomobject]@{Names=@('abc','xyz'); Settings=@{Enabled=$true; Empty=$null}}},
    @{Mode=@([pscustomobject]@{A=1}, @{A=2})},
    @{Mode=@()},
    @{Mode=@('abc')},
    @{Mode=$null}
)) {
    Assert-Equal (Test-DefenderDesiredState -Current $value -Desired $value `
        -Definition @{ManagedProperties=@('Mode')}) $true 'Equivalent values did not compare equal'
}
Assert-Equal (Test-DefenderDesiredState -Current @{Mode=[pscustomobject]@{Name='abc'}} `
    -Desired @{Mode=@{Name='xyz'}} -Definition @{ManagedProperties=@('Mode')}) $false 'Nested change was missed'
Assert-Equal (Test-DefenderDesiredState -Current @{Mode=@('abc','xyz')} `
    -Desired @{Mode=@('abc','def')} -Definition @{ManagedProperties=@('Mode')}) $false 'Array change was missed'
Assert-Equal (Test-DefenderDesiredState -Current @{Mode=[pscustomobject]@{B=@('abc','xyz'); A=@{Enabled=$true; Missing=$null}}} `
    -Desired @{Mode=@{A=[pscustomobject]@{Missing=$null; Enabled=$true}; B=@('abc','xyz')}} `
    -Definition @{ManagedProperties=@('Mode')}) $true 'Equivalent nested dictionary/PSObject shapes compared differently'
Assert-Equal (Test-DefenderDesiredState -Current @{Mode=@([pscustomobject]@{Name='abc'},[pscustomobject]@{Name='xyz'})} `
    -Desired @{Mode=@(@{Name='abc'},@{Name='xyz'})} -Definition @{ManagedProperties=@('Mode')}) $true 'Equivalent array object shapes compared differently'
Write-Host "PASS: $assertions Defender comparable-value assertions."
