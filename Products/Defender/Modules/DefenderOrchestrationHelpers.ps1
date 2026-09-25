#requires -Version 7.0

function Invoke-DefenderModuleProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ScriptPath,
        [hashtable] $Arguments = @{},
        [scriptblock] $ProcessInvoker = {
            param($Path, $BoundArguments)
            & $Path @BoundArguments
        }
    )

    if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
        throw "Module script not found: $ScriptPath"
    }
    & $ProcessInvoker $ScriptPath $Arguments
}

function Invoke-DefenderModuleSequence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Tasks,
        [scriptblock] $ProcessInvoker = {
            param($Path, $BoundArguments)
            & $Path @BoundArguments
        },
        [switch] $ContinueOnError
    )

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($task in @($Tasks)) {
        try {
            Invoke-DefenderModuleProcess -ScriptPath $task.ScriptPath `
                -Arguments $task.Arguments -ProcessInvoker $ProcessInvoker
            $results.Add([pscustomobject]@{
                Name = [string] $task.Name
                Status = 'Succeeded'
                Error = $null
            })
        }
        catch {
            $results.Add([pscustomobject]@{
                Name = [string] $task.Name
                Status = 'Failed'
                Error = $_.Exception.Message
            })
            if (-not $ContinueOnError) {
                throw
            }
        }
    }
    return @($results)
}
