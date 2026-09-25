#requires -Version 7.0

function Get-PurviewTenantIdentity {
    [CmdletBinding()]
    param()

    $identity = [pscustomobject]@{
        DisplayName = $null
        TenantId = $null
        DefaultDomain = $null
        InitialDomain = $null
        AllDomains = @()
        Source = $null
    }

    if (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
        try {
            $org = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains' `
                -ErrorAction Stop
            if ($org -and $org.value -and @($org.value).Count -gt 0) {
                $item = @($org.value)[0]
                $identity.DisplayName = $item.displayName
                $identity.TenantId = $item.id
                $identity.AllDomains = @($item.verifiedDomains | ForEach-Object { $_.name })
                $defaultDomain = @($item.verifiedDomains | Where-Object { $_.isDefault })
                $initialDomain = @($item.verifiedDomains | Where-Object { $_.isInitial })
                if ($defaultDomain.Count -gt 0) { $identity.DefaultDomain = $defaultDomain[0].name }
                if ($initialDomain.Count -gt 0) { $identity.InitialDomain = $initialDomain[0].name }
                $identity.Source = 'Microsoft Graph (/organization)'
                return $identity
            }
        } catch {
            Write-Verbose "Graph identity lookup failed, falling back to Exchange Online: $($_.Exception.Message)"
        }
    }

    try {
        $organization = Get-OrganizationConfig -ErrorAction Stop
        if ($organization) {
            $identity.DisplayName = if ($organization.DisplayName) {
                $organization.DisplayName
            } else {
                $organization.Name
            }
            if ($organization.PSObject.Properties['Guid'] -and $organization.Guid) {
                $identity.TenantId = [string]$organization.Guid
            }
        }
        $domains = @(Get-AcceptedDomain -ErrorAction Stop)
        $identity.AllDomains = @($domains | ForEach-Object { $_.DomainName })
        $defaultDomain = @($domains | Where-Object { $_.Default })
        $initialDomain = @($domains | Where-Object { $_.InitialDomain })
        if ($defaultDomain.Count -gt 0) { $identity.DefaultDomain = $defaultDomain[0].DomainName }
        if ($initialDomain.Count -gt 0) { $identity.InitialDomain = $initialDomain[0].DomainName }
        $identity.Source = 'Exchange Online (Get-OrganizationConfig + Get-AcceptedDomain)'
        return $identity
    } catch {
        throw "Could not resolve tenant identity from Graph or Exchange Online. Connection may have failed silently. Error: $($_.Exception.Message)"
    }
}

function Test-PurviewExpectedTenantMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Identity,
        [string] $TenantAdminUpn,
        [string] $DelegatedOrganization
    )

    $expected = if ($DelegatedOrganization) {
        $DelegatedOrganization.ToLowerInvariant()
    } elseif ($TenantAdminUpn -match '@(.+)$') {
        $Matches[1].ToLowerInvariant()
    } else {
        $null
    }
    $source = if ($DelegatedOrganization) { '-DelegatedOrganization' } else { 'admin UPN suffix' }

    if (-not $expected) {
        return [pscustomobject]@{
            Match = $false
            Matched = $false
            Source = '(could not derive expected tenant from inputs)'
            Expected = $null
            Reason = 'Cannot validate tenant identity: no delegated organization was supplied and the admin UPN has no domain suffix.'
        }
    }

    $domains = @(
        $Identity.AllDomains |
            Where-Object { $_ } |
            ForEach-Object { ([string]$_).ToLowerInvariant() }
    )
    $match = $domains -contains $expected
    return [pscustomobject]@{
        Match = $match
        Matched = $match
        Source = $source
        Expected = $expected
        Reason = if ($match) {
            "Expected domain '$expected' from $source is verified on the connected tenant."
        } else {
            "Expected domain '$expected' from $source is NOT a verified domain on the connected tenant. The signed-in session appears to be authenticated against a DIFFERENT tenant than intended."
        }
    }
}

function Test-PurviewValidationGraphContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string] $ExpectedAccount,
        [Parameter(Mandatory)] [string[]] $RequiredScopes,
        [string[]] $AllowedIdentityScopes = @('openid', 'profile', 'email', 'offline_access')
    )

    $actualScopes = @(
        $Context.Scopes |
            Where-Object { $_ } |
            ForEach-Object { [string]$_ } |
            Select-Object -Unique
    )
    $allowedScopes = @($RequiredScopes + $AllowedIdentityScopes | Select-Object -Unique)
    $missingScopes = @(
        $RequiredScopes |
            Where-Object { $actualScopes -notcontains $_ } |
            Select-Object -Unique
    )
    $unexpectedScopes = @(
        $actualScopes |
            Where-Object { $allowedScopes -notcontains $_ } |
            Select-Object -Unique
    )
    $accountMatched = [bool]$Context.Account -and
        ([string]$Context.Account -ieq $ExpectedAccount)

    [pscustomobject]@{
        Matched = ($accountMatched -and
            $missingScopes.Count -eq 0 -and
            $unexpectedScopes.Count -eq 0)
        AccountMatched = $accountMatched
        MissingScopes = $missingScopes
        UnexpectedScopes = $unexpectedScopes
    }
}
