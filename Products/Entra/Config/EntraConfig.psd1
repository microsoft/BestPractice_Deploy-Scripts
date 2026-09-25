@{
    ProductName = 'Microsoft Entra Best Practice Toolkit'
    ProductVersion = '0.4.0'
    ManagedByTag = '[Managed by SMBTool Entra Toolkit]'

    # Source baseline: Identity Protection Best Practice Deployment guide for
    # Small Business (Business Premium / Microsoft Entra ID P1, 6 March 2026).
    # GuideTask maps an item back to the source so evidence can be traced.
    # The guide places all Conditional Access work under Priority 1 ("Set up
    # Conditional Access using built-in templates"), preceded by the Priority 1
    # task "Create emergency access account(s)".
    # Additional P1 scenarios follow the Microsoft Learn references in
    # docs/Coverage.md and have not inherited the original baseline's pilot evidence.
    BestPracticeItems = @(
        @{
            Key = 'emergency-access-account'
            Name = 'Ensure an emergency access (break-glass) account is excluded from Conditional Access'
            Module = 'Setup-EmergencyAccess'
            LicenseCapability = 'entraId'
            Risk = 'Standard'
            RequiresHighRiskGate = $false
            Priority = 1
            GuideTask = 1
        }
        @{
            Key = 'conditional-access-baseline'
            Name = 'Deploy the Conditional Access baseline policies'
            Module = 'Setup-ConditionalAccessBaseline'
            LicenseCapability = 'entraId'
            # High risk: Conditional Access can deny sign-in to every user and
            # lock administrators out. Report-only by default; enforcing is a
            # deliberate, separately gated promotion.
            Risk = 'High'
            RequiresHighRiskGate = $true
            Priority = 1
            GuideTask = 2
        }
        @{
            Key = 'tenant-security-settings'
            Name = 'Harden tenant-wide identity settings (Zero Trust)'
            Module = 'Setup-TenantSecuritySettings'
            LicenseCapability = 'entraId'
            Risk = 'Standard'
            RequiresHighRiskGate = $false
            Priority = 2
            GuideTask = 3
        }
    )

    LicenseCapabilities = @{
        entraId = @{
            SkuPartNumbers = @('SPB', 'AAD_PREMIUM', 'EMS', 'EMSPREMIUM')
            ServicePlanNames = @('AAD_PREMIUM', 'AAD_PREMIUM_P2')
        }
    }

    # Least-privilege delegated scopes. Read scopes cover preflight/readback;
    # the ReadWrite scopes are each required by a validated write path. Do not
    # place secrets or tokens here.
    Api = @{
        GraphBaseUri = 'https://graph.microsoft.com/v1.0'
        GraphScopes = @(
            'User.Read'
            'Organization.Read.All'
            'Policy.Read.All'
            'RoleManagement.Read.Directory'
            'Group.Read.All'
            'User.Read.All'
            # Write scopes, each tied to a validated apply path:
            'Policy.ReadWrite.ConditionalAccess'   # create the CA baseline
            'User.ReadWrite.All'                    # create a break-glass account when requested
            'Policy.ReadWrite.Authorization'        # user-consent and guest tenant settings
            'Policy.ReadWrite.ConsentRequest'       # admin consent workflow
            'Domain.ReadWrite.All'                  # password expiration policy
        )
        RequiredCommands = @(
            'Connect-MgGraph'
            'Invoke-MgGraphRequest'
            'Get-MgContext'
        )
    }

    # The all-users-style policies (block legacy auth, MFA for all users,
    # compliant-or-MFA, no persistent browser, approved client apps, unsupported
    # platform) are scoped to this pilot group rather than every user, because a
    # Conditional Access policy applied tenant-wide on a first run can deny
    # access broadly. Role- and app-scoped policies (admins, admin portals,
    # Azure management) keep their template scope. Tenant-wide is an explicit
    # opt-in via -AssignTenantWide.
    Assignment = @{
        DefaultScope = 'PilotGroup'
        RequirePilotGroupForHighRisk = $true
        AllowTenantWideAssignmentForHighRisk = $false
    }

    # Conditional Access is the highest blast-radius surface in the baseline.
    ConditionalAccess = @{
        # Every policy is created in this state by default. The guide's
        # recommended target state per policy is recorded below; promoting a
        # policy to 'enabled' is a deliberate configuration change once the
        # guide's stated preconditions are met.
        DefaultState = 'enabledForReportingButNotEnforced'

        # A break-glass exclusion is mandatory: the baseline refuses to create
        # any policy until an emergency-access user or group is available, so a
        # misconfiguration cannot lock every account out.
        RequireBreakGlassExclusion = $true
        BreakGlass = @{
            # Operator supplies an existing emergency-access account/group here,
            # or sets CreateAccountIfMissing to have Setup-EmergencyAccess create
            # a dedicated cloud-only break-glass account (guide Priority 1 task).
            ExcludeUserIds = @()
            ExcludeGroupIds = @()
            CreateAccountIfMissing = $false
            AccountDisplayName = 'Emergency Access (break-glass)'
            AccountUpnPrefix = 'break-glass-emergency'
            # The built-in Emergency Access Account directory role many CA
            # templates already exclude by role.
            EmergencyAccessRoleId = 'd29b2b05-8046-44ba-8758-1e26182fcf32'
        }

        PolicyTemplateDirectory = 'Config/PolicyTemplates'
        # Empty preserves existing names. Example: 'SMB-CA-' adds each policy's
        # stable tier/sequence/scope NameCode before its purpose.
        DisplayNamePrefix = ''
        # Retain prior prefixes after changing one so reruns find existing policies.
        PreviousDisplayNamePrefixes = @()

        # Original templates retain the guide's target ("On" = enabled).
        # Additions stay ReportOnly pending their own pilot. This metadata
        # never promotes a policy; DefaultState controls new-policy state.
        Policies = @(
            @{ Key = 'require-mfa-admins'; File = 'require-mfa-admins.json'; RecommendedState = 'On'; Tier = 'P1Baseline'; NameCode = 'P1-01-Admins' }
            @{ Key = 'block-legacy-authentication'; File = 'block-legacy-authentication.json'; RecommendedState = 'On'; Tier = 'P1Baseline'; NameCode = 'P1-02-Users' }
            @{ Key = 'require-mfa-all-users'; File = 'require-mfa-all-users.json'; RecommendedState = 'On'; Tier = 'P1Baseline'; NameCode = 'P1-03-Users' }
            @{ Key = 'require-mfa-guests'; File = 'require-mfa-guests.json'; RecommendedState = 'On'; Tier = 'P1Baseline'; NameCode = 'P1-04-Guests' }
            @{ Key = 'require-mfa-azure-management'; File = 'require-mfa-azure-management.json'; RecommendedState = 'On'; Tier = 'P1Baseline'; NameCode = 'P1-05-AzureManagement' }
            @{ Key = 'require-mfa-admin-portals'; File = 'require-mfa-admin-portals.json'; RecommendedState = 'On'; Tier = 'P1Baseline'; NameCode = 'P1-06-AdminPortals' }
            @{ Key = 'block-unsupported-device-platform'; File = 'block-unsupported-device-platform.json'; RecommendedState = 'On'; Tier = 'P1Baseline'; NameCode = 'P1-07-Users' }
            @{ Key = 'no-persistent-browser-session'; File = 'no-persistent-browser-session.json'; RecommendedState = 'ReportOnly'; Tier = 'P1Baseline'; NameCode = 'P1-08-Users' }
            @{
                Key = 'require-approved-client-apps'
                File = 'require-approved-client-apps.json'
                RecommendedState = 'ReportOnly'
                Tier = 'P1Baseline'
                NameCode = 'P1-09-Mobile'
                LegacyDisplayNames = @('Require approved client apps or app protection policies')
                # Correcting existing mobile filters can broaden effective scope.
                # Keep this migration manual, including when AdoptExisting is set.
                ReviewExistingOnly = $true
            }
            @{ Key = 'require-compliant-device-or-mfa'; File = 'require-compliant-device-or-mfa.json'; RecommendedState = 'ReportOnly'; Tier = 'P1Baseline'; NameCode = 'P1-10-Users' }
            @{
                Key = 'block-device-code-flow'
                File = 'block-device-code-flow.json'
                RecommendedState = 'ReportOnly'
                Tier = 'P1Baseline'
                NameCode = 'P1-11-Users'
                Enabled = $true
                ReviewExistingOnly = $true
            }
            @{
                Key = 'protect-security-info-registration'
                File = 'protect-security-info-registration.json'
                RecommendedState = 'ReportOnly'
                Tier = 'P1Baseline'
                NameCode = 'P1-12-Registration'
                Enabled = $true
                ReviewExistingOnly = $true
            }
            @{
                Key = 'require-phishing-resistant-mfa-admins'
                File = 'require-phishing-resistant-mfa-admins.json'
                RecommendedState = 'ReportOnly'
                Tier = 'P1Hardened'
                NameCode = 'P1H-01-Admins'
                # Targets roles, not the pilot group. Verify method readiness
                # for all targeted administrators before separately enforcing.
                Enabled = $false
                ReviewExistingOnly = $true
            }
        )
    }

    Report = @{
        OutputDirectory = '.\Reports'
        JsonLogFileName = 'entra-run-log.json'
        HtmlReportFileName = 'entra-run-report.html'
    }

    # Tenant-wide identity hardening from the Zero Trust "Configure Microsoft
    # Entra for increased security" guidance. Each setting is opt-in via Apply;
    # when Apply is $false the module reports current vs recommended state
    # (GuidedOnly) and changes nothing. Every write uses a GA v1.0 Graph API.
    TenantSecurity = @{
        # Restrict who users can consent to apps for (user-consent to verified
        # publishers / low-impact permissions only).
        UserConsent = @{
            Apply = $false
            PermissionGrantPoliciesAssigned = @('managePermissionGrantsForSelf.microsoft-user-default-low')
        }
        # Enable the admin consent request workflow so users can request access
        # that admins review, instead of consenting themselves.
        AdminConsentWorkflow = @{
            Apply = $false
            IsEnabled = $true
            ReviewerGroupIds = @()
        }
        # Restrict guest access: only admins/guest-inviters can invite, and
        # guests get the restricted directory role.
        GuestAccess = @{
            Apply = $false
            AllowInvitesFrom = 'adminsAndGuestInviters'
            # Restricted guest user role (most limited directory access).
            GuestUserRoleId = '2af84b1e-32c8-42b7-82bc-daa82404023b'
        }
        # Disable password expiration (Microsoft guidance: long-lived passwords
        # with MFA beat forced rotation). Applied to the primary verified domain.
        PasswordExpiration = @{
            Apply = $false
            DisableExpiration = $true
        }
    }
}
