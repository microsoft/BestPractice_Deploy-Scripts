@{
    ProductName = 'Microsoft Defender Best Practice Toolkit'
    ProductVersion = '0.1.0'
    ManagedByTag = '[Managed by SMBTool Defender Toolkit]'

    StateManagement = @{
        ObjectDefinitions = @{
            Policy = @{
                IdentifierProperties = @('Name')
                ManagedProperties = @('Name', 'Settings')
                ManagedTagProperty = 'ManagedBy'
            }
            Connector = @{
                IdentifierProperties = @('Name', 'ConnectorType')
                ManagedProperties = @('Name', 'ConnectorType', 'Settings')
                ManagedTagProperty = 'ManagedBy'
            }
            Recipient = @{
                IdentifierProperties = @('Address')
                ManagedProperties = @('Address', 'Role')
                ManagedTagProperty = 'ManagedBy'
            }
            Template = @{
                IdentifierProperties = @('Name', 'TemplateType')
                ManagedProperties = @('Name', 'TemplateType', 'Settings')
                ManagedTagProperty = 'ManagedBy'
            }
            IntunePolicy = @{
                IdentifierProperties = @('Name', 'Platform')
                ManagedProperties = @('Name', 'Platform', 'Settings')
                ManagedTagProperty = 'ManagedBy'
            }
            QuarantinePolicy = @{
                IdentifierProperties = @('Name')
                ManagedProperties = @(
                    'Name'
                    'EndUserQuarantinePermissionsValue'
                    'ESNEnabled'
                    'IncludeMessagesFromBlockedSenderAddress'
                )
                ManagedTagProperty = 'AdminDisplayName'
            }
        }
    }

    DefenderForOffice365 = @{
        QuarantinePolicy = @{
            Key = 'mdo-quarantine-limited-access'
            Name = 'SMBTool-Quarantine-LimitedAccess'
            EndUserQuarantinePermissionsValue = 43
            ESNEnabled = $true
            IncludeMessagesFromBlockedSenderAddress = $false
            ProtectionPolicyAssignments = @()
        }
    }

    DefenderForBusiness = @{
        AsrAuditPolicy = @{
            Key = 'mde-asr-audit'
            Name = 'SMBTool - ASR rules in audit mode'
            Description = 'Configures the Microsoft-recommended ASR rules in audit mode.'
            TemplateFamily = 'endpointSecurityAttackSurfaceReduction'
            TemplateVersion = 1
            TemplateSettingCount = 5
            Platform = 'windows10'
            Technologies = @('mdm', 'microsoftSense')
            ScopeTagIds = @('0')
            RuleMode = 'Audit'
        }
    }

    # Keep policy names, application-internal keys, and risk classifications in
    # configuration. Keys are not Microsoft recommendation identifiers.
    BestPracticeItems = @(
        @{
            Key = 'mdo-auto-forward'
            Name = 'Block outbound auto-forwarding'
            Module = 'Setup-MdoEopBaseline'
            CapabilityKey = 'exchange-online'
            LicenseCapability = 'mdo'
            Risk = 'High'
            RequiresHighRiskGate = $true
            PermissionOperations = @('mdo-auto-forward-read')
        }
        @{
            Key = 'mdo-safe-attachments'
            Name = 'Enable Safe Attachments for SPO, OneDrive, and Teams'
            Module = 'Setup-MdoEopBaseline'
            CapabilityKey = 'exchange-online'
            LicenseCapability = 'mdo'
            Risk = 'Standard'
            RequiresHighRiskGate = $false
            PermissionOperations = @('mdo-safe-attachments-read')
        }
        @{
            Key = 'mdo-quarantine-limited-access'
            Name = 'Create a limited-access quarantine policy'
            Module = 'Setup-MdoEopBaseline'
            CapabilityKey = 'exchange-online'
            LicenseCapability = 'mdo'
            Risk = 'Standard'
            RequiresHighRiskGate = $false
            PermissionOperations = @('mdo-quarantine-policy-read')
        }
        @{
            Key = 'mde-asr-audit'
            Name = 'Deploy ASR rules in audit mode'
            Module = 'Setup-DefenderForBusiness'
            CapabilityKey = 'intune-asr-audit'
            LicenseCapability = 'mde'
            Risk = 'Standard'
            RequiresHighRiskGate = $false
            PermissionOperations = @('mde-asr-audit-read')
        }
    )

    # Licensing is documented for operator review only. Runtime readiness is
    # established by workload/API availability and authorized readback, not by
    # inferring entitlement from SKU or service-plan names.
    LicenseCapabilities = @{
        mdo = @{
            DocumentationUrl = 'https://learn.microsoft.com/en-us/defender-office-365/service-description-mdvo'
            Requirement = 'Microsoft Defender for Office 365 licensing; suites and add-ons can satisfy this requirement.'
        }
        mde = @{
            DocumentationUrl = 'https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint'
            Requirement = 'Microsoft Defender for Endpoint licensing; suites and add-ons can satisfy this requirement.'
        }
        mdca = @{
            DocumentationUrl = 'https://learn.microsoft.com/en-us/defender-cloud-apps/what-is-defender-for-cloud-apps'
            Requirement = 'Microsoft Defender for Cloud Apps licensing; suites and add-ons can satisfy this requirement.'
        }
    }

    # Placeholder for Graph resource IDs, recipient IDs, policy templates, and
    # other tenant-specific values. Do not place secrets or tokens here.
    Api = @{
        GraphBaseUri = 'https://graph.microsoft.com/v1.0'
        GraphScopes = @()
        RequiredCommands = @(
            'Connect-MgGraph'
            'Invoke-MgGraphRequest'
            'Get-MgContext'
        )
    }

    # Capability records describe what this preview can truthfully connect to.
    # They are readiness metadata, not permission to dispatch write operations.
    WorkloadCapabilities = @(
        @{
            Key = 'graph-tenant-identity'
            Workload = 'Microsoft Graph'
            Status = 'Verified'
            Mode = 'ReadOnly'
            Detail = 'Tenant identity preflight through delegated Graph; licensing is documented, not inferred from SKU metadata.'
        }
        @{
            Key = 'exchange-online'
            Workload = 'Exchange Online / EOP'
            Status = 'Verified'
            Mode = 'ReadOnly'
            Detail = 'Delegated EXO connection, organization targeting, and outbound auto-forwarding policy readback are verified; setter RBAC is checked only before an approved write.'
        }
        @{
            Key = 'information-protection'
            Workload = 'Security and Compliance PowerShell'
            Status = 'GuidedOnly'
            Mode = 'Unavailable'
            Detail = 'No IPPS session or policy readback is claimed by this preview.'
        }
        @{
            Key = 'intune-asr-audit'
            Workload = 'Microsoft Intune ASR Audit policy'
            Status = 'Verified'
            Mode = 'ManagedConfiguration'
            Detail = 'ASR Audit policy readback and the explicitly enabled managed apply and recovery paths are verified; tenant capability, permissions, schema, and pilot-group scope are checked before mutation.'
        }
        @{
            Key = 'defender-portals'
            Workload = 'Defender portals and MDCA'
            Status = 'GuidedOnly'
            Mode = 'Unavailable'
            Detail = 'No Defender portal or Cloud Apps connector session is claimed by this preview.'
        }
    )

    # Permission requirements are operation-scoped. WriteApply is deliberately
    # unverified until each write endpoint has authoritative API, role, license,
    # readback, and rollback evidence; it must not be silently consented.
    PermissionModel = @{
        Profiles = @{
            ReadOnlyPreflight = @{
                MinimumRoles = @('User')
                MinimumGdapRoles = @()
                ConsentOwner = 'Tenant administrator or delegated application administrator'
                Status = 'Verified'
            }
            WriteApply = @{
                MinimumRoles = @()
                MinimumGdapRoles = @()
                ConsentOwner = 'Defined by each explicitly verified write operation'
                Status = 'GuidedOnly'
            }
        }
        Operations = @(
            @{
                Key = 'tenant-identity'
                Module = 'Connect-DefenderServices'
                Phase = 'ReadOnlyPreflight'
                ReadWrite = 'Read'
                Endpoint = '/organization?$select=id,verifiedDomains'
                License = 'Microsoft Entra tenant'
                # User.Read covers id and verifiedDomains on /organization.
                GraphDelegatedScopes = @('User.Read')
                GraphApplicationPermissions = @('Organization.Read.All')
                MinimumRoles = @('User')
                MinimumGdapRoles = @()
                VerificationStatus = 'Verified'
                Readback = 'Organization response contains tenant id and verified domains.'
                Rollback = 'Read-only operation; no rollback required.'
            }
            @{
                Key = 'mdo-auto-forward-read'
                Module = 'Setup-MdoEopBaseline'
                Phase = 'ReadOnlyPreflight'
                ReadWrite = 'Read'
                Endpoint = 'Get-HostedOutboundSpamFilterPolicy -Identity Default; Get-ManagementRole; Get-ManagementRoleAssignment -RoleAssignee'
                License = 'Exchange Online Protection workload availability; commercial licensing remains operator-reviewed'
                GraphDelegatedScopes = @()
                GraphApplicationPermissions = @()
                WorkloadDelegatedPermissions = @('Exchange Online delegated session')
                WorkloadApplicationPermissions = @('Exchange.ManageAsApp')
                MinimumRoles = @('Security Admin or Transport Hygiene through Exchange RBAC')
                MinimumGdapRoles = @('Exchange Administrator')
                VerificationStatus = 'Verified'
                Readback = 'Default outbound spam-filter policy and effective operator RBAC are readable.'
                Rollback = 'Read-only operation; no rollback required.'
            }
            @{
                Key = 'mdo-auto-forward-apply'
                Module = 'Setup-MdoEopBaseline'
                Phase = 'GuidedOnly'
                ReadWrite = 'Write'
                Endpoint = 'Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off'
                License = 'Microsoft Defender for Office 365; see LicenseCapabilities.mdo.DocumentationUrl'
                GraphDelegatedScopes = @()
                GraphApplicationPermissions = @()
                WorkloadDelegatedPermissions = @('Exchange Online delegated session')
                WorkloadApplicationPermissions = @('Exchange.ManageAsApp')
                MinimumRoles = @('Exchange Administrator (or equivalent custom Exchange RBAC role group)')
                MinimumGdapRoles = @('Exchange Administrator')
                VerificationStatus = 'GuidedOnly'
                Readback = 'Get-HostedOutboundSpamFilterPolicy -Identity Default; verify AutoForwardingMode is Off.'
                Rollback = 'Manual Exchange Online policy recovery after operator review.'
            }
            @{
                Key = 'mdo-safe-attachments-read'
                Module = 'Setup-MdoEopBaseline'
                Phase = 'ReadOnlyPreflight'
                ReadWrite = 'Read'
                Endpoint = 'Get-AtpPolicyForO365 -Identity Default; Get-ManagementRole; Get-ManagementRoleAssignment -RoleAssignee'
                License = 'Exchange Online Protection workload availability; commercial licensing remains operator-reviewed'
                GraphDelegatedScopes = @()
                GraphApplicationPermissions = @()
                WorkloadDelegatedPermissions = @('Exchange Online delegated session')
                WorkloadApplicationPermissions = @('Exchange.ManageAsApp')
                MinimumRoles = @('Security Admin or Transport Hygiene through Exchange RBAC')
                MinimumGdapRoles = @('Exchange Administrator')
                VerificationStatus = 'Verified'
                Readback = 'Default ATP policy and effective operator RBAC are readable.'
                Rollback = 'Read-only operation; no rollback required.'
            }
            @{
                Key = 'mdo-safe-attachments-apply'
                Module = 'Setup-MdoEopBaseline'
                Phase = 'GuidedOnly'
                ReadWrite = 'Write'
                Endpoint = 'Set-AtpPolicyForO365 -Identity Default -EnableATPForSPOTeamsODB $true'
                License = 'Microsoft Defender for Office 365; see LicenseCapabilities.mdo.DocumentationUrl'
                GraphDelegatedScopes = @()
                GraphApplicationPermissions = @()
                WorkloadDelegatedPermissions = @('Exchange Online delegated session')
                WorkloadApplicationPermissions = @('Exchange.ManageAsApp')
                MinimumRoles = @('Exchange Administrator (or equivalent custom Exchange RBAC role group)')
                MinimumGdapRoles = @('Exchange Administrator')
                VerificationStatus = 'GuidedOnly'
                Readback = 'Get-AtpPolicyForO365 -Identity Default; verify EnableATPForSPOTeamsODB is True.'
                Rollback = 'Allow up to 30 minutes for propagation, then restore the captured prior Boolean after operator review if recovery is required.'
            }
            @{
                Key = 'mdo-quarantine-policy-read'
                Module = 'Setup-MdoEopBaseline'
                Phase = 'ReadOnlyPreflight'
                ReadWrite = 'Read'
                Endpoint = 'Get-QuarantinePolicy; filter exact name SMBTool-Quarantine-LimitedAccess; Get-ManagementRole; Get-ManagementRoleAssignment -RoleAssignee'
                License = 'Microsoft Defender for Office 365; see LicenseCapabilities.mdo.DocumentationUrl'
                GraphDelegatedScopes = @()
                GraphApplicationPermissions = @()
                WorkloadDelegatedPermissions = @('Exchange Online delegated session')
                WorkloadApplicationPermissions = @('Exchange.ManageAsApp')
                MinimumRoles = @('Security Administrator or Quarantine role through Exchange RBAC')
                MinimumGdapRoles = @('Exchange Administrator')
                VerificationStatus = 'Verified'
                Readback = 'Get-QuarantinePolicy; filter and verify the exact policy name before accepting the result.'
                Rollback = 'Read-only operation; no rollback required.'
            }
            @{
                Key = 'mdo-quarantine-policy-apply'
                Module = 'Setup-MdoEopBaseline'
                Phase = 'GuidedOnly'
                ReadWrite = 'Write'
                Endpoint = 'New-QuarantinePolicy for SMBTool-Quarantine-LimitedAccess'
                License = 'Microsoft Defender for Office 365; see LicenseCapabilities.mdo.DocumentationUrl'
                GraphDelegatedScopes = @()
                GraphApplicationPermissions = @()
                WorkloadDelegatedPermissions = @('Exchange Online delegated session')
                WorkloadApplicationPermissions = @('Exchange.ManageAsApp')
                MinimumRoles = @('Exchange Administrator or equivalent custom Exchange RBAC role')
                MinimumGdapRoles = @('Exchange Administrator')
                VerificationStatus = 'GuidedOnly'
                Readback = 'Get-QuarantinePolicy; filter the exact policy name and verify permissions 43, notifications enabled, and blocked-sender messages excluded.'
                Rollback = 'Leave the newly created, unassigned policy in place pending an explicit removal decision. Existing policies are never updated.'
            }
            @{
                Key = 'mde-asr-audit-read'
                Module = 'Setup-DefenderForBusiness'
                Phase = 'ReadOnlyPreflight'
                ReadWrite = 'Read'
                Endpoint = 'GET /deviceManagement/configurationPolicies, /configurationPolicyTemplates, and linked configurationSettings (Microsoft Graph beta)'
                License = 'Microsoft Intune and Microsoft Defender for Endpoint; see LicenseCapabilities.mde.DocumentationUrl'
                GraphDelegatedScopes = @('DeviceManagementConfiguration.Read.All')
                GraphApplicationPermissions = @('DeviceManagementConfiguration.Read.All')
                MinimumRoles = @('Endpoint Security Manager')
                MinimumGdapRoles = @('Intune Administrator')
                VerificationStatus = 'Verified'
                Readback = 'One active endpointSecurityAttackSurfaceReduction template exposes five parent settings and 19 child rule definitions; existing policy state is readable.'
                Rollback = 'Read-only operation; no rollback required.'
            }
            @{
                Key = 'mde-asr-audit-apply'
                Module = 'Setup-DefenderForBusiness'
                Phase = 'WriteApply'
                ReadWrite = 'Write'
                Endpoint = 'POST /deviceManagement/configurationPolicies and POST /deviceManagement/configurationPolicies/{id}/assign (Microsoft Graph beta)'
                License = 'Microsoft Intune and Microsoft Defender for Endpoint; see LicenseCapabilities.mde.DocumentationUrl'
                GraphDelegatedScopes = @('DeviceManagementConfiguration.ReadWrite.All', 'Group.Read.All')
                GraphApplicationPermissions = @('DeviceManagementConfiguration.ReadWrite.All', 'Group.Read.All')
                MinimumRoles = @('Endpoint Security Manager')
                MinimumGdapRoles = @('Intune Administrator')
                VerificationStatus = 'Verified'
                Readback = 'GET the captured policy, settings, and assignments; verify the exact ASR Audit payload and one unfiltered direct pilot-group target.'
                Rollback = 'Retain the captured policy ID and use separately approved pilot-owned policy recovery after exact ownership and assignment-isolation readback.'
            }
            @{
                Key = 'mde-asr-audit-recovery'
                Module = 'Setup-DefenderForBusiness'
                Phase = 'WriteApply'
                ReadWrite = 'Write'
                Endpoint = 'DELETE /deviceManagement/configurationPolicies/{id} (Microsoft Graph beta)'
                License = 'Microsoft Intune and Microsoft Defender for Endpoint; see LicenseCapabilities.mde.DocumentationUrl'
                GraphDelegatedScopes = @('DeviceManagementConfiguration.ReadWrite.All', 'Group.Read.All')
                GraphApplicationPermissions = @('DeviceManagementConfiguration.ReadWrite.All', 'Group.Read.All')
                MinimumRoles = @('Endpoint Security Manager')
                MinimumGdapRoles = @('Intune Administrator')
                VerificationStatus = 'Verified'
                Readback = 'GET /deviceManagement/configurationPolicies; verify the captured pilot-owned policy ID is absent.'
                Rollback = 'Recovery is the deletion; never recreate or modify a pre-existing customer-managed policy.'
            }
        )
    }

    # These checks are deliberately explicit where Microsoft does not expose a
    # stable, least-privilege read API suitable for unattended verification.
    Preflight = @{
        AuditReadinessDisposition = 'GuidedOnly'
        EmergencyAccessDisposition = 'GuidedOnly'
    }

    Report = @{
        OutputDirectory = '.\Reports'
        JsonLogFileName = 'defender-run-log.json'
        HtmlReportFileName = 'defender-run-report.html'
    }
}
