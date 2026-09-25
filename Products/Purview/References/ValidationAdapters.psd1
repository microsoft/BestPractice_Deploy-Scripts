@{
    # =========================================================================
    # Purview configuration-validation adapter allowlist.
    #
    # Maintainer-owned reference data used by the validator:
    #
    #   * PurviewValidationModel.ps1 derives AdapterId, comparator, selector,
    #     prerequisite, and expected values from schema 1.2 IntendedState and
    #     refuses any value that is not listed here.
    #   * PurviewValidationCollectors.ps1 dispatches each derived AdapterId
    #     through a hardcoded switch and asserts that the switch covers exactly this
    #     list.
    #
    # A Deployment Plan is operator-supplied input. The validator therefore
    # never treats any string in the plan as a command, a script, or a
    # property path. The validator can only derive an adapter that already
    # exists in this file, and the adapter decides which read commands to run.
    #
    # Adding an adapter requires: an entry here, a collector branch, an
    # API/permission matrix row with a Microsoft Learn reference and a
    # verification date, and fixture coverage.
    # =========================================================================

    SchemaVersion = '1.1'

    # Comparators the plan may name for a managed field. The validator rejects
    # any other value before it connects to a tenant.
    Comparators = @(
        'ExactBoolean'
        'ExactString'
        'CaseInsensitiveString'
        'ExactInt'
        'SetEquality'
        'OrderedSequence'
        'Presence'
    )

    # Prerequisite kinds a plan action may declare. 'License' and 'Capability'
    # resolve at validation time; an unresolved prerequisite produces
    # 'Not evaluated' rather than 'Drift'.
    PrerequisiteKinds = @(
        'None'
        'License'
        'Capability'
    )

    # License prerequisite identifiers. These map to entitlement checks in the
    # collector module, not to raw SKU strings in the plan.
    LicensePrerequisites = @(
        'BusinessPremiumOrHigher'
        'E5OrPurviewSuite'
        'AuditPremium'
    )

    # Capability prerequisite identifiers. These map to command or service
    # availability checks in the collector module.
    CapabilityPrerequisites = @(
        'SharePointOnlineSession'
        'GraphDirectorySettings'
    )

    # Allowlisted adapters. 'Reads' is documentation for the API/permission
    # matrix and for the report's read attribution. It is never executed from
    # this file.
    Adapters = @(
        @{
            Id = 'purview.tenant.audit-standard'
            Module = 'Setup-TenantSettings'
            Service = 'ExchangeOnline'
            Reads = @('Get-AdminAuditLogConfig')
            ManagedFields = @('UnifiedAuditLogIngestionEnabled')
        }
        @{
            Id = 'purview.tenant.spo-labels'
            Module = 'Setup-TenantSettings'
            Service = 'SharePointOnline'
            Reads = @('Get-SPOTenant')
            ManagedFields = @('EnableAIPIntegration')
        }
        @{
            Id = 'purview.tenant.pdf-labels'
            Module = 'Setup-TenantSettings'
            Service = 'SharePointOnline'
            Reads = @('Get-SPOTenant')
            ManagedFields = @('EnableSensitivityLabelForPDF')
        }
        @{
            Id = 'purview.tenant.container-directory-setting'
            Module = 'Setup-TenantSettings'
            Service = 'MicrosoftGraph'
            Reads = @('Get-MgBetaDirectorySetting')
            ManagedFields = @('EnableMIPLabels')
        }
        @{
            Id = 'purview.tenant.label-coauthoring'
            Module = 'Setup-TenantSettings'
            Service = 'SecurityCompliance'
            Reads = @('Get-PolicyConfig')
            ManagedFields = @('EnableLabelCoauth')
        }
        @{
            Id = 'purview.tenant.audit-premium'
            Module = 'Setup-TenantSettings'
            Service = 'ExchangeOnline'
            Reads = @('Get-Mailbox')
            ManagedFields = @('AuditOwnerIncludesSearchQueryInitiated')
        }
        @{
            Id = 'purview.labels.taxonomy'
            Module = 'Setup-SensitivityLabels'
            Service = 'SecurityCompliance'
            Reads = @('Get-Label')
            ManagedFields = @('RootLabelCount', 'SubLabelCount', 'LabelSignatures')
        }
        @{
            Id = 'purview.labels.priority'
            Module = 'Setup-SensitivityLabels'
            Service = 'SecurityCompliance'
            Reads = @('Get-Label')
            ManagedFields = @('PriorityOrder')
        }
        @{
            Id = 'purview.labels.publish'
            Module = 'Setup-SensitivityLabels'
            Service = 'SecurityCompliance'
            Reads = @('Get-LabelPolicy', 'Get-Label')
            ManagedFields = @(
                'PolicyPresent', 'PublishedLabelSignatures', 'DefaultLabelSignature',
                'DefaultLabelForEmailSignature', 'MandatoryLabelling', 'DowngradeJustification'
            )
        }
        @{
            Id = 'purview.labels.attachment-inheritance'
            Module = 'Setup-SensitivityLabels'
            Service = 'SecurityCompliance'
            Reads = @('Get-LabelPolicy')
            ManagedFields = @('AttachmentAction')
        }
        @{
            Id = 'purview.labels.content-marking'
            Module = 'Setup-SensitivityLabels'
            Service = 'SecurityCompliance'
            Reads = @('Get-Label')
            ManagedFields = @('ContentMarkedLabelSignatures')
        }
        @{
            Id = 'purview.labels.encryption'
            Module = 'Setup-SensitivityLabels'
            Service = 'SecurityCompliance'
            Reads = @('Get-Label')
            ManagedFields = @(
                'EncryptedLabelSignatures', 'EncryptionOfflineAccessDays',
                'EncryptionContentExpiration'
            )
        }
        @{
            Id = 'purview.labels.container-scope'
            Module = 'Setup-SensitivityLabels'
            Service = 'SecurityCompliance'
            Reads = @('Get-Label')
            ManagedFields = @('ContainerScopedLabelSignatures')
        }
        @{
            Id = 'purview.dlp.workload'
            Module = 'Setup-DLP'
            Service = 'SecurityCompliance'
            Reads = @('Get-DlpCompliancePolicy', 'Get-DlpComplianceRule')
            ManagedFields = @(
                'PolicyPresent', 'PolicyMode', 'RulePresent', 'BlockAccess',
                'LabelPathCount', 'LabelSignatures', 'PolicySignatures'
            )
        }
        @{
            Id = 'purview.retention.exchange'
            Module = 'Setup-Retention'
            Service = 'SecurityCompliance'
            Reads = @('Get-RetentionCompliancePolicy', 'Get-RetentionComplianceRule')
            ManagedFields = @(
                'PolicyPresent', 'RetentionDurationDays', 'RetentionAction',
                'ExpirationDateOption', 'Locations'
            )
        }
        @{
            Id = 'purview.ai.copilot-dlp'
            Module = 'Setup-AIGovernance'
            Service = 'SecurityCompliance'
            Reads = @('Get-DlpCompliancePolicy', 'Get-DlpComplianceRule')
            ManagedFields = @(
                'PolicyCount', 'PolicyMode', 'EnforcementPlanes',
                'RestrictAccessSettings', 'ScopePrincipalSignatures',
                'LabelPathCount', 'PolicySignatures'
            )
        }
    )
}
