@{
    SchemaVersion = '1.1'
    Role = 'Supporting'
    Guide = @{
        Id = 'MS-PURVIEW-LIGHTWEIGHT-DLP'
        Title = 'Lightweight guide to mitigate data leakage'
        Edition = '2026-03-31'
        RevisionDate = '2026-03-31'
        VerifiedDate = '2026-08-11'
        Publisher = 'Microsoft Learn'
        SourceClassification = 'AuthoritativePublic'
        SourceUri = 'https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-intro'
        SourceCommit = 'a580c1c2e34a67b10bce436a05a44376cf21f61d'
        Owner = 'SMB Best Practice Tool maintainers'
    }
    Controls = @(
        @{
            Id = 'DS-1.1'
            Section = 'Step 1 - Create sensitivity labels'
            Summary = 'Create parent sensitivity labels for files and other data assets.'
            Status = 'Aligned'
            ActionIds = @('purview.labels.taxonomy')
            ConfigPaths = @('Labels')
            Rationale = ''
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step1')
        }
        @{
            Id = 'DS-1.2'
            Section = 'Step 1 - Create sensitivity sub-labels'
            Summary = 'Create granular sub-labels beneath the parent taxonomy.'
            Status = 'Aligned'
            ActionIds = @('purview.labels.taxonomy')
            ConfigPaths = @('Labels[].SubLabels')
            Rationale = ''
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step1')
        }
        @{
            Id = 'DS-1.3'
            Section = 'Step 1 - Order labels by priority'
            Summary = 'Order labels so the most restrictive protection has the highest priority.'
            Status = 'Aligned'
            ActionIds = @('purview.labels.priority')
            ConfigPaths = @('Labels')
            Rationale = ''
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step1')
        }
        @{
            Id = 'DS-1.4'
            Section = 'Step 1 - Publish labels and set a default'
            Summary = 'Publish sensitivity labels and configure default labels.'
            Status = 'Aligned'
            ActionIds = @('purview.labels.publish')
            ConfigPaths = @('LabelPolicy')
            Rationale = ''
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step1')
        }
        @{
            Id = 'DS-1.5'
            Section = 'Step 1 - Enable labels for SharePoint and OneDrive'
            Summary = 'Enable sensitivity-label support for SharePoint and OneDrive files.'
            Status = 'Aligned'
            ActionIds = @('purview.tenant.spo-labels')
            ConfigPaths = @('TenantSettings.EnableAIPIntegrationInSPO')
            Rationale = ''
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step1')
        }
        @{
            Id = 'DS-1.6'
            Section = 'Step 1 - Exchange DLP'
            Summary = 'Create a separate Exchange DLP policy that blocks external sharing of labeled content.'
            Status = 'Conditional'
            ActionIds = @('purview.dlp.exchange')
            ConfigPaths = @('DlpPolicies[Workload=Exchange]')
            Rationale = 'The toolkit uses simulation as the safe default instead of immediate enforcement.'
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step1')
        }
        @{
            Id = 'DS-1.7'
            Section = 'Step 1 - SharePoint and OneDrive DLP'
            Summary = 'Create DLP coverage for SharePoint and OneDrive external sharing.'
            Status = 'Conditional'
            ActionIds = @('purview.dlp.sharepoint-onedrive')
            ConfigPaths = @('DlpPolicies[Workload=SharePointOneDrive]')
            Rationale = 'The toolkit uses simulation as the safe default instead of immediate enforcement.'
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step1')
        }
        @{
            Id = 'DS-1.8'
            Section = 'Step 1 - Enable audit logging'
            Summary = 'Confirm or enable audit logging for user and administrator activity.'
            Status = 'Aligned'
            ActionIds = @('purview.tenant.audit-standard')
            ConfigPaths = @('TenantSettings.EnableUnifiedAuditLog')
            Rationale = ''
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step1')
        }
        @{
            Id = 'DS-2.1'
            Section = 'Step 2 - Custom sensitive information types'
            Summary = 'Create organization-specific sensitive information types.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Custom sensitive information type authoring requires organization-specific patterns and review.'
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2')
        }
        @{
            Id = 'DS-2.2'
            Section = 'Step 2 - Client-side auto-labeling'
            Summary = 'Recommend labels in Office apps by using custom sensitive information types.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Auto-labeling is intentionally left for organization-specific false-positive review.'
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2')
        }
        @{
            Id = 'DS-2.3'
            Section = 'Step 2 - Endpoint DLP'
            Summary = 'Protect sensitive data from device copy, print, and upload actions.'
            Status = 'Conditional'
            ActionIds = @('purview.dlp.endpoint')
            ConfigPaths = @('DlpPolicies[Workload=Endpoint]')
            Rationale = 'Endpoint DLP is configured but requires E5 or Microsoft Purview Suite entitlement.'
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2')
        }
        @{
            Id = 'DS-2.4'
            Section = 'Step 2 - Teams DLP'
            Summary = 'Block external sharing of sensitive content in Teams chats and channels.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'The shipped Purview configuration does not define a Teams chat and channel DLP workload.'
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2')
        }
        @{
            Id = 'DS-2.5'
            Section = 'Step 2 - Email DLP and label inheritance'
            Summary = 'Use a separate Exchange DLP policy and inherit labels from email attachments.'
            Status = 'Aligned'
            ActionIds = @('purview.dlp.exchange', 'purview.labels.attachment-inheritance')
            ConfigPaths = @('DlpPolicies[Workload=Exchange]', 'LabelPolicy.AttachmentAction')
            Rationale = ''
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step2')
        }
        @{
            Id = 'DS-3.1'
            Section = 'Step 3 - Encrypt labeled content'
            Summary = 'Apply encryption to high-sensitivity labeled content.'
            Status = 'Aligned'
            ActionIds = @('purview.labels.encryption')
            ConfigPaths = @('Labels[].Encrypt', 'EncryptionRightsDefinitions')
            Rationale = ''
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step3')
        }
        @{
            Id = 'DS-3.2'
            Section = 'Step 3 - Service-side auto-labeling'
            Summary = 'Auto-label existing files and in-transit email by using service-side policies.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Service-side auto-labeling is intentionally outside the shipped configuration.'
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step3')
        }
        @{
            Id = 'DS-3.3'
            Section = 'Step 3 - Insider Risk Management analytics'
            Summary = 'Use Insider Risk Management analytics to identify risk patterns.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Insider Risk Management analytics requires separate governance and role review.'
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step3')
        }
        @{
            Id = 'DS-3.4'
            Section = 'Step 3 - Adaptive Protection in DLP'
            Summary = 'Adjust DLP actions by Insider Risk Management risk level.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Risk-based enforcement is outside the toolkit safe default and needs separate approval design.'
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step3')
        }
        @{
            Id = 'DS-3.5'
            Section = 'Step 3 - Adaptive Protection with Conditional Access'
            Summary = 'Restrict SharePoint and OneDrive access for elevated-risk users.'
            Status = 'NotApplicable'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Conditional Access enforcement belongs to the Entra product boundary, not the Purview deployment module.'
            ReferenceUris = @('https://learn.microsoft.com/purview/deploymentmodels/depmod-lightweight-dlp-step3')
        }
    )
}
