@{
    SchemaVersion = '1.1'
    Role = 'Primary'
    Guide = @{
        Id = 'MS-DATA-SECURITY-SMB-FINALCLEAN'
        Title = 'Data Security Deployment Guide for Small Business'
        Edition = 'FinalClean'
        RevisionDate = '2026-04-08'
        SourceModifiedDate = '2026-06-11'
        VerifiedDate = '2026-09-10'
        Publisher = 'Microsoft Security'
        SourceClassification = 'ProductOwnerSupplied'
        SourceFileName = 'Data Security Deployment Guide for Small Business_FinalClean.pptx'
        Owner = 'SMB Best Practice Tool maintainers'
        Levels = @(
            @{
                Id = 'Good'
                Title = 'Good'
                Summary = 'Enable audit logging, deploy the baseline label experience, and protect Exchange, SharePoint, and OneDrive.'
                Inherits = @()
            }
            @{
                Id = 'Better'
                Title = 'Better'
                Summary = 'Add an Exchange mailbox retention policy, expanding to other workloads as needed.'
                Inherits = @('Good')
            }
            @{
                Id = 'Best'
                Title = 'Best'
                Summary = 'Add Endpoint, Teams, and Copilot DLP, automated classification, encryption, custom SITs, and DSPM.'
                Inherits = @('Good', 'Better')
            }
        )
    }
    Controls = @(
        @{
            Id = 'DS-SMB-G-01'
            Level = 'Good'
            Section = 'Audit logging'
            SourceSection = 'Enable audit log'
            Summary = 'Enable or confirm audit logging for user and administrator activity.'
            Status = 'Aligned'
            ActionIds = @('purview.tenant.audit-standard')
            ConfigPaths = @('TenantSettings.EnableUnifiedAuditLog')
            Rationale = ''
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-G-02'
            Level = 'Good'
            Section = 'Sensitivity label hierarchy'
            SourceSection = 'Recommended label taxonomy'
            Summary = 'Define the Public, General, Confidential, and Highly Confidential label hierarchy.'
            Status = 'Conditional'
            ActionIds = @('purview.labels.taxonomy')
            ConfigPaths = @('Labels', 'Labels[].SubLabels')
            Rationale = 'The toolkit implements the four-level hierarchy but consolidates or omits some sublabels shown in the guide taxonomy.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-G-03'
            Level = 'Good'
            Section = 'Sensitivity label hierarchy'
            SourceSection = 'Order labels by priority'
            Summary = 'Order the sensitivity label hierarchy from least to most restrictive.'
            Status = 'Aligned'
            ActionIds = @('purview.labels.priority')
            ConfigPaths = @('Labels')
            Rationale = ''
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-G-04'
            Level = 'Good'
            Section = 'Sensitivity label policy settings'
            SourceSection = 'Publish sensitivity labels'
            Summary = 'Publish the configured sensitivity labels and defaults so the hierarchy is available to users.'
            Status = 'Aligned'
            ActionIds = @('purview.labels.publish')
            ConfigPaths = @('LabelPolicy')
            Rationale = ''
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-G-05'
            Level = 'Good'
            Section = 'Sensitivity labels for containers'
            SourceSection = 'Enable sensitivity labels for containers and synchronize labels'
            Summary = 'Enable sensitivity labels for Microsoft 365 groups, Teams, and SharePoint sites and synchronize them with Microsoft Entra ID.'
            Status = 'Aligned'
            ActionIds = @(
                'purview.tenant.container-directory-setting'
                'purview.labels.container-scope'
            )
            ConfigPaths = @(
                'TenantSettings'
                'Labels[].ContentType'
            )
            Rationale = ''
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-G-06'
            Level = 'Good'
            Section = 'Sensitivity labels for SharePoint and OneDrive'
            SourceSection = 'Enable sensitive labels for Office files SharePoint and OneDrive'
            Summary = 'Enable sensitivity-label processing for Office files stored in SharePoint and OneDrive.'
            Status = 'Aligned'
            ActionIds = @('purview.tenant.spo-labels')
            ConfigPaths = @('TenantSettings.EnableAIPIntegrationInSPO')
            Rationale = ''
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-G-07'
            Level = 'Good'
            Section = 'Sensitivity label content marking'
            SourceSection = 'Create sensitivity labels: Modern label scheme'
            Summary = 'Optionally add content marking while configuring sensitivity labels.'
            Status = 'Conditional'
            ActionIds = @('purview.labels.content-marking')
            ConfigPaths = @('EnableContentMarking', 'Labels[].ContentMark')
            Rationale = 'The guide presents content marking as optional, and the shipped global content-marking gate is disabled.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-G-08'
            Level = 'Good'
            Section = 'Exchange DLP'
            SourceSection = 'Create and deploy DLP policies for Exchange'
            Summary = 'Protect Confidential, All Employees content from external Exchange recipients.'
            Status = 'Conditional'
            ActionIds = @('purview.dlp.exchange')
            ConfigPaths = @('DlpPolicies[Workload=Exchange]')
            Rationale = 'The toolkit starts the Exchange DLP policy in simulation instead of immediate enforcement.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-G-09'
            Level = 'Good'
            Section = 'SharePoint and OneDrive DLP'
            SourceSection = 'Create and deploy DLP policies for SharePoint and OneDrive'
            Summary = 'Protect Confidential, All Employees content from external sharing in SharePoint and OneDrive.'
            Status = 'Conditional'
            ActionIds = @('purview.dlp.sharepoint-onedrive')
            ConfigPaths = @('DlpPolicies[Workload=SharePointOneDrive]')
            Rationale = 'The toolkit starts the SharePoint and OneDrive DLP policy in simulation instead of immediate enforcement.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-B-01'
            Level = 'Better'
            Section = 'Exchange retention'
            SourceSection = 'Create a retention policy for Exchange Email box'
            Summary = 'Create a retention policy for Exchange mailboxes and expand it to other workloads as needed.'
            Status = 'Conditional'
            ActionIds = @('purview.retention.exchange')
            ConfigPaths = @('Retention')
            Rationale = 'The toolkit requires explicit -ApplyRetention opt-in and uses the configured seven-year policy rather than assuming the guide example fits every organization.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-01'
            Level = 'Best'
            Section = 'Endpoint DLP prerequisites'
            SourceSection = 'Enable Endpoint DLP for the policy to apply to devices'
            Summary = 'Enable Endpoint DLP settings and onboard supported Windows and macOS devices.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Device onboarding and tenant-wide Endpoint DLP prerequisite configuration are outside the Purview policy module.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-02'
            Level = 'Best'
            Section = 'Endpoint DLP policy'
            SourceSection = 'Create DLP policy for Devices'
            Summary = 'Restrict copy, print, browser upload, cloud sync, remote access, Bluetooth, and removable-media actions on sensitive files.'
            Status = 'Conditional'
            ActionIds = @('purview.dlp.endpoint')
            ConfigPaths = @('DlpPolicies[Workload=Endpoint]')
            Rationale = 'The toolkit uses audit-first endpoint restrictions and requires Purview Suite entitlement, device onboarding, and runtime readiness.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-03'
            Level = 'Best'
            Section = 'Teams DLP'
            SourceSection = 'Create DLP policy for Teams'
            Summary = 'Create a DLP policy for sensitive data shared in Teams chats and channel messages.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'The shipped Purview configuration does not define a Teams chat and channel DLP workload.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-04'
            Level = 'Best'
            Section = 'Copilot DLP'
            SourceSection = 'Create DLP policy for Copilot'
            Summary = 'Create separate Copilot DLP rules for sensitive prompt information and labeled content.'
            Status = 'Conditional'
            ActionIds = @('purview.ai.copilot-dlp')
            ConfigPaths = @('AIGovernance.DlpPolicies')
            Rationale = 'The toolkit blocks processing of configured highly confidential labels but does not create the guide''s separate sensitive-information-type prompt rule.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-05'
            Level = 'Best'
            Section = 'Client-side auto-labeling'
            SourceSection = 'Configure client-side auto-labeling'
            Summary = 'Configure Office apps to recommend sensitivity labels when custom sensitive information types match.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Client-side recommendation rules require organization-specific classifiers, tuning, and false-positive review.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-06'
            Level = 'Best'
            Section = 'Service-side auto-labeling'
            SourceSection = 'Extend auto-labeling to M365 services'
            Summary = 'Configure service-side auto-labeling for existing files in SharePoint and OneDrive.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Service-side auto-labeling requires separate classifier tuning, simulation, and rollout approval.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-07'
            Level = 'Best'
            Section = 'Sensitivity label encryption'
            SourceSection = 'Apply encryption to labeled content'
            Summary = 'Apply encryption and access controls to high-sensitivity labeled content.'
            Status = 'Aligned'
            ActionIds = @('purview.labels.encryption')
            ConfigPaths = @(
                'Labels[].Encrypt'
                'Labels[].ProtectionType'
                'EncryptionRightsDefinitions'
            )
            Rationale = ''
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-08'
            Level = 'Best'
            Section = 'Custom sensitive information types'
            SourceSection = 'Create custom sensitive info types'
            Summary = 'Create organization-specific sensitive information types from built-in types or new patterns.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Custom pattern authoring requires organization-specific samples, testing, and false-positive review.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-09'
            Level = 'Best'
            Section = 'Advanced classification'
            SourceSection = 'Out-of-the-box Built-in SITs vs. Custom SITs'
            Summary = 'Improve classification with custom keyword dictionaries.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Custom keyword dictionaries require organization-specific source data and validation.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-10'
            Level = 'Best'
            Section = 'Advanced classification'
            SourceSection = 'Out-of-the-box Built-in SITs vs. Custom SITs'
            Summary = 'Improve classification with exact data match.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Exact data match requires organization-specific schemas, data preparation, and secure upload.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-11'
            Level = 'Best'
            Section = 'Advanced classification'
            SourceSection = 'Out-of-the-box Built-in SITs vs. Custom SITs'
            Summary = 'Improve classification with document fingerprinting.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Document fingerprinting requires organization-specific templates and validation.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-12'
            Level = 'Best'
            Section = 'Advanced classification'
            SourceSection = 'Out-of-the-box Built-in SITs vs. Custom SITs'
            Summary = 'Improve classification with trainable classifiers.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Trainable classifiers require curated examples, evaluation, and governance outside the shipped baseline.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-13'
            Level = 'Best'
            Section = 'Data Security Posture Management'
            SourceSection = 'Get started with DSPM'
            Summary = 'Activate Data Security Posture Management and complete its initial setup.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'DSPM activation requires separate tenant permissions, product setup, and operational ownership.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-14'
            Level = 'Best'
            Section = 'Data Security Posture Management'
            SourceSection = 'Know your data estate'
            Summary = 'Review data-security posture objectives, snapshots, and trends.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Posture review is an operator assessment workflow rather than a deterministic tenant configuration action.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-15'
            Level = 'Best'
            Section = 'Data Security Posture Management'
            SourceSection = 'Run Data risk assessment'
            Summary = 'Run and review data risk assessments for oversharing in SharePoint, OneDrive, and Fabric.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Risk assessment review requires live tenant evidence and remains outside the offline deployment configuration.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-16'
            Level = 'Best'
            Section = 'Data Security Posture Management'
            SourceSection = 'Configure policies based on recommended actions'
            Summary = 'Review DSPM recommendations and create the appropriate out-of-box policies.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Recommendation-driven policy creation needs human review, explicit scope, and separate promotion controls.'
            ReferenceUris = @()
        }
        @{
            Id = 'DS-SMB-X-17'
            Level = 'Best'
            Section = 'Data Security Posture Management'
            SourceSection = 'Review policy Impact with Out-of-the-box Posture Report'
            Summary = 'Review posture reports to measure how deployed policies affect data protection.'
            Status = 'NotImplemented'
            ActionIds = @()
            ConfigPaths = @()
            Rationale = 'Posture reporting depends on live tenant telemetry and is not produced by the offline deployment plan.'
            ReferenceUris = @()
        }
    )
}
