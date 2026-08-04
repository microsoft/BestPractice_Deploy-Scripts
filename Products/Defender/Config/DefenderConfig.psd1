@{
    ProductName = 'Microsoft Defender Best Practice Toolkit'
    ProductVersion = '0.1.0'
    ManagedByTag = '[Managed by SMBTool Defender Toolkit]'

    # Keep policy names, application-internal keys, and risk classifications in
    # configuration. Keys are not Microsoft recommendation identifiers.
    BestPracticeItems = @(
        @{
            Key = 'mdo-auto-forward'
            Name = 'Block outbound auto-forwarding'
            Module = 'Setup-MdoEopBaseline'
            LicenseCapability = 'mdo'
            Risk = 'High'
            RequiresHighRiskGate = $true
        }
        @{
            Key = 'mdo-safe-attachments'
            Name = 'Enable Safe Attachments for SPO, OneDrive, and Teams'
            Module = 'Setup-MdoEopBaseline'
            LicenseCapability = 'mdo'
            Risk = 'Standard'
            RequiresHighRiskGate = $false
        }
        @{
            Key = 'mde-asr-audit'
            Name = 'Deploy ASR rules in audit mode'
            Module = 'Setup-DefenderForBusiness'
            LicenseCapability = 'mde'
            Risk = 'Standard'
            RequiresHighRiskGate = $false
        }
    )

    # These identifiers are configuration candidates, not an assertion that a
    # tenant has the capability. Verify current SKU/service-plan metadata
    # during F6 implementation and update this data file as Microsoft changes
    # catalog names.
    LicenseCapabilities = @{
        mdo = @{
            SkuPartNumbers = @('ATP_ENTERPRISE', 'THREAT_INTELLIGENCE')
            ServicePlanNames = @('ATP_ENTERPRISE', 'THREAT_INTELLIGENCE')
        }
        mde = @{
            SkuPartNumbers = @('WIN10_ENT_E5', 'MDE_SENSE')
            ServicePlanNames = @('MDE_SENSE')
        }
        mdca = @{
            SkuPartNumbers = @('ADALLOM_S_STANDALONE')
            ServicePlanNames = @('ADALLOM_S_STANDALONE')
        }
    }

    # Placeholder for Graph resource IDs, recipient IDs, policy templates, and
    # other tenant-specific values. Do not place secrets or tokens here.
    Api = @{
        GraphBaseUri = 'https://graph.microsoft.com/v1.0'
        GraphScopes = @(
            'Organization.Read.All'
        )
        RequiredCommands = @(
            'Connect-MgGraph'
            'Invoke-MgGraphRequest'
            'Get-MgContext'
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
