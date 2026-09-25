@{
    ProductName = 'Microsoft Intune Best Practice Toolkit'
    ProductVersion = '0.3.0'
    ManagedByTag = '[Managed by SMBTool Intune Toolkit]'

    # Source baseline: Device Management Deployment Guide for Small Business
    # (Device Enrollment Best Practices, Business Premium / Intune Plan 1,
    # 7 March 2026). Keys are toolkit-internal identifiers and are not Microsoft
    # recommendation identifiers. GuideTask maps back to the source baseline so
    # evidence can be traced to the guide.
    BestPracticeItems = @(
        @{
            Key = 'windows-auto-enrollment'
            Name = 'Enable automatic MDM enrollment for Windows devices'
            Module = 'Setup-EnrollmentPrerequisites'
            LicenseCapability = 'intune'
            Risk = 'Standard'
            RequiresHighRiskGate = $false
            Priority = 1
            GuideTask = 1
        }
        @{
            Key = 'apple-push-certificate'
            Name = 'Apple MDM push certificate for iOS/iPadOS and macOS'
            Module = 'Setup-EnrollmentPrerequisites'
            LicenseCapability = 'intune'
            Risk = 'Standard'
            RequiresHighRiskGate = $false
            Priority = 1
            GuideTask = 2
        }
        @{
            Key = 'managed-google-play'
            Name = 'Connect the tenant to a managed Google Play account'
            Module = 'Setup-EnrollmentPrerequisites'
            LicenseCapability = 'intune'
            Risk = 'Standard'
            RequiresHighRiskGate = $false
            Priority = 1
            GuideTask = 3
        }
        @{
            Key = 'default-compliance-settings'
            Name = 'Treat devices with no compliance policy as not compliant'
            Module = 'Setup-ComplianceBaseline'
            LicenseCapability = 'intune'
            Risk = 'High'
            RequiresHighRiskGate = $true
            Priority = 1
            GuideTask = 4
        }
        @{
            Key = 'enrollment-restrictions'
            Name = 'Restrict enrollment for unused platforms and personal devices'
            Module = 'Setup-EnrollmentRestrictions'
            LicenseCapability = 'intune'
            Risk = 'High'
            RequiresHighRiskGate = $true
            Priority = 2
            GuideTask = 5
        }
        @{
            Key = 'app-protection-policies'
            Name = 'Deploy app protection policies for core Microsoft apps'
            Module = 'Setup-AppProtectionPolicies'
            LicenseCapability = 'intune'
            Risk = 'Standard'
            RequiresHighRiskGate = $false
            Priority = 2
            GuideTask = 6
        }
        @{
            Key = 'device-compliance-policies'
            Name = 'Create per-platform device compliance policies'
            Module = 'Setup-DeviceCompliancePolicies'
            LicenseCapability = 'intune'
            # High risk despite the source guide presenting it as routine.
            # Creating a compliance policy can mark existing devices
            # noncompliant, and if the customer already operates Conditional
            # Access requiring a compliant device (whether or not this toolkit
            # created it), those users lose access immediately.
            Risk = 'High'
            RequiresHighRiskGate = $true
            Priority = 2
            GuideTask = 7
        }
        @{
            Key = 'm365-apps-deployment'
            Name = 'Deploy Microsoft 365 Apps to managed Windows devices'
            Module = 'Setup-AppDeployment'
            LicenseCapability = 'intune'
            Risk = 'Standard'
            RequiresHighRiskGate = $false
            Priority = 2
            GuideTask = 8
        }
        @{
            Key = 'enterprise-state-roaming'
            Name = 'Configure Enterprise State Roaming through Windows Backup for Organizations'
            Module = 'Setup-EnterpriseStateRoaming'
            LicenseCapability = 'conditionalAccess'
            Risk = 'Standard'
            RequiresHighRiskGate = $false
            Priority = 2
            GuideTask = 9
        }
        @{
            Key = 'device-conditional-access'
            Name = 'Require MFA and a compliant device for Intune enrollment'
            Module = 'Setup-DeviceConditionalAccess'
            LicenseCapability = 'conditionalAccess'
            Risk = 'High'
            RequiresHighRiskGate = $true
            Priority = 3
            GuideTask = 10
        }
    )

    # These identifiers are configuration candidates, not an assertion that a
    # tenant has the capability, and not an assertion that the names are
    # current. Verify SKU and service-plan metadata before enabling apply
    # behavior, and update this data file as Microsoft changes catalog names.
    LicenseCapabilities = @{
        intune = @{
            SkuPartNumbers = @('SPB', 'INTUNE_A', 'EMS', 'EMSPREMIUM')
            ServicePlanNames = @('INTUNE_A')
        }
        conditionalAccess = @{
            SkuPartNumbers = @('SPB', 'AAD_PREMIUM', 'EMS', 'EMSPREMIUM')
            ServicePlanNames = @('AAD_PREMIUM', 'AAD_PREMIUM_P2')
        }
    }

    # Graph scopes are the least-privilege set the toolkit consents to. Read
    # scopes cover preflight and readback; the ReadWrite scopes are each
    # required by an implemented write path with deterministic fixture
    # coverage. Refresh pilot evidence after changing a write contract. Do not
    # place secrets or tokens here.
    Api = @{
        GraphBaseUri = 'https://graph.microsoft.com/v1.0'
        # Some device management resources (officeSuiteApp, managed app
        # protection) are only projected on the beta endpoint. Writes that need
        # it read this value rather than hard-coding the host.
        GraphBetaBaseUri = 'https://graph.microsoft.com/beta'
        GraphScopes = @(
            'User.Read'
            'LicenseAssignment.Read.All'
            'DeviceManagementConfiguration.Read.All'
            'DeviceManagementApps.Read.All'
            'DeviceManagementServiceConfig.Read.All'
            # Write scopes, each tied to an implemented apply path:
            'DeviceManagementApps.ReadWrite.All'          # M365 Apps, app protection
            'DeviceManagementServiceConfig.ReadWrite.All' # enrollment restrictions
            'DeviceManagementConfiguration.ReadWrite.All' # default compliance, device compliance policies
            'Policy.Read.All'                            # read Conditional Access policies
            'Policy.ReadWrite.ConditionalAccess'          # device-based Conditional Access
            'Application.ReadWrite.All'                   # ensure the Intune enrollment service principal exists
        )
        RequiredCommands = @(
            'Connect-MgGraph'
            'Get-MgDeviceManagement'
            'Update-MgDeviceManagement'
            'Invoke-MgGraphRequest'
            'Get-MgContext'
        )
    }

    # The source guide instructs the reader to assign policies to all users.
    # The toolkit deliberately diverges and defaults to a pilot group, because
    # enrollment restrictions, compliance enforcement, and Conditional Access
    # can deny access to every user in the tenant on a first run. Tenant-wide
    # assignment is an explicit operator opt-in.
    Assignment = @{
        DefaultScope = 'PilotGroup'
        RequirePilotGroupForHighRisk = $true
        # Named for what it actually controls: whether a high-risk run may go
        # tenant-wide. It is not an absolute veto and must not be named like
        # one, because a config author would otherwise rely on it as a hard
        # stop that the command line can lift.
        AllowTenantWideAssignmentForHighRisk = $false
    }

    # Candidate payloads normalized from the contributor implementation.
    # Runtime loading verifies file hashes and rejects export-only metadata.
    # Every entry remains blocked for apply until its API, permission, pilot,
    # rollback, and recovery gates are complete.
    PolicyCatalog = @{
        ManifestPath = 'Config/PolicyCatalog/catalog.psd1'
        RequiredEntryCount = 19
    }

    # These are explicit where Microsoft does not expose a stable,
    # least-privilege, unattended path suitable for automation.
    Preflight = @{
        ManagedGooglePlayDisposition = 'GuidedOnly'
        WindowsAutoEnrollmentDisposition = 'GuidedOnly'
        EnterpriseStateRoamingDisposition = 'GuidedOnly'
        EmergencyAccessDisposition = 'GuidedOnly'
    }

    # Renew before expiry. Microsoft documents a 365-day certificate lifetime
    # and a 30-day post-expiry grace period; the toolkit uses the same interval
    # as an earlier warning window rather than waiting for management disruption.
    ApplePushCertificate = @{
        RenewalWarningDays = 30
    }

    # Conditional Access is the highest blast-radius item in the baseline.
    # A policy requiring a compliant device, applied before devices are enrolled
    # and evaluated, denies access and can lock administrators out.
    ConditionalAccess = @{
        DefaultState = 'enabledForReportingButNotEnforced'
        RequireBreakGlassExclusions = $true
        EnrollmentAppId = 'd4ebce55-015a-49b5-a083-c84d1797ae8c'
        DisplayName = 'Require MFA and compliant device for Intune enrollment'
    }

    Report = @{
        OutputDirectory = '.\Reports'
        JsonLogFileName = 'intune-run-log.json'
        HtmlReportFileName = 'intune-run-report.html'
    }

    # Microsoft 365 Apps for Windows (guide task 8). The payload matches the
    # source guide: Monthly Enterprise Channel and Open Document Format as the
    # default. Values live here so an operator can retune the deployment
    # without editing module code.
    AppDeployment = @{
        DisplayName = 'Microsoft 365 Apps for Windows'
        Publisher = 'Microsoft'
        Architecture = 'x64'
        UpdateChannel = 'monthlyEnterprise'
        DefaultFileFormat = 'officeOpenDocumentFormat'
        UseSharedComputerActivation = $false
        Locales = @('en-us')
        ProductIds = @('o365ProPlusRetail')
        ExcludedApps = @('groove', 'lync')
        AssignmentIntent = 'required'
    }

    # Tenant-wide default compliance behavior (guide task 4). secureByDefault
    # treats a device with no targeted compliance policy as noncompliant. This
    # is High risk: it becomes an access denial once compliant-device
    # Conditional Access is enforced, so the write is gated behind
    # IncludeHighRisk + EnableComplianceEnforcement.
    DefaultCompliance = @{
        CheckinThresholdDays = 30
    }

    # App protection policies for core Microsoft apps (guide task 6), Level 1
    # basic data protection. Standard risk: MAM protects app data and denies no
    # device access. Settings mirror the source guide's L1 baseline. Apps are
    # the current core Microsoft mobile app identifiers.
    AppProtection = @{
        Ios = @{
            OdataType = '#microsoft.graph.iosManagedAppProtection'
            DisplayName = 'iOS - App Protection Baseline (L1)'
            AppIdentifierType = '#microsoft.graph.iosMobileAppIdentifier'
            AppIdentifierKey = 'bundleId'
            Apps = @(
                'com.microsoft.Office.Outlook', 'com.microsoft.skype.teams',
                'com.microsoft.Office.Word', 'com.microsoft.Office.Excel',
                'com.microsoft.Office.Powerpoint', 'com.microsoft.skydrive',
                'com.microsoft.onenote', 'com.microsoft.msedge'
            )
            Settings = @{
                periodOfflineBeforeAccessCheck          = 'PT12H'
                periodOnlineBeforeAccessCheck           = 'PT30M'
                allowedInboundDataTransferSources       = 'allApps'
                allowedOutboundDataTransferDestinations = 'managedApps'
                organizationalCredentialsRequired       = $false
                allowedOutboundClipboardSharingLevel    = 'managedAppsWithPasteIn'
                dataBackupBlocked                       = $true
                deviceComplianceRequired                = $false
                managedBrowserToOpenLinksRequired       = $false
                saveAsBlocked                           = $true
                periodOfflineBeforeWipeIsEnforced       = 'P90D'
                pinRequired                             = $true
                maximumPinRetries                       = 5
                simplePinBlocked                        = $false
                minimumPinLength                        = 4
                pinCharacterSet                         = 'numeric'
                allowedDataStorageLocations             = @('oneDriveForBusiness', 'sharePoint')
                contactSyncBlocked                      = $false
                printBlocked                            = $false
                fingerprintBlocked                      = $false
                disableAppPinIfDevicePinIsSet           = $true
                faceIdBlocked                           = $false
                appDataEncryptionType                   = 'whenDeviceLocked'
            }
        }
        Android = @{
            OdataType = '#microsoft.graph.androidManagedAppProtection'
            DisplayName = 'Android - App Protection Baseline (L1)'
            AppIdentifierType = '#microsoft.graph.androidMobileAppIdentifier'
            AppIdentifierKey = 'packageId'
            Apps = @(
                'com.microsoft.office.outlook', 'com.microsoft.teams',
                'com.microsoft.office.word', 'com.microsoft.office.excel',
                'com.microsoft.office.powerpoint', 'com.microsoft.skydrive',
                'com.microsoft.office.onenote', 'com.microsoft.emmx'
            )
            Settings = @{
                periodOfflineBeforeAccessCheck                  = 'PT12H'
                periodOnlineBeforeAccessCheck                   = 'PT30M'
                allowedInboundDataTransferSources               = 'allApps'
                allowedOutboundDataTransferDestinations         = 'managedApps'
                organizationalCredentialsRequired               = $false
                allowedOutboundClipboardSharingLevel            = 'managedAppsWithPasteIn'
                dataBackupBlocked                               = $true
                deviceComplianceRequired                        = $false
                managedBrowserToOpenLinksRequired               = $false
                saveAsBlocked                                   = $true
                periodOfflineBeforeWipeIsEnforced               = 'P90D'
                pinRequired                                     = $true
                maximumPinRetries                               = 5
                simplePinBlocked                                = $false
                minimumPinLength                                = 4
                pinCharacterSet                                 = 'numeric'
                allowedDataStorageLocations                     = @('oneDriveForBusiness', 'sharePoint')
                contactSyncBlocked                              = $false
                printBlocked                                    = $false
                fingerprintBlocked                              = $false
                disableAppEncryptionIfDeviceEncryptionIsEnabled = $false
                encryptAppData                                  = $true
                screenCaptureBlocked                            = $false
            }
        }
    }

    # Per-platform device compliance policies (guide task 7). High risk:
    # creating a compliance policy can mark existing devices noncompliant, and
    # if compliant-device Conditional Access is enforced those users lose
    # access, so the write is gated behind IncludeHighRisk (the orchestrator
    # records the item in Context.WriteBlockedItemKeys when it is absent). The
    # Windows payload includes Secure Boot and code integrity per the source
    # guide; every payload carries its own scheduledActionsForRule.
    DeviceCompliance = @{
        PayloadDirectory = 'Config/CompliancePayloads'
    }

    # Device platform enrollment restrictions (guide task 5). High risk: a
    # misconfigured restriction can block the enrollment the rest of the
    # baseline depends on, so the write is gated behind IncludeHighRisk +
    # EnableEnrollmentRestrictions. Safe by default: the shipped restrictions
    # block only personally owned enrollment on used platforms (corporate
    # enrollment continues to work). Set PlatformBlocked = $true to block a
    # platform outright. Assignment follows the orchestrator's verified
    # PilotGroup or explicitly approved TenantWide scope.
    EnrollmentRestrictions = @{
        Restrictions = @(
            @{
                DisplayName = 'Block personal iOS/iPadOS enrollment'
                PlatformType = 'ios'
                PlatformBlocked = $false
                PersonalDeviceEnrollmentBlocked = $true
            }
            @{
                DisplayName = 'Block personal Android enrollment'
                PlatformType = 'android'
                PlatformBlocked = $false
                PersonalDeviceEnrollmentBlocked = $true
            }
        )
    }
}
