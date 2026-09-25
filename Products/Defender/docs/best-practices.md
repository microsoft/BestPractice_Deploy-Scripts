---
title: Defender best-practice coverage
layout: default
nav_order: 6
parent: Microsoft Defender
permalink: /defender/best-practices/
---

# Defender best-practice coverage

This page is a **coverage and readiness matrix**, not a list of currently
deployed controls. Defender is available at its approved release scope.
Default execution is read-only, MDO/EOP writes remain `GuidedOnly`, and the ASR
Audit policy is the only managed configuration path with approved pilot
evidence. The matrix records which practices can be assessed, guided, or
configured within those boundaries.

## Current boundary

The default path does not create, update, adopt, publish, enforce, or roll back
Defender workload policies. `-WhatIf` is the supported starting point. The ASR
Audit path requires the explicit managed-configuration switches and an
approved pilot security group. A practice listed below is not evidence that
its operation is available.

## Pilot capability status

The 2026-08-25 delegated `-WhatIf` run initially verified only the Microsoft
Graph tenant identity capability. Subsequent approved staged-tenant work
validated bounded outbound-forwarding configuration and recovery, plus ASR
audit-policy configuration and assignment. Safe Attachments passed tenant-free
configuration validation and was already compliant in the observed tenant, so
no mutation was manufactured. MDE and MDCA API capabilities were unavailable
and skipped; guided portal evidence remains possible where the operator has
access. Production use remains `GuidedOnly` unless the operator explicitly
selects a documented managed configuration path.

| Recommendation | Required capability | Current status |
| --- | --- | --- |
| Block outbound auto-forwarding | Exchange Online / EOP | GuidedOnly in production / Implemented and pilot-validated |
| Enable Safe Attachments for SPO, OneDrive, and Teams | Exchange Online / EOP | GuidedOnly in production / Implemented with tenant-free validation; pilot pending |
| Configure `SMBTool-Quarantine-LimitedAccess` without assignments | Exchange Online / Defender for Office 365 | GuidedOnly in production / Implemented with tenant-free validation and non-production WhatIf; apply pending |
| Deploy ASR rules in audit mode | Microsoft Intune | Default read-only; managed configuration and assignment pilot-validated; recovery path validated deterministically |

## Practices in scope

The coverage review identifies 25 practices for assessment, guided deployment,
or bounded configuration. Inclusion means the toolkit can safely evaluate or
guide the practice; it does not mean the setting has been applied. The current
treatment column distinguishes implemented configuration paths from assessment
and guidance that still require operator action.

| Best practice | High-level configuration summary | Current toolkit treatment |
| --- | --- | --- |
| Verify audit readiness | Confirm that security activity is being recorded so investigations and reports have the evidence they need. | Assessment and guided remediation |
| Verify required Defender roles | Confirm that the deployment operator has the security roles needed for the selected work without granting broad access automatically. | Readiness assessment |
| Verify emergency-access safety | Confirm that an emergency administrator account can preserve tenant access before any future enforcement change. | Read-only safety assessment |
| Enable Standard preset security policies | Apply Microsoft's recommended baseline email protections to the approved users or pilot group. | GuidedOnly pending complete pilot evidence |
| Block outbound automatic forwarding | Prevent mailboxes from automatically forwarding company email to external recipients. | Implemented configuration path; production remains GuidedOnly |
| Enable Safe Attachments for SharePoint, OneDrive, and Teams | Scan shared files for malicious content across Microsoft 365 collaboration services. | Implemented configuration path; production remains GuidedOnly |
| Block executable email attachments | Prevent commonly abused executable file types from being delivered through email. | GuidedOnly; high-impact approval required |
| Apply recommended quarantine settings | Configure how suspicious messages are held, released, and reported to users and administrators. | GuidedOnly pending approved desired state |
| Enable Teams protection | Turn on available protections that detect and remove malicious links or messages in Teams. | Assessment and guided configuration |
| Configure email investigation and remediation | Review or configure how Defender investigates email threats and whether remediation requires approval. | GuidedOnly; remediation mode requires approval |
| Assess Defender for Business readiness | Confirm licensing, device onboarding, and baseline protection status before endpoint configuration. | Assessment and guided setup |
| Validate Defender and Intune integration | Confirm that Defender device risk can be shared with Intune for compliance decisions. | Assessment and guided configuration |
| Apply malware and firewall defaults | Configure Microsoft's recommended antivirus and Windows Firewall baseline for managed devices. | Candidate configuration; pilot evidence required |
| Validate Automatic Attack Disruption | Confirm that Defender can automatically contain supported attacks and that required devices are onboarded. | Assessment and guided setup |
| Validate endpoint investigation and remediation | Confirm that automated endpoint investigations are available and configured for the intended response model. | Assessment and guided setup |
| Configure Defender notification recipients | Route endpoint security alerts to the approved operational contacts. | GuidedOnly pending supported configuration evidence |
| Deploy ASR rules in audit mode | Apply recommended attack surface reduction rules in observation mode so impact can be reviewed before any blocking. | Implemented and pilot-validated configuration path |
| Configure endpoint attack notifications | Route advanced endpoint attack notifications to the approved responders where the tenant supports them. | GuidedOnly |
| Validate Defender for Endpoint and Defender for Cloud Apps integration | Confirm that endpoint activity contributes to cloud application discovery and risk visibility. | GuidedOnly |
| Create Cloud Discovery template policies | Use built-in policy templates to identify risky or unexpected cloud application use after discovery data is available. | GuidedOnly; discovery data required |
| Validate the default anomaly policy | Confirm that unusual cloud activity detection is enabled and retains appropriate Microsoft defaults. | Assessment and guided configuration |
| Enable App Governance | Turn on visibility and protection for applications that access Microsoft 365 data. | GuidedOnly |
| Enable predefined app policy templates | Use Microsoft's predefined policies to identify risky application behavior without creating custom rules. | GuidedOnly |
| Enable threat-detection policy templates | Use Microsoft templates to detect suspicious activity across connected cloud applications. | GuidedOnly |
| Enable user enrichment | Associate discovered cloud activity with known users when identity mapping can be resolved safely. | GuidedOnly; skipped when identity is ambiguous |

For each practice, the operator must use the endpoint validation register and
permission matrix rather than inferring support from a product name or license
SKU. No practice should be described as applied until the implementation
contract and approved pilot evidence exist.

## Practices intentionally deferred

The approved low-touch plan explicitly identifies the following 33 practices
as outside its apply scope. The earlier category summary did not retain enough
source data to support its aggregate count, so this table uses only traceable
practices from the plan. ASR appears here only for promotion to block mode; its
audit-mode configuration is implemented separately.

Download Microsoft's [Best Practice Security Deployment Guides for
SMB](https://aka.ms/Security_SMBDeploymentGuides). The mappings below were
verified against these files from the package downloaded on 2026-08-28:

- **Email guide:** `Email & App + Collaboration Protection Best Practice
  Deployment_Final030926.pdf`
- **Device guide:** `Device Security Best Practice
  Deployment_Final030926.pdf`
- **SaaS guide:** `SaaS Security Best Practice
  Deployment_Final030926.pdf`

| Best practice outside apply scope | Why it remains outside scope | Microsoft guide section |
| --- | --- | --- |
| Configure SPF | Requires provider-specific DNS access and design. | Email guide, pages 10-11, "Configure email authentication" |
| Configure DKIM | Requires provider-specific DNS access and design. | Email guide, pages 10-11, "Configure email authentication" |
| Configure DMARC | Requires provider-specific DNS access and staged enforcement decisions. | Email guide, pages 10-11, "Configure email authentication" |
| Review built-in alert policies | Review activity, not a one-time configuration baseline. | Email guide, pages 21-24, "Alert Policies" |
| Use Configuration Analyzer | Assessment and review activity, not a configuration deliverable. | Email guide, pages 28-29, "Configuration Analyzer" |
| Configure skip listing for a third-party email service | Requires the customer's mail-routing and third-party filtering architecture. | Email guide, page 41, "Advanced Email and Apps Protection Checklist" |
| Customize anti-phishing impersonation protection | Requires customer-selected users and partner or supplier domains. | Email guide, page 41, "Advanced Email and Apps Protection Checklist" |
| Complete provider-specific DNS prerequisites | Requires control of the authoritative DNS provider. | Email guide, pages 10-11, "Configure email authentication" |
| Configure priority account protection | Requires the customer to identify executives and other priority users. | Email guide, pages 42-43, "Priority Account Protection" |
| Run attack simulation and training | Requires campaign design, user targeting, communications, and recurring ownership. | Email guide, pages 42 and 44, "Attack Simulation Training" |
| Perform discovery, Threat Explorer, and hunting review | Investigation and operational review, not baseline configuration. | Email guide, pages 48-51, "Discovery items," "Threat Explorer," and "Advanced Hunting" |
| Create Cloud Discovery snapshot reports | Requires representative firewall or proxy logs and source-specific parsing. | SaaS guide, pages 9-12, "Set up cloud discovery" |
| Configure automatic Cloud Discovery log uploads | Requires firewall, proxy, or secure web gateway collector design. | SaaS guide, pages 9 and 13, "Automatic Log Uploads" |
| Scope anomaly detection policies | Requires customer-specific user, IP address, report, and threshold choices. | SaaS guide, pages 14-18, "Cloud discovery anomaly detection policy" |
| Review and govern OAuth apps | Recurring governance review requiring app-specific business decisions. | SaaS guide, pages 19-21, "Manage OAuth apps that are authorized by your users" |
| Create custom OAuth app policies | Requires custom conditions, exceptions, actions, and risk thresholds. | SaaS guide, pages 19 and 23-25, "Create OAuth App Policies" |
| Connect SaaS applications | Requires SaaS administrator credentials and provider authorization. | SaaS guide, pages 26-27, "Connect Apps for Visibility and Protection" |
| Enable SaaS Security Posture Management | Requires connected applications and customer-approved recommendations. | SaaS guide, pages 26-28, "Enable SSPM" |
| Design SaaS data protection policies | Requires connectors, sensitive-data design, and enforcement choices. | SaaS guide, pages 26 and 29, "Implement Data Protection / DLP Policies" |
| Establish recurring Defender for Cloud Apps operations | Ongoing operational work, not one-time configuration. | SaaS guide, pages 32-33, "Operations Guide" |
| Enforce BitLocker | High-impact device change requiring readiness, escrow, scope, and recovery planning. | Device guide, pages 24-27, "Configure Disk Encryption Policy" |
| Promote ASR rules from audit to block mode | Requires audit evidence, staged targeting, explicit approval, and recovery planning. | Device guide, pages 33-36, "Configure Attack Surface Reduction rules" and "View Attack Surface Reduction Report" |
| Enforce a device-risk compliance policy | Depends on stable device onboarding and risk signals and can mark devices noncompliant. | Device guide, pages 37-40, "Create Compliance Policy: Devices must have low risk score" |
| Block noncompliant devices with Conditional Access | Can block tenant access and requires emergency-access exclusions and staged rollout. | Device guide, pages 37 and 41-43, "Configure Conditional Access that blocks access for devices marked as noncompliant" |
| Switch the tenant to the MDE Plan 2 experience | Can require licensing decisions and a Microsoft Support workflow. | Device guide, pages 44-47, "Ensure Defender for Endpoint Plan 2 Subscription state" |
| Author custom MDE detection rules | Requires customer-specific KQL, validation, monitoring, and response ownership. | Device guide, page 45, "Defender for Business vs Defender for Endpoint P2" overview; the downloaded guide contains no custom-detection implementation procedure |
| Design MDE device groups and RBAC | Requires customer-specific device grouping and remediation responsibility. | Device guide, pages 46 and 48-50, "Configure Device Groups" |
| Configure ARC trusted sealers | Requires identification of trusted intermediaries that legitimately modify mail. | Email guide, page 41, "Advanced Email and Apps Protection Checklist" |
| Operate a continuous SOC workflow | Ongoing investigation and response process, not one-time configuration. | Email guide, pages 46-47, "Automated Investigation and Response 24/7/365 SOC Unlocked" |
| Perform daily Defender for Cloud Apps operations | Recurring operational ownership. | SaaS guide, pages 32-33, "Operations Guide," Daily activities |
| Perform weekly Defender for Cloud Apps operations | Recurring operational ownership. | SaaS guide, pages 32-33, "Operations Guide," Weekly activities |
| Perform monthly Defender for Cloud Apps operations | Recurring operational ownership. | SaaS guide, pages 32-33, "Operations Guide," Monthly activities |
| Perform ad-hoc Defender for Cloud Apps operations | Operational response driven by tenant events and risk. | SaaS guide, pages 32-33, "Operations Guide," Ad-hoc activities |

A later package revision can change filenames or pagination. Follow the named
section in the current download when it moves. These references provide manual
guidance only; they do not change an item's automation disposition or authorize
the toolkit to perform it.

## Practices outside the automated scope of this release

The following practices remain part of the Defender product coverage, but their
automated API path is outside the current approved pilot scope:

- **MDE advanced endpoint actions and MDE P2 automation**, including machine
  isolation, antivirus scan actions, remediation status, and advanced endpoint
  notification routing. Supported API automation requires an
  organization-provisioned MDE identity, MDE roles, and device-group scope.
  No approved managed identity is available for this pilot, and the toolkit
  must not ask an operator to create an app registration.
- **MDCA policy and governance automation**, including cloud discovery,
  anomaly-detection, App Governance, and threat-detection templates. MDCA uses
  a separate application-context authorization model; no approved
  organization-managed MDCA identity or policy-management read/write evidence
  is available.
- **Graph Security incident and alert readback as an automated MDE evidence
  path**.
  Both `GET /security/incidents` with `SecurityIncident.Read.All` and
  `GET /security/alerts_v2` with `SecurityAlert.Read.All` returned HTTP 403
  `Account is not provisioned`. This indicates Defender XDR account/service
  provisioning or eligibility is unavailable in the pilot tenant, so adding
  more Graph scopes is not an appropriate workaround.

These practices remain available as `GuidedOnly` portal-based readback and
presentation where the operator has access. Portal exports or operator-provided
evidence may be recorded, but browser scraping is not treated as supported
automation. API automation remains planning material for a future release or a
separately approved pilot with the required service provisioning and centrally
managed identities.

### Guided deployment references

Download Microsoft's [Best Practice Security Deployment Guides for
SMB](https://aka.ms/Security_SMBDeploymentGuides) and use these files from the
downloaded package:

- **MDE advanced configuration:** `Device Security Best Practice
  Deployment_Final030926.pdf`, pages 28-32 for attack disruption and endpoint
  notifications, and pages 44-50 for Defender for Endpoint Plan 2 subscription
  state and device-group/RBAC configuration.
- **Defender for Cloud Apps:** `SaaS Security Best Practice
  Deployment_Final030926.pdf`, pages 9-18 for Defender for Endpoint integration,
  Cloud Discovery, and anomaly policies; pages 19-25 for App Governance; pages
  30-31 for threat-detection policy templates; and pages 32-34 for operational
  review and user enrichment.

These page references were verified against the package downloaded on
2026-08-28. A later package revision can change filenames or pagination. Follow
the equivalent section headings in the current download if they move. These
portal procedures remain `GuidedOnly`; they do not authorize toolkit API calls,
endpoint response actions, connectors, or enforcement changes.

## Evidence and next steps

Use the approved private preflight package for the pilot protocol and endpoint
boundaries. Contributor-reported observations are not independent pilot
evidence and do not clear the manual pilot gate.

For a safe preview, run the documented `-WhatIf` command and review
`defender-run-log.json` and `defender-run-report.html`. Do not interpret those
reports as proof that a policy was applied.

## Summary

This matrix supports planning without overstating current capability. The
preview delivers read-only evidence, guided next steps, and the explicitly
enabled ASR Audit configuration path. Other workload automation requires
separate operation-level validation and human approval.
