---
title: Changelog
layout: default
nav_order: 90
permalink: /changelog/
---

# Changelog
{: .no_toc }

All notable, **operator-facing** changes to the SMB Best Practice Tool are
recorded here — new features, changed defaults, fixes, and anything that
affects how you run the toolkit or what lands in a customer tenant.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

1. TOC
{:toc}

---

## How versions work here

This is an operations toolkit organised around **products** — a product is a
tenant-facing workload with its own deployment path (e.g. `[Purview]`). SemVer
(`MAJOR.MINOR.PATCH`) is read against those products:

| Bump | Means | Example |
|---|---|---|
| **MAJOR** | A **new product** is added to the toolkit — a new tenant-facing workload with its own deployment path. | Adding Defender alongside Purview. |
| **MINOR** | A **new feature, switch, or a redesign _within_ an existing product** — backward compatible for whoever runs it. | A new optional `-Switch`; the sensitivity-label signature redesign. |
| **PATCH** | A **bug fix** with no behaviour change for correct usage. | A connect/auth reliability fix. |

> A **changed default** (e.g. a switch that flips off→on, or a new tenant-side
> effect) does **not** by itself force a MAJOR bump — it rides the MINOR/PATCH of
> the product it belongs to — but it is **always** called out under **Changed**
> so operators see it.

Each entry is grouped under **Added / Changed / Deprecated / Removed / Fixed /
Security**, and tagged by area (e.g. `[Purview]`, `[Site]`). Changes that have
landed but not yet been tagged in a release appear under **Unreleased**.


---

## [Unreleased]

### Added

- **[Entra] First-run and recovery guidance.** Adds an operator guide and
  evidence/troubleshooting guide, linked from the product and shared starting
  pages. Emergency-access instructions now distinguish Conditional Access
  exclusions from mandatory MFA and require tested replacement access before
  retiring an emergency account.

- **[Entra] P1 coverage and optional admin hardening.** Entra 0.4.0 adds
  report-only device-code blocking and security-information registration
  protection to the default baseline, plus opt-in phishing-resistant MFA for
  privileged roles. Existing matches require manual review, and P2 risk
  policies remain guidance-only.

- **[Entra] Deployment guidance and policy naming.** Adds colored text-labeled
  output, numbered stages, module summaries and a first-preview apply checklist.
  An optional naming prefix adds sortable tier, sequence and scope codes while
  preserving existing policy names. Security Defaults remains a visible,
  read-only deployment gate and is never disabled automatically.

### Fixed

- [Defender] Report a module as `FAILED` when any operation or readback fails,
  even if other entries are blocked.
- [Entra] Correct role and Azure-management targeting and include the MFA
  alternative in the device-or-MFA policy. Verify managed session controls and
  device filters during readback. Existing corrected policies require manual
  review rather than automatic adoption; new policies remain report-only by
  default.
- [Intune] Treat exclusion-only assignments as unknown scope. Verify managed
  compliance and enrollment settings and their assignments instead of accepting
  a matching display name as proof of deployment. Keep enrollment inventory
  and write payloads aligned with their documented Graph API versions.
  Existing app-protection policies remain unchanged and are reported as
  requiring review rather than verified compliance.

- **[Entra, Intune] Report incomplete work accurately.** Modules that never
  start after an earlier failure now carry explicit skipped/blocked evidence,
  rather than appearing successful from configuration messages alone.
  Entra console, HTML, and JSON summaries agree without a child summary
  changing its parent's result. Evidence-write warnings cannot replace the
  deployment error when warning preferences are set to stop.

- **[Entra, Intune] Find saved run reports.** Final output now shows the full
  paths of successfully saved HTML and JSON reports and a command to open the
  HTML manually, including previews and failures after logging starts.
  Report-write failures are visible and do not hide the original deployment
  error. Report filenames and tenant behavior are unchanged.

- **[Intune] Keep Graph prerequisite versions aligned.** DeviceManagement is
  installed and imported at the same SDK version as Authentication. Existing
  loaded versions are respected, missing versions still require installation
  approval, and conflicting assemblies stop with fresh-session recovery
  guidance instead of an unpinned reinstall.

- **[Entra] Existing-policy review and exclusion payloads.** Review-only
  policies retain a manual-review outcome even when compared fields match.
  Emergency-access exclusions merge as flat Graph string collections while
  preserving existing guest and group exclusions.

- **[Entra] Disabled-policy verification.** A deliberately disabled new
  policy can be verified and rerun without a false readback failure. A disabled
  existing policy is still not considered compliant with an active target.

- **[Intune] Conditional Access and default-compliance reliability.** Intune
  now requests the documented Conditional Access read/write permission pair,
  verifies the Microsoft Intune Enrollment service principal after creating it,
  retries bounded service-principal and Conditional Access propagation checks,
  and treats nullable default-compliance projections as unknown. Unknown
  pre-write state cannot trigger a tenant change, while unavailable post-write
  readback blocks continuation with portal verification guidance.

### Security

- **[Purview] Tenant validation rejects broader Graph consent.** The read-only
  validator now checks the effective token, disconnects contexts containing
  permissions outside its two documented Graph read scopes, and supports an
  explicit fresh-session reauthentication path followed by an approved
  isolated public client fallback plus device authentication.
- **[Entra] Security Defaults readiness gate.** Entra 0.3.0 reads Security
  Defaults before setup and at selected write boundaries. Enabled or
  unverifiable state withholds all tenant writes, including account creation
  and opted-in tenant settings, while supported assessments can continue.
  The toolkit never disables Security Defaults. Reports expose readiness
  state and the deployment guide maps coverage and the approved transition,
  without claiming report-only policies replace active protection.

- **[Entra][Intune] Purview-aligned delegated Graph authentication.** Entra
  0.2.0 and Intune 0.3.0 now connect Microsoft Graph once per run using the
  administrator UPN or GDAP customer domain, reuse only account-, scope-, and
  tenant-matched contexts, disconnect stale sessions, and verify live tenant
  identity before setup begins. The product-specific `-TenantId`/`-ClientId`
  delegated-app path and the blocked `-CertificateThumbprint` placeholder are
  removed, and `-AutoInstallModules` adds Purview-compatible module readiness.
  `-NonInteractive` suppresses toolkit prompts but does not enable app-only
  authentication.

- **[Defender] Pre-consent ASR validation.** Rejects conflicting or incomplete
  ASR apply and recovery requests before permission planning or Microsoft Graph
  connection, so invalid input cannot trigger a write-scope consent request.
  ASR pagination now accepts only bounded HTTPS links on the Microsoft Graph
  host.

- **[Defender] Standalone ASR write authorization.** Requires the selected
  permission plan to contain the verified apply or recovery operation before
  the Defender for Business module can reach Microsoft Graph. Policy and
  assignment readback mismatches now record an exact blocked result.

### Changed

- **[Defender] Available release scope.** Lists the Defender toolkit as
  Available with a read-only default and the pilot-validated ASR Audit managed
  configuration path. Safe Attachments, quarantine, MDE advanced, and MDCA
  writes remain `GuidedOnly` pending operation-specific promotion evidence.

- **[Defender] Operator parameter reference.** Lists every Defender deployment
  parameter, default, safety interaction, and unsupported boundary in the
  product README. Detailed authentication, permission, lifecycle, evidence,
  and recovery guidance now lives on one canonical child page per topic.

### Fixed

- **[Purview] Deployment Plan intent parity.** Publish-all label policies,
  singular DLP `LabelPath`, encryption lifetime, managed ownership, custom
  recipient sets, supporting-guide ordering, and paired HTML/JSON output paths
  now match the effective deployment contract. The plan also uses a canonical
  Microsoft 365 Copilot location token and opaque custom-location digests,
  excludes unsupported-only retention scope, and rejects malformed built-in
  label signatures before sign-in, producing deterministic validator-ready
  schema 1.2 artifacts.

- **[Entra] App-protection template and migration safety.** New Android/iOS
  policies use the name "Require app protection policy" with the existing
  `compliantApplication` grant and no conflicting platform exclusions.
  Current and legacy names are recognized across all policy pages; existing
  policies require manual migration review and are not duplicated or silently
  changed, including with `-AdoptExisting`. Ambiguous matches and corrected
  readback mismatches block the operation. Custom configuration must include
  the current app-policy migration fields.

- **[Intune] Write-capable documentation parity and pilot assignment.** Corrects stale read-only
  preview language across the product README, operator and deployment guides,
  examples, support guidance, configuration reference, and roadmap. The
  documentation now identifies the six supported write paths,
  their pilot and high-risk gates, and the remaining guided or blocked tasks.
  Enrollment restriction writes now honor the resolved pilot scope unless
  tenant-wide assignment was explicitly approved. Create-only writers also
  leave existing same-purpose objects unchanged when `-AdoptExisting` is
  supplied instead of attempting a duplicate create. Unmanaged same-name
  objects now block the run, service-created IDs are encoded before follow-up
  requests, and supported post-write readback mismatches stop the run.
  App-protection targeting and assignment remain explicitly portal-verified.
  Conditional Access is restricted to the report-only state with explicit
  emergency-access exclusion IDs in the current release. A short first-run
  path now links pilot group setup, interactive sign-in recovery, separate
  high-risk stage commands, and object-specific partial-deployment recovery.
  The documentation hub links directly to that Intune first-run path.
  Renamed managed enrollment/compliance objects block duplicate creation;
  equivalent renamed Conditional Access policies remain unchanged.

### Added

- **[Purview] Standalone tenant validation.** Added a read-only validator that
  compares live state with schema 1.2 intended state or runs a guide-only Good,
  Better, and Best assessment without assuming default configuration. Matching
  HTML and JSON artifacts separate observation, plan comparison, and baseline
  results, calculate proven and provisional levels, anonymize unmatched
  objects, and request only `Organization.Read.All` and
  `GroupSettings.Read.All`. A new operator runbook documents required modules,
  report commands and locations, version-conflict troubleshooting, and the
  evidence needed to qualify future exact-version module profiles. Pilot tenant
  evidence remains pending.

- **[Purview] Tiered pre-connection Deployment Plan.** The plan now compares
  selected actions with the supplied Good, Better, and Best Data Security guide
  and keeps Microsoft Learn as a separate supporting reference. Each HTML and
  JSON pair has a short plan reference, while the deterministic fingerprint
  continues to identify equivalent intent. The JSON carries the identity fields
  and sanitized intended-state snapshot used by the standalone tenant
  validation handoff. Tenant identity, live object GUIDs, mailbox UPNs,
  resolved domains, and local paths remain excluded. The primary mapping now
  follows the supplied guide's task priorities: audit and foundational label
  controls are Good, Exchange retention is Better, and advanced DLP,
  auto-labeling, encryption, custom classification, and DSPM are Best. The
  Action Preview now labels these as Deployment Priority Levels and includes a
  closed glossary for its intent, priority, and recommendation statuses.

- **[Defender] Limited-access quarantine policy planning.** The MDO/EOP module
  now reads and plans a custom quarantine policy with limited end-user access,
  notifications enabled, blocked-sender messages excluded, and no protection
  policy assignments. Production mutation remains `GuidedOnly`. A quarantine
  policy the toolkit does not own is never adopted, even with `-AdoptExisting`,
  because the module cannot read which anti-spam, anti-phishing, anti-malware,
  or Safe Attachments policies already reference it; the run stops with
  guidance to rename the existing policy or configure a different name. A
  configured name that differs from an existing policy only by capitalization
  is also stopped, because Exchange Online treats those as the same policy. The
  block also covers drift on policies the toolkit owns. Existing policies are
  accepted only when already compliant, and the module has no
  `Set-QuarantinePolicy` path. A future create requires the verified apply
  operation to be present in the permission plan selected for that run. If
  the quarantine step cannot proceed, the Safe Attachments and outbound
  auto-forwarding assessments still run and record their evidence before the
  run reports the quarantine failure, and a configuration that omits the
  quarantine section records a skipped entry instead of failing.

- **[Entra] Read-only deployment health check.** Every run now finishes with a
  health check that reports whether the Conditional Access baseline has drifted
  since it was deployed, and above all whether each managed policy still
  excludes the emergency-access (break-glass) principals. An enforcing policy
  that lost its exclusion is reported as a lockout risk, and a tenant where the
  exclusion could not be evaluated is reported as indeterminate rather than
  healthy. The check issues GET requests only, changes nothing, and can be
  skipped with `-SkipDeploymentHealth`.

- **[Defender] Best-practice coverage guide.** Adds title-led summaries for 25
  in-scope practices and maps 33 practices outside the automated apply scope
  to the relevant Microsoft SMB deployment guide sections and pages.

- **[Defender] Managed ASR Audit pilot configuration.** Adds an explicit
  `-EnableAsrAuditPolicy` path that verifies a security-enabled pilot group,
  creates or reuses the toolkit-managed Intune policy, and confirms all 19
  Audit settings plus the isolated direct-group assignment. Partial failures
  retain the captured policy ID; separately acknowledged recovery can delete
  only that exactly verified policy. Default execution remains read-only.

- **[Intune] Documentation published to the site.** The Intune operator,
  deployment, configuration-reference, change-management, evidence/
  troubleshooting, support-team, end-user-adoption, scenarios, and
  future-write-capabilities guides now render on the docs site under
  `/intune/`, and Intune is listed with a Site link in the repository README
  and the site landing page (previously README-only).

- **[Entra] Conditional Access baseline (new product).** Adds the write-capable
  Microsoft Entra toolkit that deploys the Identity Protection guide's ten
  Conditional Access policies. Every policy is created report-only by default and
  always excludes an emergency-access (break-glass) account, which the toolkit
  verifies or creates. High-risk gates (IncludeHighRisk with approval, break-glass
  and rollback confirmation), pilot-group scope by default, idempotent on display
  name, and ShouldProcess + shared retry + readback + structured JSON/HTML
  evidence. The Intune enrollment Conditional Access policy is owned by the Intune
  product and is not duplicated here. Validated against a Business Premium test
  tenant in report-only state (created, verified, and torn down).

- **[Entra] Zero Trust tenant-security settings.** Adds
  `Setup-TenantSecuritySettings`, covering the Zero Trust "increased security"
  identity hardening (restrict user consent, admin consent workflow, restrict
  guest access defaults, disable password expiration) over GA `v1.0` Graph APIs.
  Every setting is opt-in via its `Apply` flag and reports guided-only until
  enabled; the coverage doc records the settings the guidance recommends that are
  out of scope or need a Product-Group ask.

- **[Intune] Tenant write paths for the enrollment and device-management
  baseline.** Six baseline tasks now apply to a tenant, not just assess:
  Microsoft 365 Apps deployment, app protection (MAM) Level 1, secure-by-default
  compliance, per-platform device compliance (Windows now includes Secure Boot
  and code integrity), device platform enrollment restrictions, and the
  device-based Conditional Access policy for Intune enrollment. Every write is
  idempotent (read-before-write on the managed-by tag), gated by
  `-WhatIf`/`ShouldProcess`, wrapped in the shared transient-retry boundary, and
  read back into the structured JSON/HTML evidence. High-risk items stay behind
  `-IncludeHighRisk` and their category switches, and Conditional Access is
  created report-only by default. Validated end-to-end on a Business Premium
  tenant. The hash-verified policy catalog remains apply-blocked.

- **[Defender] Read-only Exchange Online auto-forwarding planning.** Adds delegated EXO
  connection and tenant verification, runtime prior-state capture, and an
  ownership-neutral managed-write adapter for the built-in `Default` policy.
  Read-only assessment does not require setter permission; exact setter RBAC
  is checked immediately before an approved write. The outbound
  auto-forwarding write remains guided-only in production configuration.

- **[Defender] Safe Attachments planning and readback.** Reads the built-in
  ATP policy without requiring setter permission, no-ops when Safe Attachments
  is already enabled for SharePoint, OneDrive, and Teams, and prepares guarded
  write/readback/recovery behavior. Exact setter RBAC is checked immediately
  before an approved write. The write remains guided-only in production
  configuration.

- **[Defender] Module verdicts in deployment reports.** Defender JSON and HTML
  reports now include a shared per-module summary using `OK`, `FAILED`,
  `SKIPPED`, or `BLOCKED` so release evidence has an unambiguous module-level
  outcome.

- [Defender] Report configured recommendations with their current workload
  capability status instead of implying that unavailable controls are ready.

- **[Defender] Delegated authentication alternatives.** Documents browser
  authentication as the default and device code flow as a fallback, including
  explicit tenant targeting, process-scoped contexts, and known WAM/token
  handoff troubleshooting. Neither path changes the preview's read-only and
  guided-only boundaries.

- **[Defender] Corrected preview boundaries.** Defender public guidance now
  describes read-only, guided-only readiness coverage, uses the exact report
  names, qualifies contributor-reported pilot observations, and does not
  claim MDCA policy-management support or tenant deployment.

- **[Intune] Contributor policy catalog.** Integrates all 19 mobile and
  Windows policy payloads from the existing contributor implementation into a
  hash-verified candidate catalog. Export-only IDs and timestamps are removed,
  a placeholder Factory Reset Protection account is removed, Settings Catalog
  payload shape and discriminators are repaired, task 7 evidence reports the
  seven compliance candidates, and a reserved
  `-EnablePolicyCatalogWrite` gate always denies tenant apply.

- **[Intune] Device enrollment deployment guide.** Adds a guide-aligned
  partner runbook for the prerequisite, Priority 1, Priority 2, Priority 3,
  and post-configuration enrollment workflow. It identifies the current
  read-only and guided boundaries for every task.

- **[Purview] Offline Deployment Plan.** Each invocation now writes matching
  HTML and JSON intent artifacts before authentication, including config
  fingerprints, effective scope, and a versioned comparison to Microsoft's
  Data Security guide. Use `-NoDeploymentPlan` to suppress them.

### Changed

- **[Purview] Deployment Plan schema is now 1.2.** Plans now carry a sanitized
  intended-state handoff with action `IntendedStateKeys`, top-level
  `ManagedByTag`, handoff capabilities, and deterministic fingerprints. The
  standalone validator derives allowlisted adapters, selectors, prerequisites,
  comparators, and expected values from that data; the plan does not carry
  action-level validation instructions. Plans generated before schema 1.2
  remain readable but are rejected as validation baselines with an instruction
  to regenerate.

- **[Defender] Preview operator guide.** Documents the current read-only scope,
  prerequisites, reports, safety gates, explicit exclusions, and the
  guided-only boundary for unverified tenant writes.
- **[Defender] Explicit workload readiness records.** Graph tenant identity and
  license preflight are distinguished from unavailable EXO/IPPS, Intune,
  Defender portal, and MDCA connections; operator docs and release/SFI gates
  now preserve the Planned status until pilot evidence exists.
- **[Defender] Initial low-touch product foundation.** Adds the independent
  PowerShell Defender product boundary, configuration contract, tenant/API
  preflight, license capability classification, safety gates, and
  Purview-aligned structured JSON/HTML evidence. The current implementation is
  pre-release and does not yet claim production-ready tenant enforcement.
- **[Intune] Apple MDM push certificate health assessment.** The enrollment
  prerequisites module now reads the Apple MDM push certificate through
  Microsoft Graph and reports whether it is present and unexpired. A valid
  certificate is recorded as already compliant, an expired one is recorded as
  guided with renewal direction, and a missing, incomplete, or unreadable
  response fails the run instead of guessing. The read needs
  `DeviceManagementServiceConfig.Read.All`. Downloading the certificate signing
  request and uploading a certificate remain manual steps in the Apple portal.
- **[Intune] Default compliance setting assessment.** The compliance baseline
  module now reads the tenant `secureByDefault` setting and reports whether
  devices with no targeted compliance policy are already treated as
  noncompliant. It never changes the setting. Enabling it stays a manual,
  gated decision because it can deny access once device-based Conditional
  Access is enforced. The read requires the
  `Microsoft.Graph.DeviceManagement` PowerShell module.
- **[Intune] Android and iOS app protection assessment.** The app protection
  module now reads Android and iOS/iPadOS managed app protection policies,
  assignments, and targeted-app readback through Microsoft Graph GET requests.
  It reports one guided-only assessment per platform with normalized counts and
  assignment scope, redacts policy, group, app, tenant, and operator
  identifiers from evidence, and leaves policy creation, assignment, targeting,
  update, and deletion blocked pending human approval and pilot evidence.
- **[Intune] Device enrollment restriction inventory.** The enrollment
  restriction module now reads GA platform-restriction configurations and
  assignments, reports normalized counts and assignment scope without retaining
  identifiers, and continues to block all create, update, assignment, and
  delete operations pending pilot evidence.
- **[Intune] Per-platform compliance policy inventory.** Adds an independent
  GET-only module that inventories policies, assignments, and scheduled actions,
  classifies GA, beta-only, and unknown platform types, and emits redacted
  normalized evidence while all compliance writes remain blocked.
- **[Intune] Initial device management product foundation.** Adds the
  independent PowerShell Intune product boundary, configuration contract,
  tenant/API preflight, license capability classification, safety gates, and
  Purview-aligned structured JSON/HTML evidence for the Device Management
  Deployment Guide for Small Business baseline (ten tasks across three
  priorities). The current implementation is pre-release and read-only: it
  changes no tenant state, and no baseline item ships apply behavior until its
  API, permissions, licensing, readback, and rollback are verified.

### Changed

- **[Intune] Guide-task evidence follows deployment order.** Intune
  configuration and license evidence now lists tasks by Priority and guide task
  number, rather than alphabetically by toolkit key.

### Fixed

- **[Purview] Unsupported DLP workloads no longer terminate the module.**
  Workloads outside Exchange, SharePoint and OneDrive, and Endpoint are skipped
  with structured evidence, and the Deployment Plan excludes them from intended
  state instead of implying a supported runtime path.

- **[Defender] Configured-item summaries now reflect module outcomes.** Run-log
  entries remain individually filterable, and MDO/EOP terminal evidence carries
  its configured best-practice key so final reports show the actual compliant,
  blocked, or guided-only result instead of an unattributed fallback.

- **[Defender] Missing quarantine policies now plan creation correctly.** The
  MDO/EOP module enumerates quarantine policies and selects the configured name
  locally. This avoids Exchange module versions that raise an object-not-found
  error for an unknown identity while preserving collision checks and the
  create-only, `GuidedOnly` boundary.

- **[Entra] Permanent emergency-access role verification.** Break-glass checks
  now use active role assignment schedule instances and require a tenant-wide
  Global Administrator assignment with no expiry. Temporary PIM activations
  and expiring assignments no longer qualify.

- **[Entra] Graph pagination destination validation.** Entra directory reads
  now parse continuation links and require HTTPS, the configured Graph host,
  the default port, and the configured API path boundary before requesting the
  next page. Deceptive hostnames and lookalike path prefixes are rejected.

- **[Intune] Enrollment restriction exclusion counts are now order independent.**
  The assignment-scope assessment stopped counting exclusion groups as soon as it
  saw an all-users or all-devices target, so the `ExclusionCount` reported in
  enrollment restriction evidence depended on the order Microsoft Graph happened
  to return assignments and could read zero while exclusions existed. Both Intune
  modules now share one assignment-scope classifier, so the two cannot drift
  apart again. The assessment now also inspects every assignment instead of
  stopping at the first broad target, so a malformed assignment fails the
  assessment rather than being skipped depending on response order.

- **[Defender] Managed-write failures now fail the deployment.** MDO/EOP
  operations preserve every item-level recovery entry, then return a failing
  module and run outcome when a write fails or exact readback cannot confirm
  the tenant state.

- **[Defender] Least-privilege Graph examples.** Corrects delegated tenant
  identity examples to request the operation-selected `User.Read` scope rather
  than the application-only `Organization.Read.All` permission.

- **[Defender] Cmdlet throttling retries.** Retries supported EXO, IPPS, and
  SPO cmdlet failures when their error messages indicate throttling or
  temporary service unavailability, while preserving fail-fast handling for
  deterministic failures.

- **[Defender] Delegated tenant targeting.** Allows `-TenantId` without
  certificate parameters for delegated browser or device-code authentication;
  certificate validation still requires the complete tenant, client ID, and
  thumbprint tuple.

- **[Defender] Device code deployment switch.** Adds
  `-UseDeviceAuthentication` to route the orchestrator through the documented
  delegated device-code fallback while preserving the read-only preview
  boundary.

- **[Intune] Unconfigured Apple certificate assessment continues safely.**
  Microsoft Graph `404` responses from the Apple certificate singleton now
  produce a sanitized `GuidedOnly` result with portal verification direction,
  rather than aborting the remaining read-only assessments.

- **[Intune] Default compliance service state is assessed correctly.** A
  nullable `SecureByDefault` value now maps to Microsoft's documented
  `Compliant` default and a `GuidedOnly` result instead of aborting a
  read-only run.

- **[Intune] Compliance inventory survives unavailable action readback.** When
  the documented scheduled-action relationship has no matching v1.0 GET route,
  the toolkit now preserves policy and assignment inventory and reports the
  action count as unavailable instead of failing or reporting zero.

- **[Intune] Enrollment inventory accepts service-defined IDs.** Opaque
  configuration identifiers are now URL-encoded for assignment reads instead
  of being rejected when they are not GUIDs.

- **[Intune] App-protection inventory accepts service-defined IDs.** Opaque
  Android and iOS/iPadOS policy identifiers are now URL-encoded for assignment
  and target-app reads instead of being rejected when they are not GUIDs.

- **[Intune] Public gate messages no longer expose internal milestone names.**
  Runtime refusals, module help, configuration comments, and README guidance
  now name the actual API, permission, role, consent, licensing, readback, and
  rollback conditions. Public tests no longer require private planning paths.

- **[Intune] Policy catalog integrity is cross-platform.** Catalog hashes now
  use a canonical LF representation, so Windows CRLF checkout settings no
  longer cause Linux or macOS validation failures. A catalog integrity failure
  is reported separately and no longer prevents live read-only compliance
  inventory from completing.

- **[Intune] Enrollment restriction scope evidence no longer conflates default,
  custom, and exclusion assignments.** The assessment now separates assigned
  and unassigned restriction signals, counts exclusions independently,
  recognizes all-users and all-devices targets as broad, accepts valid OData
  type prefixes, and preserves legitimate empty Graph collections.

- **[Intune] Read-only assessment evidence stays consistent and sanitized.**
  Expected unsupported targeted-app responses no longer make a guided-only
  assessment report fail, successful retries no longer leave failed evidence,
  and subscribed SKU, Apple certificate, and default compliance failures no
  longer retain raw service-authored error text.
- **[Defender] Corrected the high-risk approval contract and review lifecycle.**
  Removed obsolete customer approval token parameters, aligned safety-gate
  fixtures and documentation with explicit operator opt-in, and clarified that
  independent review and tenant pilot validation occur during preflight rather
  than in the build-stage evidence record.
- **[Defender] Redacted tenant identifiers in JSON and HTML evidence.**
  Reports no longer expose the tenant GUID while retaining masked operator
  identity and structured evidence.


### Changed

- **[Intune] Apple certificate renewal is flagged before expiry.** The
  read-only Apple MDM push certificate assessment now reports guided renewal
  direction when the certificate enters a configurable warning window, which
  defaults to 30 days, rather than waiting until the certificate has expired.
  CSR generation, the Apple portal exchange, and certificate upload remain
  guided-only.

- **[Intune] Managed Google Play guidance identifies the safe ownership
  boundary.** The guided result now calls for a customer-controlled Entra
  account with an active mailbox, the required Intune role, a second Google
  enterprise owner, and verification through the four automatically added
  Android apps. It also states that GDAP does not replace interactive customer
  consent and that disconnect is destructive.

- **[Intune] Future write capability roadmap.** Adds a partner/customer-facing
  register that distinguishes work in progress, pilot blockers, guided-only
  tasks, genuine API gaps, and the precise stakeholder help needed without
  presenting beta surfaces as supported automation.
- **[Intune] Complete read-only deployment guidance.** Adds a ten-task scenario
  matrix, deployment framework, change-management playbook, current portal
  routes, support-team guide, end-user communication kit, worked examples,
  configuration reference, and evidence/troubleshooting guidance. The material
  clearly separates the current assessment from later customer-approved portal
  changes and blocked write automation.
- **[Intune] Microsoft 365 Apps deployment guidance.** Task 8 now emits a
  GuidedOnly result with the supported Intune portal path, configuration
  decisions, pilot assignment, and installation-status verification.
- **[Intune] Enterprise State Roaming guidance follows the current management
  model.** Task 9 now directs operators to Windows Backup for Organizations in
  Intune and explicitly rejects the obsolete post-June 2026 Entra portal path
  while policy API and migration behavior remain under verification.
- **[Intune] Conditional Access remains explicitly non-enforcing.** Task 10 now
  emits GuidedOnly evidence naming every prerequisite for a future pilot-scoped
  report-only policy, while creation and enforcement remain blocked.

- **[Intune] Withholding a write switch no longer hides the default compliance
  reading.** The default compliance assessment is read-only, so it now runs
  even when `-IncludeHighRisk` or `-EnableComplianceEnforcement` is not
  supplied. The missing write authorization is recorded separately in the
  report instead of blocking the check, so you can see the tenant's current
  state before deciding whether to approve a change. Enrollment restrictions,
  device compliance policies, and Conditional Access are unchanged and stay
  blocked without their switches.

- **[Intune] Per-item license findings are labelled as license findings.**
  Preflight now records each item's license result as `LicenseDisposition`
  rather than `Disposition`, so a licensing result is no longer easy to mistake
  for the outcome of the task itself. The Apple certificate state is now
  reported once, by the task that reads it, instead of also appearing as a
  fixed preflight note.

- **[Intune] Policies are assigned to a pilot group by default.** The source
  guide recommends assigning to all users. This toolkit deliberately defaults to
  `-PilotGroupId` instead, because enrollment restrictions, compliance
  enforcement, and Conditional Access can deny access to every user in the
  tenant on a first run. Tenant-wide assignment is an explicit opt-in through
  `-AssignTenantWide`, which also requires `-RollbackAcknowledged` and must be
  permitted by `Assignment.AllowTenantWideAssignmentForHighRisk` in
  configuration.

- **[Intune] Device compliance policies are classified high risk.** The source
  guide presents them as routine. Creating a compliance policy can mark existing
  devices noncompliant, and where the customer already operates Conditional
  Access requiring a compliant device, those users lose access immediately. Four
  of the ten baseline items now require `-IncludeHighRisk`, and a blocked item is
  recorded in the report with its reason rather than silently omitted.

- **[Intune] A run refused by a safety gate still produces a report.** Evidence
  is initialised before gates are evaluated, so a rejected run records which gate
  refused it and why. Customer approval references and approval artifacts are
  recorded only as SHA-256 digests.

- **[Repo] Shared prerequisites no longer claim every toolkit installs modules
  automatically.** The root README and documentation home previously stated that
  the toolkits auto-detect missing modules and that `-AutoInstallModules`
  installs them silently. That is a Purview behavior, not a framework guarantee,
  and Intune does not expose the switch. Both pages now direct you to the
  product's own documentation for its supported installation path.

### Fixed

- **[Intune] Safety-gate errors remain diagnostic under strict mode.** Empty
  certificate-argument sets are counted safely, and non-HTTP exceptions retain
  their original refusal reason instead of being masked by status-code parsing.

- **[Intune] Deployment evidence no longer stores raw tenant or approval
  identifiers.** JSON and HTML reports retain only the first tenant-ID segment
  for correlation, redact the remaining GUID segments, redact tenant domains
  including those quoted inside service error messages, omit approval paths, and
  hash customer approval references. Microsoft service endpoints such as
  `graph.microsoft.com` stay readable so failures remain diagnosable.

- **[Intune] The configured Graph endpoint is now the only one used.**
  `Api.GraphBaseUri` was defined in configuration while the tenant-identity and
  license requests hardcoded the endpoint, so changing the setting had no
  effect. Both requests are now composed from the configured value, and the
  value is validated as an approved HTTPS Microsoft Graph host before use.

- **[Intune] Per-category approval is enforced alongside global approval.**
  An item was recorded as unblocked once `-IncludeHighRisk` was supplied, even
  when its own switch, such as `-EnableComplianceEnforcement`, was withheld.
  The blocklist now evaluates both, so it agrees with the gate a module would
  apply and names the missing switch as the reason. The modules are read-only
  today, so this closes a future safety boundary rather than an active write.

- **[Intune] A failed configuration check now reports its own reason.** When
  validation rejected a configuration before the run log existed, the
  orchestrator's error and cleanup paths read an uninitialised variable and
  replaced the real message with a variable-access error. The run now reports
  which configuration value was rejected. `ConditionalAccess.DefaultState` is
  also validated by value, so a typo cannot reach a Conditional Access decision.

- **[Intune] Conditional Access permission requirements are now documented in
  full.** The API permission matrix listed only
  `Policy.ReadWrite.ConditionalAccess` for Conditional Access create, update,
  delete, and enable. Microsoft documents the least-privilege requirement as the
  pair `Policy.Read.All` and `Policy.ReadWrite.ConditionalAccess`, and records a
  known permissions issue confirming POST and PATCH need `Policy.Read.All`
  consent. All four rows now list both permissions, and the known issue is
  recorded as a Task 10 prerequisite so a run is not consented into a 403 at
  apply time.

- **[Purview] [Defender] `-WhatIf` no longer discards the deployment report.**
  The HTML report and JSON sidecar are written with `-WhatIf:$false` because
  they are local evidence, not a tenant change. Previously these writes
  inherited `$WhatIfPreference` from the orchestrator, so a `-WhatIf` dry run
  produced **no report at all** while still printing `HTML report written:` with
  a path that did not exist. Normal (non-`-WhatIf`) runs are byte-for-byte
  unchanged.

### Security

- **[Intune] Delegated consent now matches implemented reads.** The Preview uses
  `User.Read` and `LicenseAssignment.Read.All` for tenant and SKU discovery and
  no longer requests unused `Organization.Read.All` or `Policy.Read.All`.
  Delegated authentication is process-scoped so historical user tokens cannot
  restore removed scopes.

- **[Defender] Least-privilege consent model now fails closed.** Read-only Graph
  permissions are selected per operation (`User.Read` for tenant identity and
  `LicenseAssignment.Read.All` for license inventory), malformed permission
  manifests are rejected, app-only Defender authorization remains blocked until
  operation-level evidence exists, and unverified write operations cannot reach
  module dispatch.

- **[Defender] Safe-by-default readiness checks.** Noninteractive runs require
  certificate authentication parameters; audit readiness and emergency-access
  safety remain explicit guided-only decisions when no stable unattended check is
  claimed; secrets and operator UPNs are redacted from evidence.

- **[Intune] Safe-by-default readiness checks and access-denial gates.**
  Certificate-based application authentication is blocked until its
  operation-level permissions, roles, and consent are verified. The device-based
  Conditional Access policy defaults to report-only and needs
  `-IncludeHighRisk`, `-BreakGlassExclusionsConfirmed`, and
  `-RollbackAcknowledged` before it can be created enabled, because it can lock
  administrators out of the tenant. Marking unevaluated devices as not compliant
  and creating enrollment restrictions are separate explicit opt-ins. The Apple
  MDM push certificate and managed Google Play connection are recorded as
  guided-only and are never attempted, since both require human credentials and
  interactive browser flows. Secrets, tenant identifiers, tenant domains, and
  operator identities are redacted from evidence.

---

## [1.2.0] - 2026-07-01

> **Note — significant redesign (within Purview).** This reworks Purview sensitivity-label
> management to adopt Microsoft's built-in taxonomy by its stable signature, create MS-exact
> labels on blank tenants, and support the modern label scheme. It is a substantial redesign
> but stays within the existing Purview product, so it ships as a **MINOR** bump
> (`1.2.0`), not `2.0.0`. MAJOR (`2.x`) is reserved for adding a **new product** (e.g. Defender).

### Added

- **[Purview] Region- and scheme-proof label adoption + creation via the Microsoft
  `defa4170` signature.** Built-in labels are now identified by their stable internal
  `defa4170-…` name instead of the (localized) display name, so adoption works identically
  on English/French/German/… tenants and on both classic and modern label schemes. On
  blank tenants the toolkit now *creates* labels with the same `defa4170` names, so they are
  byte-identical to Microsoft's defaults (multitenant tools that look up by the standard
  name work everywhere).
- **[Purview] Blank modern-scheme tenant support.** Parents that own sub-labels are created
  as label **groups** (`-IsLabelGroup`) on modern-scheme tenants, with automatic fallback to
  a classic parent on classic tenants. Previously, deploying to a *blank* modern tenant
  failed creating sub-labels with `InvalidParentLabelInModernLabelSchemeException`.
- **[Purview] "Inherit label from attachments" is on by default.** Label policies now set
  `AttachmentAction = Automatic`, so an email inherits the highest-priority label from its
  attachments. Set `LabelPolicy.AttachmentAction` to `'Recommended'` (prompt) or `$null`
  (off) in `PurviewConfig.psd1` to change it.

### Changed

- **[Purview] Sensitivity-label taxonomy aligned to the Microsoft built-in defaults.**
  Confidential publishes **All Employees** + **Trusted People**; Highly Confidential
  publishes **All Employees** + **Specific People**; **General** is now a label **group**
  with **Anyone (unrestricted)** + **All Employees (unrestricted)**. The custom
  `Specific People` (under Confidential) and `Internal Exception` sub-labels are removed and
  consolidated into Trusted People / Specific People. **⚠️ On tenants where a previous
  version already created those extra sub-labels, they become unmanaged — delete them in
  Purview Admin.**
- **[Purview] Email default targets the assignable `General\Anyone (unrestricted)` leaf**
  (General is now a non-applicable group).
- **[Purview] Soft-delete tombstone rename no longer adds ` v2` to the user-visible
  DisplayName.** When a ~30-day tombstone blocks a re-created label, only the internal name
  is versioned; the DisplayName stays clean (a tombstone does not reserve the DisplayName).

### Fixed

- **[Purview] No more 45-second false "IPPS propagation" waits** when resolving already-
  existing (adopted) labels — they resolve on the first pass, and `-WhatIf` never waits. A
  `-WhatIf` that previously idled ~14 minutes now runs straight through.

---

## [1.1.0] - 2026-06-27

### Added

- **[Purview] Modern label-scheme publishing.** On tenants migrated to the
  modern sensitivity-label scheme, the toolkit now detects label **groups** (a
  parent that has sub-labels becomes a non-publishable container) and publishes
  only their sub-labels — the service auto-includes the parent group. It also
  substitutes a group used as the document or email default with the
  appropriate child (e.g. the Outlook default falls back from `General` to
  `General\Anyone (unrestricted)`), and excludes auto-managed group entries
  from the label-policy diff so re-runs stay idempotent. **Classic-scheme
  tenants are unchanged.** Previously, deploying to a modern-scheme tenant that
  already had the Microsoft built-in labels failed to publish with
  `Label group(s) ... can not be published`.

### Fixed

- **[Purview] No longer aborts on a localized display-name collision.** When a
  configured sub-label's display name matches an existing label's *localized*
  name under the same parent (e.g. `Specific People` vs the built-in
  `Specified People`), the toolkit now adopts the existing label instead of
  failing `New-Label` — which previously cascaded into a hard
  `Sensitivity label ... not found` stop in the DLP step.
- **[Purview] Policy default label resolves when it is an adopted sub-label.**
  Fixes `Default label 'AllEmployees' was not found after creation` on tenants
  where the default sub-label was adopted from a pre-existing built-in label
  (its live internal name is a GUID, not the configured name).

---

## [1.0.0] - 2026-06-22

**Initial versioned release.** This establishes version tracking; `1.0.0` is a
concise baseline snapshot of the toolkit as it stands today. Granular pre-1.0
development history is intentionally **not** itemised here — see the
[merged pull requests](https://github.com/microsoft/BestPractice_Deploy-Scripts/pulls?q=is%3Apr+is%3Amerged)
and [commit log](https://github.com/microsoft/BestPractice_Deploy-Scripts/commits/main)
for the detail. From the next release onward, every change is listed under its
own version above.

### What's in the box

- **[Purview] Data Security baseline** — idempotent, re-runnable deployment of
  tenant settings, sensitivity labels (encryption + container scope), DLP, and
  optional retention, all driven from one config file (`PurviewConfig.psd1`).
- **[Purview] License-aware** — auto-detects Business Premium vs E5 / Purview
  Suite and applies what the licence supports (E5 / Purview Suite additionally
  gets Endpoint DLP and AI governance / Copilot DLP).
- **[Purview] Zero-Trust connect** — Graph-first auth, WAM broker, and
  automatic recovery from common MSAL / `Microsoft.Graph.Beta` module issues.
- **[Site] Documentation site** — this GitHub Pages site: deployment framework,
  support-team guide, configuration reference, change-management timeline,
  adoption guide, and scenarios reference.

### Safety defaults

- **DLP starts in simulation** — zero user impact on day 0; promote after a
  Day-30 review.
- **Destructive / irreversible actions are opt-in** — retention
  (`-ApplyRetention`) and label co-authoring (`-EnableLabelCoAuthoring`);
  `-BPOnly` hard-blocks E5-only features.
- **Every run produces an HTML + JSON report** (secrets stripped) recording
  what ran, was skipped, or failed.

> **Upgrading from an earlier (untagged) build?** `-EnableContainerLabels` and
> `-ApplyAIControls` are now deprecated no-ops — both behaviours are default-on.
> Use `-SkipContainerLabels` / `-SkipAIControls` to opt out.

---

<!-- Link references — update the compare URLs as releases are tagged. -->
[Unreleased]: https://github.com/microsoft/BestPractice_Deploy-Scripts/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/microsoft/BestPractice_Deploy-Scripts/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/microsoft/BestPractice_Deploy-Scripts/releases/tag/v1.0.0
