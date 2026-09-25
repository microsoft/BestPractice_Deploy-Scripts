---
title: Coverage and Product-Group asks
parent: Microsoft Entra
layout: default
---

# Entra Conditional Access: coverage and Product-Group asks

Source: **Identity Protection Best Practice Deployment** guide (Business Premium /
Microsoft Entra ID P1). All Conditional Access policies fall under the guide's
**Priority 1** task "Set up Conditional Access using built-in templates,"
preceded by the Priority 1 task "Create emergency access account(s)."

## Coverage matrix

| Guide task | Item | Scripted | State shipped | Guide target | API |
|---|---|---|---|---|---|
| P1 — emergency access | Break-glass exclusion (verify or create) | ✅ | n/a | Exclude from all CA | `POST /users` (GA) |
| P1 — CA templates | Require MFA for admins | ✅ | report-only | On | `POST /identity/conditionalAccess/policies` (GA) |
| P1 — CA templates | Block legacy authentication | ✅ | report-only | On | GA |
| P1 — CA templates | Require MFA for all users | ✅ | report-only | On | GA |
| P1 — CA templates | Require MFA for guest access | ✅ | report-only | On | GA |
| P1 — CA templates | Require MFA for Azure management | ✅ | report-only | On | GA |
| P1 — CA templates | Require MFA for Microsoft admin portals | ✅ | report-only | On | GA |
| P1 — CA templates | Block unknown/unsupported device platform | ✅ | report-only | On | GA |
| P1 — CA templates | No persistent browser session | ✅ | report-only | Report-only | GA |
| P1 - CA templates | Require app protection policy | Yes | report-only | Report-only | GA |
| P1 — CA templates | Require compliant/hybrid device or MFA | ✅ | report-only | Report-only | GA |
| P1 addition | Block device code flow | Yes | report-only | Pilot before enforcement | GA |
| P1 addition | Protect security information registration | Yes | report-only | Pilot before enforcement | GA |
| P1 optional/hardened | Phishing-resistant MFA for admin roles | Yes | Not selected; report-only when selected | Method-readiness review before enforcement | GA |

Every scripted policy uses the **GA** `v1.0` Conditional Access API and requires
`Policy.ReadWrite.ConditionalAccess` for policy creation. The Security Defaults
read uses the existing `Policy.Read.All` scope. These API scopes do not prove
effective operator roles, licensing or GDAP access. The twelve selected policies
and optional hardened-admin policy have no P2 / Identity Protection dependency
and use no beta-only surface. Authentication strength is available with P1;
risk-based conditions require P2. Neither static configuration labels nor the
toolkit's informational SKU map prove the tenant's actual entitlement.

## P1 additions and P2 boundary

Entra 0.4.0 adds two selected P1 templates and one opt-in P1 hardening template.
All use the existing CA writer, approval gates, break-glass exclusions, shared
retry and readback. Every new-scenario reference requires
`ReviewExistingOnly = $true`; existing matches are never silently adopted,
renamed or replaced. Mismatched flow, user-action, strength or target conditions
produce review evidence. Readback checks these fields after creation.
Existing review-only matches remain `GuidedOnly` even when those fields match;
the comparison is not a substitute for the required manual readiness review.

| Tier | Scenario and payload | Prerequisites and limitations |
|---|---|---|
| `P1Baseline` | Block device code flow: `conditions.authenticationFlows.transferMethods = deviceCodeFlow`, `builtInControls = block`, all resources | Selected by default, pilot-group scoped. Inventory devices, CLI tools and other legitimate device-code clients. Review report-only sign-ins before enforcement and agree necessary exceptions. Does not block every authentication flow. |
| `P1Baseline` | Protect security information registration: `includeUserActions = urn:user:registersecurityinfo`, `builtInControls = mfa` | Selected by default, pilot-group scoped, guests/external users excluded. Requires combined registration and a viable initial MFA/bootstrap method such as an operator-issued Temporary Access Pass. It does not enroll users or issue credentials. There is no implicit trusted-network bypass. |
| `P1Hardened` | Admin phishing-resistant MFA: `authenticationStrength.id = 00000000-0000-0000-0000-000000000004` | Not selected by default. Explicit Boolean `Enabled=true` selects it. Targets the configured directory roles across the tenant, not the pilot group; CA includes are a union, not a role/group intersection. Verify usable phishing-resistant methods for every targeted admin and independently tested emergency access before enforcement. |
| P2 guidance only | Sign-in risk, user risk and stronger authentication triggered by risk | Not deployed by this release. Requires separately verified Entra ID P2 entitlement, risk/remediation design, emergency access and approval. Adding P2 licenses does not automatically opt in or create risk policies. |

The registration policy requires MFA from every in-scope location. Microsoft's
example also demonstrates excluding trusted locations; this template
deliberately has no such exception. Review your bootstrap path before
enforcement. Registration protection is not a requirement that all users
register, and guest registration needs a separate design. Microsoft also
documents registration-targeted CA evaluation for Windows Hello for Business
and macOS Platform SSO credential registration from July 6, 2026; include those
flows in the pilot.

Phishing-resistant strength accepts supported passkeys/FIDO2, Windows Hello
for Business/platform credentials and multifactor certificate-based
authentication. Ordinary MFA (for example password plus SMS) is not equivalent.
The template does not combine `mfa` with `authenticationStrength`, an unsupported
grant combination. Enabling methods and registering them remains outside this
writer.

### Corrected targeting and verification

The admin and admin-portal MFA templates target only their configured roles.
They do not combine those roles with a pilot-group include. Conditional Access
includes are a union, so that combination would also target non-admin pilot
members rather than limit the roles to the pilot. Azure-management MFA
explicitly targets all users for the configured application. Review these
tenant-wide principal selections even when the run supplies a pilot group.

The device-or-MFA template includes `mfa` in its OR grant controls alongside
`compliantDevice` and `domainJoinedDevice`. Browser-session comparisons check
the managed session settings and device filter, while ignoring unrelated
server response metadata. Every new CA policy is read back for the compared
controls, targeting and exclusions, not just its state.

Existing matches for these corrected templates require
`ReviewExistingOnly = $true`, including with `-AdoptExisting`. The same
manual-review boundary already applies to the phishing-resistant policy.
Automatic adoption does not change authentication strength or session
controls. Custom configuration must retain these review gates; a missing or
false gate stops execution rather than silently migrating enforcing policies.

These corrections have offline regression coverage, not new tenant-pilot
evidence. The identity owner must review targeting, MFA readiness and recovery
before enforcement. References checked September 25, 2026:

- [Conditional Access user and group assignments](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-users-groups)
- [Grant controls](https://learn.microsoft.com/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0)
- [Session controls](https://learn.microsoft.com/graph/api/resources/conditionalaccesssessioncontrols?view=graph-rest-1.0)

### API and source verification for the additions

References checked **2026-09-24**. No live tenant validation of the additions
has been performed.

| Operation | Surface, access and handling |
|---|---|
| Discover existing and read back created policies | Graph v1.0 CA collection/item GET, existing delegated `Policy.Read.All`; complete pagination for discovery, bounded transient retry and bounded 404 retry for propagation after creation |
| Create selected policies | Graph v1.0 `POST /identity/conditionalAccess/policies`, existing `Policy.ReadWrite.ConditionalAccess` plus the configured read scope; verify effective Conditional Access Administrator (or other supported role), consent and GDAP access independently |
| Set authentication flow / user action / strength | Documented v1.0 CA body fields, no new endpoint or permission; strength ID is Microsoft's documented built-in phishing-resistant policy |
| Recovery | Human-approved portal disable/delete or restoration of recorded prior settings; no automatic rollback, rename, method change or Security Defaults transition |

The identity owner is responsible for method readiness, entitlement, recovery
and pilot sign-off. The product owner and security/permissions reviewer must
review the addition before release. Deterministic fixtures check requests,
readback mismatch, no-write previews, selection and existing-policy preservation;
they do not establish service behavior or effective tenant access.

Microsoft references:

- [Block device code flow](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-authentication-flows)
- [Graph authentication-flow condition](https://learn.microsoft.com/graph/api/resources/conditionalaccessauthenticationflows?view=graph-rest-1.0)
- [Protect security information registration](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-security-info-registration)
- [Graph application and user-action targets](https://learn.microsoft.com/graph/api/resources/conditionalaccessapplications?view=graph-rest-1.0)
- [Graph user and role targets](https://learn.microsoft.com/graph/api/resources/conditionalaccessusers?view=graph-rest-1.0)
- [Authentication strengths and P1 licensing](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths)
- [Conditional Access and P2 risk-policy licensing](https://learn.microsoft.com/entra/identity/conditional-access/overview#license-requirements)
- [Built-in authentication-strength IDs](https://learn.microsoft.com/graph/api/authenticationstrengthroot-list-policies?view=graph-rest-1.0)
- [Create Conditional Access policies](https://learn.microsoft.com/graph/api/conditionalaccessroot-post-policies?view=graph-rest-1.0)

## Tenant security settings (Zero Trust)

`Setup-TenantSecuritySettings` covers the tenant-wide identity hardening from the
Microsoft Learn Zero Trust guidance
[*Configure Microsoft Entra ID for increased security*](https://learn.microsoft.com/entra/fundamentals/concept-secure-remote-workers).
Every item is **opt-in** via its `Apply` flag; while `Apply` is `$false` the
module compares current vs recommended state and reports `GuidedOnly` without
changing anything. Each write uses a **GA** `v1.0` Graph API.

| Zero Trust setting | Scripted | Default | Recommended | API |
|---|---|---|---|---|
| Restrict user consent to apps (verified publishers / low-impact) | ✅ | GuidedOnly | `managePermissionGrantsForSelf.microsoft-user-default-low` | `PATCH /policies/authorizationPolicy` (GA) |
| Admin consent request workflow | ✅ | GuidedOnly | Enabled with reviewers | `PUT /policies/adminConsentRequestPolicy` (GA) |
| Restrict guest access defaults | ✅ | GuidedOnly | `adminsAndGuestInviters` + restricted guest role | `PATCH /policies/authorizationPolicy` (GA) |
| Disable password expiration | ✅ | GuidedOnly | Never-expire on primary domain | `PATCH /domains/{id}` (GA) |

The admin consent workflow reports `GuidedOnly` (never enables) when `Apply` is
set but no reviewer group is configured, because enabling the workflow without a
reviewer would strand user requests.

Even with `Apply = $true`, all setting writes are withheld while Security
Defaults is enabled or unknown. Assessment and local reporting continue where
other prerequisites permit. The toolkit never changes Security Defaults.

## Zero Trust page — Product-Group asks and out-of-scope items

The following items appear in the Zero Trust "increased security" guidance but
are **documented rather than scripted** (no hallucinated APIs), with the reason:

1. **Security Defaults**: the toolkit reads
   `identitySecurityDefaultsEnforcementPolicy` but never changes it. Enabled or
   unknown state blocks all tenant writes. This baseline is not established as
   equivalent protection. Use the [control mapping and approved transition
   procedure](Security-Defaults-Transition.md), including registration, MFA
   prompting, legacy clients and device code flow. Report-only policies do not
   replace active Security Defaults.
2. **Authentication methods hardening** (migrate to the Authentication methods
   policy; disable SMS/voice) — `authenticationMethodsPolicy` is GA, but the
   correct target state is tenant-specific and disabling a method a user depends
   on can lock them out. A per-method, verified template is a backlog item.
3. **Self-service password reset (SSPR) enablement** — there is no supported GA
   Microsoft Graph write for the SSPR enablement toggle (configured in the portal
   / legacy APIs). Documented gap for Product-Group.
4. **Smart lockout thresholds** — exposed only through the `beta` directory
   settings surface; beta-only, so out of scope for a GA baseline.
5. **Identity Protection risk policies** require Microsoft Entra ID **P2**
   and remain guidance-only. PIM and Global Secure Access are also outside this
   toolkit's scope; verify their separate licensing rather than treating them
   as features deployed by the P1 baseline.

## Design decisions (documented for review)

- **Report-only default.** The guide lists a target state per policy (some
  "On"), but the toolkit ships new policies report-only. This is a configuration
  default, not a lockout guarantee or active replacement protection. The guide
  target is recorded per policy (`RecommendedState`) for separately approved
  promotion once its preconditions hold.
- **Break-glass required, verified, and injected.** The toolkit refuses to
  create the baseline without an emergency-access exclusion, and injects it into
  every policy's `excludeUsers`/`excludeGroups`. Verification is strict, matching
  Microsoft's emergency-access guidance: the account must be **enabled** and hold
  a **permanently-assigned Global Administrator** role (directly or through a
  role-assignable group). The check reads active role assignment schedule
  instances and accepts only tenant-wide assignments with no expiry. Temporary
  PIM activations, PIM-eligible-only status, and expiring assignments do not
  qualify. A break-glass *group* must contain an enabled member and provide
  Global Administrator (on the group or a member). Anything else, including a
  wrong role, no role, a disabled account, or a failed role read, stops the run
  rather than proceeding with a false exclusion.
  The final read-only deployment health check repeats this same shared
  recoverability check so a role, membership, or exclusion removed after
  deployment cannot be reported as healthy.
- **Existing-policy matching and adopt.** A same-named policy is only treated as
  compliant when it actually carries the required protections and excludes the
  break-glass principals; otherwise drift is reported (no duplicate is created).
  `-AdoptExisting` updates only policies outside the mandatory manual-review
  set described above, in place as a read-modify-write:
  it ensures **only** the required grant controls and the break-glass exclusion,
  and preserves the customer's other conditions (named locations, risk levels),
  session controls, targeting, and state.
- **App-protection migration.** New policies use `compliantApplication`, not
  the retired `approvedApplication` grant, and include Android/iOS without
  conflicting platform exclusions. Current and configured legacy names are
  recognized across paginated reads. Existing app-protection policies require
  manual migration review even with `-AdoptExisting`; neither silent repair
  nor duplicate creation is allowed. Corrected creation readback checks the
  app-policy grant/operator, target/platform fields, state and exclusions.
  See [migration prerequisites and service guidance](Security-Defaults-Transition.md#corrected-app-protection-policy-and-existing-tenants).
- **Enrollment CA excluded.** "Require MFA for Intune enrollment" is owned by the
  Intune product; it is not shipped here to avoid duplicate policies.
- **Pilot-group scope.** All-users-style templates are scoped to a pilot group
  by default rather than every user.

## Product-Group / API asks

These are documented rather than half-implemented (no hallucinated APIs):

1. **Registration bootstrap and guest registration**: the P1 template protects
   member registration with MFA, but does not configure combined registration,
   issue Temporary Access Passes, deploy guest registration controls or prove
   organization-wide MFA enrollment. Those remain operator prerequisites or
   separately designed controls.
2. **Guest MFA scope fidelity** — the source guest template targets a group. The
   more precise pattern targets guest/external user types
   (`includeGuestsOrExternalUsers`). Documented simplification; a verified guest
   template is a backlog item.
3. **Break-glass password handoff** — creating a break-glass account sets a
   random password that is never emitted to evidence; there is no supported way
   to hand the credential to the operator programmatically without logging it.
   The operator resets and stores it out of band (see the break-glass guide). A
   supported secure-handoff mechanism would be a Product-Group ask.

## Tenant validation

The historical write paths were validated against a Business Premium test tenant in
**report-only** state (dedicated pilot group + break-glass account, torn down
afterward):

- All ten Conditional Access policies were created in
  `enabledForReportingButNotEnforced`, each with the break-glass principal in
  `excludeUsers` and the all-users-style policies scoped to the pilot group.
- Every create was **read back and verified** (`state` matched) before teardown.
  A freshly created policy can briefly return `404 Not Found` on read-back while
  directory replication settles, so the read-back tolerates `404` as a transient
  status (`Invoke-WithTransientRetry -RetryStatusCodes 404`) and retries with
  backoff rather than reporting a false failure.
- The tenant-security settings ran with their default opt-out (`Apply = $false`)
  and reported `GuidedOnly`, changing nothing.
- Teardown removed the ten policies, the pilot group, and the break-glass
  account, returning the tenant to its prior state.

That historical record does not validate the corrected targeting, MFA alternative,
session-control verification, the 0.3.0 Security Defaults gate,
the corrected app-protection filters or the 0.4.0 policy additions. Offline fixtures cover their code
behavior; fresh pilot preview, effective roles/licensing, representative app
behavior and transition/recovery evidence are still required before rollout.
Current operation references and their verification date are recorded in the
[transition guide's API matrix](Security-Defaults-Transition.md#api-and-validation-record).
