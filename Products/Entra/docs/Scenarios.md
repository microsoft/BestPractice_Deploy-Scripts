---
title: Scenarios and what it does
parent: Microsoft Entra
layout: default
nav_order: 1
permalink: /entra/scenarios/
---

# Microsoft Entra: scenarios and what it does
{: .no_toc }

A plain-language tour of what the Entra toolkit sets up for a Microsoft 365
**Business Premium** (Microsoft Entra ID P1) tenant, who each control is for, and
why it is safe to run first. For the exact APIs, license notes, and Product-Group
gaps, see [Coverage and Product-Group asks](Coverage.md). Start with the
[README preview](../README.md#first-time-here-start-with-a-preview), use the
[operator guide](Operator-Guide.md) for deployment, and consult
[evidence and troubleshooting](Evidence-Troubleshooting.md) for blocked runs.

1. TOC
{:toc}

---

## Who this is for

Partners and IT admins standing up a **secure-by-default identity baseline** on a
new or existing Business Premium tenant. New policies default to
**report-only** (`enabledForReportingButNotEnforced`) and the default
configuration requires emergency-access exclusions. Neither default is a
guarantee against lockout or a replacement for existing enforcing protection.

## The safety model in one minute

- **Report-only by default.** New policies evaluate rather than enforce.
  Existing policies and changed configuration can still affect sign-in.
  Turning a policy on is a separate,
  deliberate change once you have reviewed the impact.
- **Break-glass always excluded.** The toolkit refuses to create the baseline
  unless an emergency-access account (or group) is available, and it is excluded
  from every new policy under the default configuration.
- **Security Defaults unchanged.** Enabled or unknown state limits every
  writer to assessment-only. The toolkit reads the state and never disables
  it. Follow the [coverage and transition guide](Security-Defaults-Transition.md)
  before moving from existing protection to approved active replacements.
- **Pilot group first.** All-users-style policies target a pilot group by
  default; tenant-wide is an explicit opt-in.
- **High-risk gates.** Creating Conditional Access requires `-IncludeHighRisk`
  plus break-glass and rollback confirmation. Preview everything with `-WhatIf`.

## Conditional Access baseline (12 policies, report-only)

| Policy | Problem it solves |
|---|---|
| Require MFA for admins | Privileged accounts are the top target; MFA on every admin sign-in blocks password-only compromise. |
| Require MFA for all users | Requires MFA for the pilot group, not just admins. This grant alone does not require phishing-resistant methods. |
| Block legacy authentication | Legacy protocols (IMAP/POP/SMTP auth) bypass MFA; blocking them closes the most common MFA-evasion path. |
| Require MFA for Azure management | Protects the Azure control plane (portal, CLI, PowerShell, ARM) with MFA. |
| Require MFA for Microsoft admin portals | Adds MFA in front of the admin portals themselves. |
| Require MFA for guest access | Applies MFA to external/guest users acting in your tenant. |
| Block access from unknown/unsupported device platforms | Denies platforms you have not chosen to support, shrinking the attack surface. |
| No persistent browser session | Prevents indefinitely "stay signed in" sessions on unmanaged browsers. |
| Require app protection policy | Uses `compliantApplication` for Android/iOS. Requires compatible applications and assigned Intune app-protection policies; the Entra template does not deploy those policies. |
| Require compliant/hybrid device or MFA | Prefers a managed, compliant device and falls back to MFA otherwise. |
| Block device code flow | Evaluates blocking device-code authentication for the pilot group. Inventory legitimate devices/tools and review report-only results before enforcing. |
| Protect security information registration | Requires MFA for member registration in the pilot group. Combined registration and an initial authentication method or Temporary Access Pass must be ready; guests/external users are excluded. |

The original ten policies record the guide's recommended target state. The
additions retain a report-only target pending their own pilot and enforcement
decision. The Intune device-enrollment Conditional
Access policy is intentionally **not** duplicated here; it is owned by the
Intune product.

The corrected app-protection template retains its old configuration key/file.
Existing current or legacy policy names are assessed without silent repair or
duplicate creation, including with `-AdoptExisting`. Review conflicting
platform filters and migration impact manually before broadening effective
scope. Multiple matching policies block the run.

The new device-code and registration policies also require manual review when
already present, even with `-AdoptExisting`. They do not change customer
exceptions or automatically migrate existing policies.

### Optional P1 hardening and P2 extensions

Set `Enabled = $true` on `require-phishing-resistant-mfa-admins` in your private
configuration to select the optional P1 policy. It requires Microsoft's built-in
phishing-resistant authentication strength and is report-only by default.
It targets privileged roles, not the pilot group. Verify supported methods for
every targeted administrator before enforcing; SMS or voice MFA does not
satisfy this policy.

P2-dependent sign-in risk, user risk and risk-triggered authentication controls
are not deployed. Authentication strength without a risk condition is a P1
capability. See [the tier and prerequisite matrix](Coverage.md#p1-additions-and-p2-boundary).

### From assessment to deployment

The console uses numbered stages, color and text status labels. Its readiness
section lists missing apply parameters before sign-in. Follow the
[preview-to-apply checklist](../README.md#usage), rather than simply removing
`-WhatIf`. You need verified emergency access, an approved change reference,
all high-risk confirmations and an approved assignment scope.

An optional naming prefix exposes policy tier, sequence, scope and purpose for
new policies. Existing policies retain their names and are matched without
duplication. See [policy naming and selection](../README.md#policy-naming-and-selection).

## Emergency access (break-glass)

The toolkit either **verifies** an emergency-access account you already have —
confirming it is enabled and holds a permanently assigned, tenant-wide Global
Administrator role with no expiry — or, if you opt in, **creates** a dedicated
cloud-only account for you. Temporary PIM activations and expiring assignments
do not qualify. Either way the account is excluded from every Conditional
Access policy. See the
[break-glass guide](Break-Glass-Guide.md) for the end-user steps.

## Tenant security settings (Zero Trust, opt-in)

These tenant-wide identity settings from Microsoft's Zero Trust guidance are
**off by default** — the tool reports current vs recommended state until you opt
in per setting:

- **Restrict user consent to apps** — users can only consent to low-impact
  permissions from verified publishers, cutting illicit-consent phishing.
- **Admin consent workflow** — users request access that an admin reviews,
  instead of consenting themselves.
- **Restrict guest access defaults** — limit who can invite guests and what
  guests can read in the directory.
- **Disable password expiration** — long-lived passwords with MFA beat forced
  rotation (Microsoft guidance).

Every selected tenant-setting write also requires Security Defaults to be
verified disabled. Unknown state is a blocker, not assumed consent to write.

## What it does not do

- It never changes Security Defaults, certifies replacement coverage, or
  automatically promotes report-only policies. Do not remove existing
  protection to test a report-only baseline.
- It does not change settings the tool does not own; tenant settings use
  read-modify-write to preserve your existing configuration.
- Risk-based Conditional Access requires Entra ID P2 and is not deployed.
  PIM and Global Secure Access are also out of scope and have their own
  licensing requirements. See [Coverage](Coverage.md) for the full boundary.
