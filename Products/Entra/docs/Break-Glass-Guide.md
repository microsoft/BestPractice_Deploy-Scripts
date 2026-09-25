---
title: Emergency access (break-glass) guide
parent: Microsoft Entra
layout: default
---

# Emergency access (break-glass) accounts

Conditional Access can deny sign-in to every account, including administrators.
A **break-glass** (emergency access) account provides a recovery path when
normal administration is unavailable. Exclude emergency accounts from
Conditional Access policies that block or restrict sign-in, protect them with
phishing-resistant authentication, and test recovery regularly. No account or
exclusion is a guarantee against lockout. The Identity Protection guide lists
emergency access as a Priority 1 task.

## How this toolkit uses it

The Entra toolkit **will not deploy the Conditional Access baseline without a
break-glass exclusion.** You give it one of two ways:

1. **Use an existing account or group.** Put its object ID in the config:

   ```powershell
   ConditionalAccess = @{
       BreakGlass = @{
           ExcludeUserIds  = @('<user-object-id>')   # and/or
           ExcludeGroupIds = @('<group-object-id>')
       }
   }
   ```

2. **Let the toolkit create one.** Set `CreateAccountIfMissing = $true`. The
   `Setup-EmergencyAccess` module creates a dedicated **cloud-only** account
   (`break-glass-emergency@<your-domain>`) and excludes it from every policy.

Under the default configuration, every policy the toolkit creates excludes
the break-glass principal, including report-only policies. This is the
toolkit's preparation for later enforcement; Microsoft notes that report-only
policies themselves do not block sign-in.

This includes device-code blocking, registration protection and the optional
phishing-resistant admin policy. The hardened policy targets privileged roles
rather than intersecting them with the pilot group. Confirm emergency access
and authentication-method readiness before enforcement. The
[apply checklist](../README.md#usage) explains the configuration, approval and
confirmation parameters shown during the first preview.

Account creation is also withheld while Security Defaults is enabled or
unknown. Existing-account verification and local evidence remain read-only.
Do not disable Security Defaults to provision a test account; follow the
[approved transition and coverage procedure](Security-Defaults-Transition.md).
The script never performs that transition.

## After a break-glass account is created

The toolkit sets a random password that it **never writes to logs or evidence**
(so it cannot leak). You must finish the setup by hand:

1. In the Microsoft Entra admin center, open the account and **reset its
   password** to a long, unique value.
2. **Store the credentials securely** (offline/sealed, split knowledge if
   possible). Do not store them in the same systems the account protects.
3. Have the authorized identity owner make the Global Administrator role
   assignment active and permanent, not merely eligible or temporarily
   activated through PIM. The toolkit does not complete role assignment for you.
4. Register a phishing-resistant method such as a FIDO2 security key, with
   dependencies different from normal administrator sign-in. Emergency
   accounts must satisfy Microsoft's mandatory MFA requirements; do not treat
   Conditional Access exclusions as a blanket MFA exemption.
5. Maintain at least two cloud-only emergency accounts on the tenant's
   `.onmicrosoft.com` domain, securely store their credentials, monitor every
   use, and test sign-in and administrative recovery at least every 90 days.

These steps follow [Microsoft's emergency-access guidance](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access),
checked on 2026-09-25. The script's account creation, role checks, and
exclusion evidence do not replace an independently tested recovery procedure.

Every toolkit run finishes with a read-only deployment health check unless you
use `-SkipDeploymentHealth`. It verifies that the emergency principals remain
enabled, still provide a tenant-wide Global Administrator role through an
active role assignment schedule instance with no expiry, and remain excluded
from enforcing Conditional Access policies. Temporary PIM activations and
expiring assignments do not qualify. Treat `LockoutRisk` as immediate action,
`Indeterminate` as an incomplete safety check that must not be accepted as
healthy, and review the detailed counts in the HTML or JSON run report.

## Removing a toolkit-created account

Do not delete an emergency account just because a pilot finished. First have
the identity owner verify and test replacement emergency access, inspect every
policy and role that depends on the old account, and approve its retirement.
Only then remove the exact account and reconcile its exclusions. Preserve
working recovery access throughout; do not remove exclusions from enforcing
policies without the approved replacement plan.
