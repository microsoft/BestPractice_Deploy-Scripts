---
title: Defender permissions and supportability
parent: Microsoft Defender
nav_order: 2
---

# Permissions and supportability

The permission plan is operation-scoped. The verified read-only operation is
Graph tenant identity. API and workload capability checks, plus licensing
documentation links, are recorded in the structured run log. The toolkit does
not infer entitlement from SKU or service-plan names.

Delegated Graph sign-in may use browser authentication or device code flow.
Both paths issue delegated tokens and require the same operator consent and
tenant authorization. Device code flow is an authentication fallback; it does
not provide application permissions or make a guided-only operation writable.

The MDO/EOP module establishes its own delegated Exchange Online session;
Graph authentication does not establish that session. Current-state reads do
not require setter permission. Immediately before an approved write, the
module verifies effective Exchange RBAC for the exact cmdlet parameters with
`Get-ManagementRoleAssignment -RoleAssignee`; it never assigns a role.

Defender portal and Defender for Cloud Apps operations retain their documented
guided-only or unavailable boundaries. ASR assessment uses
`DeviceManagementConfiguration.Read.All`. Explicit ASR apply and recovery use
`DeviceManagementConfiguration.ReadWrite.All` plus `Group.Read.All` to verify
the supplied pilot security-group identifier before mutation.

Quarantine policy configuration uses dynamically imported Exchange Online
cmdlets. Before an approved creation, it checks effective RBAC for every
required `New-QuarantinePolicy` parameter and requires the verified
`mdo-quarantine-policy-apply` operation in the selected permission plan.
Production mutation remains `GuidedOnly`. See the
[Exchange Online protection boundary](deployment.md#exchange-online-protection-boundary)
for desired state, collision handling, and the create-only lifecycle.

Write operations remain guided-only until an authoritative endpoint, exact
delegated/application permissions, role or GDAP mapping, licensing
documentation, retry behavior, readback projection, and rollback procedure are
documented and verified. Actual readiness is established by workload/API
availability and authorized readback; do not treat `-WhatIf` as write
authorization.

The ASR policy operation uses the Microsoft Graph Intune
`configurationPolicies` **beta/preview** API; there is no `v1.0` equivalent
today. Apply and recovery require
`DeviceManagementConfiguration.ReadWrite.All`; group verification requires
`Group.Read.All`. See [Deployment](deployment.md) for the managed apply,
readback, rerun, and separately acknowledged recovery behavior.

## Licensing references

Licensing is documented for operator review and is not inferred from SKU or
service-plan names. Suites and add-ons can satisfy a product prerequisite, so
confirm the applicable entitlement and service availability using the
product's current licensing guidance:

The controlled probe observed the successfully provisioned `ATP_ENTERPRISE` service plan as
supporting commercial evidence for Defender for Office 365 Plan 1. The toolkit
does not use that observation as a static entitlement gate. Workload
availability and authorized readback remain the runtime authority.

- [Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/service-description-mdvo)
- [Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint)
- [Microsoft Defender for Cloud Apps](https://learn.microsoft.com/en-us/defender-cloud-apps/what-is-defender-for-cloud-apps)
