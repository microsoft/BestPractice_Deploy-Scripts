---
title: Defender troubleshooting
parent: Microsoft Defender
nav_order: 5
---

# Troubleshooting

**Permission plan is not ready:** inspect the operation key in the report.
Unverified write operations are intentionally guided-only; do not add scopes
or bypass the manifest.

**Noninteractive authentication is unavailable:** certificate-based
authentication and `-NonInteractive` execution are intentionally blocked in the
current preview until operation-level application permission evidence is
approved. Use delegated browser authentication or device code flow instead.

**The browser prompt succeeds but `Connect-MgGraph` fails:** this indicates a
local WAM/token handoff or module-loading problem, not proof that tenant
authentication succeeded. Close other PowerShell and VS Code terminals, start
`pwsh -NoLogo -NoProfile`, load one Graph Authentication module version, and
target the tenant explicitly with `-TenantId`. If the failure persists, use
`-UseDeviceAuthentication` as the supported fallback. Do not delete broad
credential stores or Windows work-account registrations without first
identifying the owning client and impact.

If you authenticate with `Connect-MgGraph` in the same process before starting
the orchestrator, a matching tenant and delegated scope set are reused; the
orchestrator does not prompt a second time. A different tenant or incomplete
scope set causes the orchestrator to disconnect that process-wide Graph
context before requesting a new sign-in. Run the toolkit in a dedicated
PowerShell process when another task must retain its existing Graph session.

**Device code returns `AADSTS70011` (`invalid_scope`):** retry with an explicit
`-TenantId` and pass scopes as an array or comma-separated values. Test with
`User.Read` first, then add the other required scopes one at a time. A
successful browser step does not issue a token if Entra rejects the scope or
audience during the token exchange.

**A workload is unavailable:** EXO/IPPS, Intune, Defender portal, or MDCA can
be unavailable when the tenant, license, permission, or service provisioning
does not satisfy the selected operation. Follow the exact continuation
guidance in the report. Do not infer ASR write readiness from a successful
read-only Intune check.

**Licensing is unclear:** review the Microsoft Learn licensing link recorded for
the affected capability. The toolkit does not infer entitlement from SKU or
service-plan names; confirm the service is available and authorized through the
workload capability/readback check.

**A run stops after a failed read:** preserve the redacted report, correct the
tenant or permission issue, and rerun. Default and GuidedOnly paths do not
dispatch writes. If an explicitly enabled ASR Audit operation began, use the
captured policy ID and the separately gated recovery procedure rather than
deleting tenant state manually. Recovery permanently deletes the captured
policy and cannot be undone; see the Microsoft Graph
[delete configurationPolicy API](https://learn.microsoft.com/graph/api/intune-deviceconfigv2-devicemanagementconfigurationpolicy-delete?view=graph-rest-beta).
