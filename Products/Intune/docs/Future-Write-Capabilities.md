---
title: Intune future write capabilities
layout: default
parent: Intune
---

# Intune remaining and future write capabilities

This page separates the six write paths available in the current release from
the remaining guided, blocked, or broader future automation. It records which
gaps require help from Microsoft, tenant administrators, security reviewers,
or pilot owners. It is a roadmap, not a Microsoft commitment.

Status terms:

- **Work in progress:** supported interfaces exist, but implementation or review
  is incomplete.
- **Available, gated:** implemented with deterministic fixture coverage and
  safety gates. Refresh controlled pilot evidence after changing a write
  contract.
- **Expansion blocked:** the current narrow write exists, but broader
  platforms, payloads, or enforcement remain outside the approved scope.
- **GuidedOnly:** the supported production workflow requires a portal or
  external interactive step, or the available Graph resource is beta-only.
- **Future release:** eligible only after every listed release gate is complete.

## Write-capability register

| Guide task | Current status | Current boundary | Stakeholder help needed |
|---|---|---|---|
| 1. Windows automatic MDM enrollment | GuidedOnly | Microsoft documents the Entra portal workflow. The mobility policy resource falls back to beta and exposes no approved GA write/readback pair. | **Microsoft Entra/Intune API owners:** confirm whether a supported GA MDM user-scope API is planned. **Tenant operator:** complete and verify the portal workflow. |
| 2. Apple MDM push certificate | GuidedOnly | Graph v1.0 exposes CSR and upload operations, but Apple sign-in remains interactive and certificate replacement has no safe automatic rollback. | **Intune enrollment owner:** confirm supported no-certificate response and renewal semantics. **Customer:** own the organization Apple account and renewal. |
| 3. Managed Google Play | GuidedOnly | Connection, readback, and unbind resources remain beta-only; Google consent requires an interactive customer-owned identity. Disconnect disables Android Enterprise management and unenrolls devices. | **Intune Android API owners:** provide or confirm GA connection/readback capability. **Customer:** own the Entra/Google identity and consent. |
| 4. Default compliance setting | Available, gated | The module assesses every run and sets `secureByDefault=True` only with `-IncludeHighRisk`, `-EnableComplianceEnforcement`, and customer approval. | **Deployment and security owners:** confirm policy delivery and access impact before selection. |
| 5. Enrollment restrictions | Available, gated | The approved Android and iOS/iPadOS personal-enrollment restrictions are created and assigned under the high-risk category gate. Broader restriction design remains customer-specific. | **Deployment and security owners:** approve supported platforms, ownership rules, pilot scope, and recovery. |
| 6. App protection policies | Available, limited | Android and iOS/iPadOS Level 1 policies are created, target the configured core apps, and are assigned to the selected scope. Modern Windows MAM and broader payloads remain outside scope. | **Intune Apps API owners:** provide the Windows GA roadmap. **Product owner:** approve any expansion beyond the shipped Level 1 payloads. |
| 7. Device compliance policies | Available, gated and partial | The approved per-platform payloads are created and assigned with `-IncludeHighRisk`. Android Device Owner, AOSP, scheduled-action mutation, and the imported catalog remain outside scope. | **Intune compliance API owners:** confirm GA roadmap and scheduled-action semantics. **Security owner:** approve each added platform independently. |
| 8. Microsoft 365 Apps deployment | Available, limited | The current release creates and assigns the configured `officeSuiteApp` through the documented beta path and verifies key readback fields. | **Intune Apps API owners:** provide or confirm a GA create/update/readback surface. **Product owner:** review the beta dependency before expanding the payload. |
| 9. Enterprise State Roaming / Windows Backup for Organizations | GuidedOnly, work in progress | Microsoft moved ESR management from the Entra portal to Windows Backup for Organizations policy management after June 2026. The toolkit has not yet verified the supported policy API payload, assignment, readback, and rollback contract. | **Windows Backup and Intune policy API owners:** identify the supported GA policy creation/readback surface and migration contract. **Tenant operator:** use the current Intune Windows Backup and Restore workflow and pilot verification. |
| 10. Conditional Access for enrollment | Available, gated, highest risk | The module ensures the enrollment service principal exists and creates the policy report-only after every high-risk gate and at least one emergency-access exclusion ID are supplied. Enforcement and broad assignment remain separate decisions. | **Security owner:** verify exclusion IDs and approve the report-only design. **Pilot owner:** prove sign-in results and recovery before promotion. |

## Evidence required before expanding a write release

Every new or expanded write must have authoritative API documentation,
least-privilege Graph
permissions, Intune/Entra RBAC and GDAP mapping, active-license checks,
customer-safe identity and adoption rules, `ShouldProcess` and `-WhatIf`,
read-modify-write preservation, bounded readback, retry and propagation
handling, deterministic fixtures, controlled pilot apply, rollback, partial
failure recovery, redacted HTML/JSON evidence, and independent human approval.

The detailed source and operation records are maintained in the private
engineering repository. Operators should rely on this page and the product
README for the supported release boundary.

## Imported candidate policy catalog

The repository now retains all 19 Intune policy definitions from the existing
contributor implementation. The import includes mobile Baseline and Advanced
compliance and device-configuration payloads, plus Windows compliance, ASR
audit, Edge hardening, security baseline, and ACSC hardening payloads.

The source orchestrator was not adopted. It deleted existing objects by a name
substring, created policies without read-modify-write preservation, and used
Graph beta commands and raw assignment calls without this toolkit's approval,
pilot, readback, evidence, or rollback controls.

The normalized catalog is useful build input, but it does not change the write
status in the register above. The current release uses separate approved
payloads for app protection, compliance, enrollment restrictions, and
Microsoft 365 Apps. Catalog-based compliance and device-configuration
deployment still requires operation-level review and independent pilot
evidence.
