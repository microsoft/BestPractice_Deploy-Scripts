---
title: Defender scenarios and boundaries
parent: Microsoft Defender
nav_order: 4
---

# Scenarios and boundaries

| Scenario | Current outcome |
|---|---|
| Graph identity and workload/API capability preflight | Read-only; licensing is documented, not inferred from SKU names |
| MDO/EOP baseline | Reads delegated Exchange policy state; quarantine creation remains GuidedOnly, compliant quarantine policies are no-ops, and existing-policy drift is blocked |
| Defender for Business / ASR | Read-only by default; explicit managed Audit apply and separately acknowledged recovery use the Microsoft Graph Intune `/beta` configuration policy API (Preview); configuration and assignment pilot validation complete |
| MDE advanced settings | Guided-only; use the [Microsoft SMB deployment guide references](best-practices.md#guided-deployment-references) |
| Defender for Cloud Apps | Guided-only; use the [Microsoft SMB deployment guide references](best-practices.md#guided-deployment-references); no connectors, credentials, or enforcement |
| Noninteractive execution | Not supported by this release; use interactive delegated sign-in |
| High-risk enforcement | Blocked without approval and recovery controls |

The product is Available within the documented release scope. Missing live
evidence remains an operation-specific promotion gate and does not broaden any
`GuidedOnly` path.
