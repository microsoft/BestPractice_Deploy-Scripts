---
title: Defender deployment playbook
parent: Microsoft Defender
nav_order: 7
---

# Defender deployment playbook

Microsoft Defender is available at its approved release scope. This playbook
describes how to collect a safe read-only report. The separately documented
ASR Audit path requires explicit managed-configuration switches and an
approved pilot group. Use the [deployment reference](deployment.md) for
configuration and recovery; this playbook does not duplicate or authorize
those operations.

## Before you start

- Use an approved non-production tenant only.
- Use an interactive delegated sign-in.
- Do not provide tenant identifiers, credentials, tokens, screenshots, or raw
  responses in issues or public repository files.
- Confirm that the operator understands that pilot approval remains a manual gate.

## Run the supported preview

```powershell
cd Products\Defender
.\Deploy-DefenderBestPractice.ps1 `
  -TenantAdminUpn admin@contoso.onmicrosoft.com `
  -WhatIf
```

The command above performs tenant-identity and capability preflight, records
guided-only boundaries, and produces evidence without applying policy changes.
Certificate authentication and `-NonInteractive` execution are not supported
by this release. The optional ASR Audit path is not enabled by this command.

## Review the reports

The output directory is `Products\Defender\Reports\`. The exact files are:

- `defender-run-log.json` - structured run entries and dispositions.
- `defender-run-report.html` - operator-readable rendering of the run log.

Review blocked and guided-only entries. A successful preview report is not
evidence that a workload policy can be changed and is not a release approval.

## Pilot evidence boundary

Operation promotion remains manual until an approved non-production record
contains workload-specific authorization, capability, readback, recovery, and
approval evidence. Existing outbound auto-forwarding and ASR evidence is
indexed in the private validation records; Safe Attachments and quarantine
retain separate live-evidence gates.

Do not use this playbook to claim production readiness. Record any remaining
operation evidence in the approved private validation package instead.

## Troubleshooting

If interactive sign-in or a read-only preflight fails, preserve the report and
record the failure without retrying with broader permissions. Check the
permission matrix and the endpoint validation register before proposing any
new operation. Do not add a skip switch as a substitute for missing evidence.
