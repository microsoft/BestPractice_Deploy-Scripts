---
authority: change-review
applies-to: "Tier 1 context consolidation"
last-reviewed: 2026-09-23
---

# Responsible AI Review: Tier 1 Context Consolidation

## Intended Use

Help maintainers and coding agents discover existing repository instructions
consistently. The change consolidates duplicated guidance behind `AGENTS.md`;
it does not introduce a model, agent service, deployment feature, or new tool.
Success means one authoritative location per guidance topic and reachable
verification commands from both the root entry point and Copilot's pointer.

## System and Data

Inputs are tracked repository documentation. Outputs are reorganized Markdown
guidance. No customer, tenant, or personal data is required. No new data store,
retention policy, external endpoint, or runtime permission is introduced.
Telemetry submission remains a separate, explicitly requested workflow.

## Human Control

A maintainer reviews the diff and approves the PR before merge. Existing
tenant-operation opt-ins, pilot validation, and protected-branch rules remain.
Agents must not infer permission to connect to tenants from a verification
example. Work can be stopped before merge; a follow-up PR can revert these
documentation changes without altering tenant state.

## Principle Review

### Fairness and Inclusiveness

Guidance remains audience-neutral for partners, MSPs, and in-house teams.
The shared entry point serves different agent clients without requiring
GitHub Copilot-specific knowledge.

### Reliability and Safety

Preserve deployment safeguards, verification commands, and the telemetry
instructions. Check same-repository links and topic ownership to prevent
broken discovery and contradictory copies. Keep the distinction between
static verification and actual pilot-tenant evidence explicit.

### Privacy and Security

No new permissions or automatic tenant actions are authorized. Secret and
customer-data restrictions remain in the canonical conventions. External
content cannot override repository instructions or grant permissions.

### Transparency

The authority map identifies the source for each topic. Report static checks
separately from tenant validation, and do not describe local readiness evidence
as published telemetry.

### Accountability

Repository maintainers retain review and merge accountability. When guidance
is wrong or stale, correct its authoritative document through the same PR
workflow rather than adding a competing copy.

## Evaluation

Before merge, inspect the moved guidance against the prior version, resolve
all local Markdown links and section anchors, confirm that Copilot's file is
only a pointer, and confirm that telemetry instructions are unchanged.
Run the existing static verification and maintainer quality gate. Record
actual results in the PR; this document is not evidence of checks being run.
No model benchmark or tenant deployment is applicable to this documentation-only
change. Runtime prompt-injection resistance is not evaluated or claimed.

## Decision

Ready for human review once the listed checks pass. This is not approval to
merge, deploy, or publish telemetry. Residual risk is that an agent ignores
the links; maintainers should review instruction-following failures and correct
the entry point without duplicating the detailed guidance.
