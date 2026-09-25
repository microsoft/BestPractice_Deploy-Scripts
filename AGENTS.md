---
authority: canonical
applies-to: "**"
last-reviewed: 2026-09-23
---

# AGENTS.md — BestPractice_Deploy-Scripts

This is the master entry point for humans and coding agents working on
SMBBestPracticeTool: repeatable, idempotent PowerShell automation for Microsoft
365 best-practice configurations. Each product's README defines its scope
and release status. Read the linked guidance before editing; each topic has one owner below.

## Context and verification

- [Repository layout](docs/conventions.md#repository-layout).
- [Deployment architecture and shared helpers](docs/conventions.md#architecture-how-a-deployment-run-flows).
- [Authoring and safety conventions](docs/conventions.md#key-conventions).
- [Verification commands and definition of done](docs/conventions.md#validation-and-definition-of-done):
  repository-wide checks, individual checks, pilot-tenant validation, and docs preview.
- [Branch, release, and PR workflow](docs/conventions.md#git-workflow).
- [Optional local decision logs](docs/conventions.md#optional-local-context).

## PR and work-item telemetry

Read and apply the canonical
[telemetry instructions](.github/instructions/telemetry.instructions.md)
whenever creating or updating a PR or work item.

## Authority map

| File / path | Authority | Scope |
| --- | --- | --- |
| `AGENTS.md` | Canonical entry point | Context discovery and topic ownership. |
| `docs/conventions.md` | Canonical guidance | Layout, architecture, validation, safety, authoring, and Git workflow. |
| `.github/instructions/telemetry.instructions.md` | Canonical telemetry | PR and work-item labels, tags, and description footers. |
| `.github/copilot-instructions.md` | Pointer | Redirects Copilot to this entry point. |
| `scripts/verify.ps1` | Executable verification | Local syntax and configuration checks. |
| `Products/` | Implementation and product docs | Product behavior and operator instructions. |
| [Responsible AI review](docs/Responsible-AI-Review.md) | Change review | Scope and safeguards of this context-consolidation change. |
