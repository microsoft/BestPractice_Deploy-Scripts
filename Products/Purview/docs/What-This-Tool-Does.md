---
title: What's Changing - Support Team Guide
layout: default
parent: Purview
nav_order: 1
permalink: /purview/whats-changing/
---

# What's Changing — Support Team Guide
{: .no_toc }

A single-screen, **visual** summary of every change the Purview toolkit makes
when it runs — what's **on by default**, what's **opt-in**, what's
**auto-detected from the licence**, and what's **destructive**. Colour-coded so
it's scannable.

**Who this is for:** the **support team / service desk**. Read it
*before* a deployment so you know exactly what lands in the customer's tenant —
and, just as importantly, **what does _not_ change** — so you're ready for any
support call about the rollout (new labels in Office, "why can't I share this
file externally", the 30-day simulation window, Copilot behaviour, etc.).

> 🧭 **Need the full technical detail?** This page is the at-a-glance impact
> view. For the complete scenario matrix, per-licence behaviour, and what's
> deliberately out of scope, see
> [**Scenarios & Capabilities**](scenarios/). For the day-by-day delivery
> runbook, see the
> [**Change-Management Playbook**](change-management-playbook/).

[Open full-screen ↗]({{ '/Products/Purview/docs/What-This-Tool-Does.html' | relative_url }}){: .btn .btn-purple target="_blank" }
[Download the standalone file ↗]({{ '/Products/Purview/docs/What-This-Tool-Does.html' | relative_url }}){: .btn target="_blank" download }

> 💡 The guide below is a **single self-contained HTML file**
> (`Products/Purview/docs/What-This-Tool-Does.html`). It needs no server, so you
> can share it with the support team on its own, pin it in a Teams channel, or
> open it offline.

<iframe
  src="{{ '/Products/Purview/docs/What-This-Tool-Does.html' | relative_url }}"
  title="What's Changing — Support Team Guide"
  style="width:100%; height:1150px; border:1px solid #dedede; border-radius:12px;"
  loading="lazy">
</iframe>

---

## How this differs from "Scenarios & Capabilities"
{: .no_toc }

| | **This page** — What's Changing | [Scenarios & Capabilities](scenarios/) |
|---|---|---|
| **Audience** | Support team / service desk | Evaluators, reviewers, security leads |
| **Angle** | What lands in the tenant · on / off / auto · **impact & no-impact** | Full scenario matrix · per-licence behaviour · **out-of-scope** |
| **Format** | Visual, colour-coded, scan-in-2-minutes | Reference prose + tables |

Use this one to **get the support team ready**; use Scenarios & Capabilities
when you need the exhaustive technical reference.

## Reports operators receive

Before authentication, the toolkit writes a self-contained Deployment Plan HTML
file and matching JSON sidecar. They summarize config intent, effective
switches, fingerprints, and action mappings to the supplied Good, Better, and
Best SMB guide. Microsoft Learn remains visible as a separate supporting
reference. A short `PUR-...` reference identifies the generated pair, and the
JSON carries a sanitized intended-state snapshot for a dependent stacked
tenant-validation feature. The snapshot includes matching fields needed for
later comparison but remains private customer-sensitive evidence. The plan
does not inspect the tenant or claim compliance. It uses the canonical
`Microsoft365Copilot` token for the public Copilot location and opaque digests
for custom locations, records unsupported retention destinations separately,
and fails local preflight when a non-empty built-in label signature is
malformed.
The Action Preview labels these as Deployment Priority Level values: Priority 1
(Good), Priority 2 (Better), and Priority 3 (Best), and provides a closed
explanation panel for the intent, priority, and comparison vocabulary.
Good includes audit, baseline labels, container and SharePoint/OneDrive label
enablement, and core DLP; Better adds Exchange retention; Best adds advanced
DLP, auto-labeling, encryption, custom SITs, and DSPM. Unassigned capabilities
are labeled as toolkit extensions.

After deployment, a separate HTML and JSON report records the actions that
actually ran, skipped, retried, or failed. `-NoDeploymentPlan` suppresses only
the pre-connection plan. `-NoReport` suppresses only the end-of-run report.

Later, `Test-PurviewTenantConfiguration.ps1` reads the tenant and can compare it with one
Deployment Plan. It is a separate read-only command, it changes nothing, and it
is not a compliance assessment. It also refuses a Graph token that contains
resource permissions beyond its two documented read scopes; an approved
fresh PowerShell sign-in is attempted first, and an isolated public client can
be supplied when the shared Graph client still has broader consent. See
[Configuration Validation](configuration-validation/).
