---
title: Defender adoption readiness guide
parent: Microsoft Defender
nav_order: 8
---

# Defender adoption readiness guide

Microsoft Defender is available at its approved release scope. Default
execution is read-only, ASR Audit has an explicitly enabled managed pilot path,
and other writes retain their documented boundaries. This guide helps a
deployment team prepare communications without suggesting broader deployment
or protection than the run evidence proves.

## Current message

For a read-only preview, tell users that no Defender workload policy is being
changed. For an approved ASR Audit pilot, use a pilot-specific notice that
names the group, observation period, support route, and recovery owner. This
documentation does not authorize a production rollout.

## Readiness checklist

- [ ] Confirm the security owner and the tenant administrator.
- [ ] Define the intended pilot population and business-critical exceptions.
- [ ] Inventory existing mail, endpoint, and cloud-app controls.
- [ ] Agree on alert ownership, support contacts, and escalation timing.
- [ ] Document rollback expectations for every future enforcement change.
- [ ] Complete independent authorization and readback evidence for each
      workload before requesting approval.
- [ ] Obtain explicit approval before any future tenant-impacting change.

## Future communication template

> The deployment team is preparing a Microsoft Defender pilot. No policy
> changes are being made by the current preview. Before any pilot begins, the
> team will publish the scope, expected user impact, support route, rollback
> plan, and approval record.

## After independent approval

Only after the repository's implementation and pilot gates are complete should
the deployment team publish a pilot-specific notice. The notice must identify
the exact workload, scope, expected impact, support contact, monitoring
period, and rollback owner. Do not reuse this guide as a production
announcement.
