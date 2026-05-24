# Decision Intelligence Platform

Decision Intelligence Platform is a governed decision automation framework.

The first implementation wedge is pre-runtime:

```text
decision spec -> capability registry -> policy preflight -> simulation
  -> decision diff -> approval -> case evidence -> replay
```

This repository intentionally does not execute production decisions. Runtime
integration, marketplace invocation, shared context exchange, and production
decision execution are blocked until separately evidenced and approved.

## Local Validation

```bash
./scripts/validate.sh
```

## Trust Loop

```bash
python3 -m dip_framework trust-loop --out reports/trust-loop
```

The trust loop writes fixture evidence only. It does not call external systems
or request runtime execution.

## v0.2 Pre-Runtime Evidence

```bash
python3 -m dip_framework release-pack --version v0.2.0-pre
```

v0.2 adds computed policy preflight from versioned policy definitions, a
file-backed case manifest with SHA-256 checksums, and release acceptance
evidence. Runtime execution remains blocked.

## v0.6 Identity/RBAC Approval Evidence

```bash
python3 -m dip_framework release-pack --version v0.6.0-pre
```

v0.6 adds a versioned local identity/RBAC registry and computed approval
authority evaluation. It proves approval role, scope, active identity, MFA, and
AI self-approval blocking against local evidence only. External identity
provider integration and runtime execution remain blocked.

## v0.7 Repository Governance Evidence

```bash
python3 -m dip_framework release-pack --version v0.7.0-pre
```

v0.7 adds repository governance policy evidence for required status checks,
one-review admission, admin enforcement, force-push/deletion blocking, and
time-boxed break-glass handling. It remains pre-runtime evidence only.

## v0.8-v1.1 Governance Maturity

```bash
python3 -m dip_framework release-pack --version v1.1.0-pre
```

v0.8 adds release lifecycle policy evidence for independent approval,
CODEOWNER/conversation-resolution expectations, rollback criteria, and
artifact/source-commit binding. v0.9 adds external identity provider contract
evidence without live authentication. v1.0 adds durable evidence-store contract
evidence for append-only content-addressed storage semantics without claiming a
production storage backend. v1.1 closes the release-enforcement gap by
requiring CODEOWNER review and conversation resolution on `main`. Runtime
execution remains blocked.

## Completion Plan

The current completion plan is documented in
[`docs/DIP_COMPLETION_PLAN.md`](docs/DIP_COMPLETION_PLAN.md). It keeps DIP
focused on the governed pre-runtime wedge and treats EDI as an evidence
observer, not the DIP runtime.

```bash
python3 -m dip_framework release-pack --version v2.0.0-pre
```

The completion release adds review-surface evidence, a third concrete decision
domain, capability governance, shared context contract governance, and a
runtime-readiness assessment. Runtime execution and production decision
authority remain blocked.

## v11.0-v20.0 API-First Platform Foundation

```bash
python3 -m dip_framework release-pack --version v20.0.0-pre
```

v11.0 adds the API-first modular platform architecture, product-pack registry,
ML shared-capability inventory, adapter evidence contract, governance-store
contract, and runtime-authority blocked model. v12.0 adds stateful shared
capability certification. v13.0 adds explicit product-pack contract gates.
v14.0 adds REST command/query contracts. v15.0 adds WebSocket event recovery
contracts with REST recovery twins. v16.0 adds certification evidence packs for
candidate shared capabilities. v17.0 adds product-pack admission records.
v18.0 adds the REST-authoritative OpenAPI skeleton. v19.0 adds concrete event
recovery fixtures. v20.0 adds the neutral governance-store logical schema and
architecture closure gate. These releases remain contract and evidence
foundation only: no service is certified for runtime use, no product pack has
runtime authority, no product can use direct database access, WebSocket is not
authoritative, no production governance-store backend is selected, and
production decision execution remains blocked.

## v2.1 Governance Exception and Schema Stability

```bash
python3 -m dip_framework release-pack --version v2.1.0-pre
```

v2.1 records the solo-maintainer GitHub review workaround as a governed
exception rather than independent review evidence. It also freezes first-wedge
schema versions and validates negative fixtures for blocked production
authority and AI approval. Runtime execution and production decision authority
remain blocked.

## v2.2 External Approval Boundary

```bash
python3 -m dip_framework release-pack --version v2.2.0-pre
```

v2.2 separates decision approval authority from GitHub code review and the
solo-maintainer merge exception. It defines the external decision-approval
evidence required before runtime can be considered, but does not claim a live
external approval system. Runtime execution and production decision authority
remain blocked.

## v2.3 Durable Case Store Adapter

```bash
python3 -m dip_framework release-pack --version v2.3.0-pre
```

v2.3 defines the durable case store adapter boundary for append-only,
content-addressed case records, manifest-chain verification, replay export,
audit export, retention controls, and denied mutation operations. It remains a
contract-backed adapter boundary, not an observed production storage backend.
Runtime execution and production decision authority remain blocked.

## v2.4 Evidence Store Adapter Parity

```bash
python3 -m dip_framework release-pack --version v2.4.0-pre
```

v2.4 computes adapter parity evidence for append, read, manifest verification,
replay export, and audit export operations. It also validates denied mutation
operations and adds negative fixtures for missing hash-chain enforcement,
delete-enabled behavior, and weak retention. This remains pre-runtime evidence:
no production storage backend is observed and no runtime backend is invoked.

## v2.5 Policy Engine Hardening

```bash
python3 -m dip_framework release-pack --version v2.5.0-pre
```

v2.5 hardens deterministic policy evaluation with policy lifecycle status,
supported rule-type compatibility, deterministic outcome precedence, escalation
support, and negative fixtures for unknown rules, revoked policies,
runtime/production authority claims, and missing required evidence. AI override,
runtime integration, and production decision authority remain blocked.

## v2.6 External Approval Adapter Boundary

```bash
python3 -m dip_framework release-pack --version v2.6.0-pre
```

v2.6 defines the neutral external approval adapter contract for approval
request, approval, rejection, expiry, delegation, revocation, and audit export.
It validates required request and decision evidence, denied self-approval and
runtime operations, lifecycle outcomes, admission controls, and audit
requirements. It remains contract-only: no live external approval system,
runtime integration, or production decision authority is observed.

## v2.7 Live Identity/RBAC Evidence

```bash
python3 -m dip_framework release-pack --version v4.0.0-pre
```

v2.7 observes live GitHub identity and repository RBAC evidence for the
pre-runtime approval authority path. It records the authenticated subject,
repository permission, and decision-scope authorization, while explicitly
leaving the external MFA claim unobserved because the available GitHub API path
does not expose that claim. Runtime integration and production decision
authority remain blocked.

## v2.8 Durable Evidence Backend Observation

v2.8 observes a pre-runtime, file-backed durable evidence backend path from the
case manifest, replay pack, and adapter parity evidence. It validates append-only
writes, content-addressed records, manifest-chain verification, read/replay/audit
exports, delete denial, mutation denial, retention policy, and backend health.
It does not observe a production storage backend or invoke a runtime backend.

## v2.9 Promotion Chain And Rollback Evidence

v2.9 records a commit-bound release artifact digest, build run id, declared
dev-test-staging-prod promotion chain, approval requirement record, rollback
criteria, rollback artifact, and solo-maintainer exception evidence. It records
that production deployment was not executed.

## v3.0 Pre-Runtime GA Acceptance

v3.0 completes the Governed Decision Review and Simulation wedge as pre-runtime
GA evidence. The acceptance pack binds decision spec, capability registry,
capability graph, policy preflight, simulation, decision diff, approval record,
case store, lineage, replay evidence, identity/RBAC, durable backend observation,
promotion chain, and EDI observer evidence while keeping runtime execution
readiness and production decision authority at `0%`.

## v3.1-v4.0 Runtime Authority Gate

v3.1 through v4.0 add the next evidence sequence without silently granting
runtime authority:

- v3.1 closes repository governance evidence while preserving the solo-maintainer
  exception as an exception, not independent review.
- v3.2 records the external identity integration boundary and keeps live IdP/MFA
  readiness blocked when not observed.
- v3.3 records the external approval system boundary and keeps live provider
  readiness blocked when not observed.
- v3.4 records the production case-store backend contract and keeps production
  storage readiness blocked when no production backend is observed.
- v3.5 records runtime control-plane design evidence: policy gate, approval
  gate, kill switch, entitlement, cost, observability, lineage, replay, and
  rollback controls.
- v3.6 records an advisory-only runtime pilot from existing simulation evidence
  with no side effects or production mutation.
- v4.0 records the limited-runtime-authority gate as complete but authority
  remains blocked until live IdP/MFA, live approval provider, and production case
  store evidence exist.

## v4.1-v6.0 Readiness Gates

```bash
python3 -m dip_framework release-pack --version v10.0.0-pre
```

v4.1 through v6.0 complete the next readiness sequence without granting hidden
runtime authority:

- v4.1 records the live identity evidence gate and keeps authority blocked while
  live external IdP/MFA evidence is unavailable.
- v4.2 records the live approval provider gate and keeps approval-provider
  readiness blocked while no live provider is observed.
- v4.3 records the production case-store gate and keeps storage readiness blocked
  while no production backend is observed.
- v4.4 records the release-promotion execution gate and keeps production
  promotion blocked while no prod deployment was executed.
- v5.0 records governed advisory runtime evidence with recommendations only, no
  side effects, and no production mutation.
- v5.5 records the controlled-runtime execution gate and keeps execution
  authority blocked until all live prerequisites pass.
- v6.0 records platform-hardening assessment evidence while keeping production
  readiness false.

## v6.1-v9.0 Production Authority Readiness Gates

```bash
python3 -m dip_framework release-pack --version v10.0.0-pre
```

v6.1 through v9.0 complete the production-readiness review sequence without
granting production decision authority:

- v6.1 records live identity authority readiness and keeps authority blocked
  while live external IdP/MFA evidence is not observed.
- v6.2 records live decision approval provider readiness and keeps approval
  readiness blocked while no live provider is observed.
- v6.3 records production durable case-store readiness and keeps production
  storage readiness blocked while no live backend is observed.
- v6.4 records production promotion-chain readiness and keeps production
  promotion blocked while no prod deployment has executed.
- v7.0 records controlled-runtime pilot admission and keeps execution blocked
  until live identity, live approval, live case store, and promotion evidence
  pass.
- v7.5 records marketplace runtime governance and keeps marketplace invocation
  blocked until controlled runtime is authorized.
- v8.0 records shared-context runtime governance and keeps runtime context
  exchange blocked until controlled runtime is authorized.
- v9.0 records production authority readiness review and keeps production
  decision authority at `0%`.

## v10.0 Completion Plan Execution Review

```bash
python3 -m dip_framework release-pack --version v10.0.0-pre
```

v10.0 executes the nine-step completion plan as a review and evidence pass. It
does not convert missing live prerequisites into readiness:

- all nine completion-plan steps are reviewed;
- all nine evidence gates remain traceable;
- live IdP/MFA, live approval provider, production case-store backend, and
  production promotion remain blocked when not observed;
- advisory runtime evidence remains recommendation-only;
- marketplace invocation and shared-context exchange remain blocked until
  controlled runtime is authorized;
- production decision authority remains `0%`.

## v11.0 Product-Pack And Shared-Capability Foundation

The next phase should not reinterpret the v10 evidence as platform completion.
v10 is a pre-runtime governance foundation baseline.

v11 should align DIP with the long-term operating model:

- DIP is the neutral decision-governance foundation.
- EDI, ML, and future applications are product packs on DIP.
- Shared services are certified through DIP contracts before reuse.
- EDI contributes engineering-governance evidence but does not replace DIP's
  neutral governance store.
- Common infrastructure is governed and isolated; it is not hidden shared state.

Expected v11 scope:

- API-first modular platform architecture contract
- product-pack contract
- EDI engineering-governance product-pack fixture
- ML trading-decision product-pack fixture
- support-routing product-pack fixture
- shared-service certification checklist
- ML shared-capability inventory
- DIP governance-store contract
- runtime authority remains blocked
