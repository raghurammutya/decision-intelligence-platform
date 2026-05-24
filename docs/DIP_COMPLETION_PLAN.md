# DIP Completion Plan

Date: 2026-05-24

## Completion Target

DIP is complete for the current product phase when the first wedge is a usable
pre-runtime trust surface:

```text
decision spec -> capability registry -> capability graph -> policy preflight
  -> simulation -> decision diff -> approval -> case evidence -> replay
  -> release evidence -> governance evidence
```

This phase does not include runtime execution, marketplace runtime invocation,
direct production mutation, or live shared-context exchange.

## Operating Rule

EDI may observe DIP evidence, plan safe work, and ingest release artifacts. EDI
does not drive DIP product scope and is not the DIP runtime.

## Milestones

### v1.1 Governance Enforcement Parity

Status: complete on `v1.1.0-pre`.

Purpose: close the gap between governance policy and observed repository
enforcement.

Required evidence:

- required status checks observed
- one approving review observed
- CODEOWNER review required
- conversation resolution required
- admin enforcement enabled
- force pushes blocked
- branch deletions blocked
- runtime authority blocked

### v1.2 Product Review Surfaces

Purpose: make the trust loop reviewable without reading raw JSON.

Required evidence:

- decision review summary
- simulation evidence summary
- decision diff summary
- approval record summary
- case evidence summary
- replay evidence summary
- capability lineage summary
- runtime-blocked banner

### v1.3 Multi-Domain Proof

Purpose: prove that DIP contracts work across concrete decision domains without
becoming a generic automation builder.

Required domains:

- support ticket routing
- engineering review readiness
- operational risk triage

### v1.4 Capability Governance

Purpose: prove every composed decision knows exactly which capability versions
contributed to the result.

Required evidence:

- all required capabilities present
- exact versions resolved
- provenance recorded
- entitlement status recorded
- compatibility status recorded
- evaluation evidence recorded
- revoked/deprecated capabilities blocked by policy
- cost profile recorded

### v1.5 Shared Context Contracts

Purpose: prove products collaborate through governed semantic projections, not
direct database access or hidden shared state.

Required evidence:

- declared purpose
- TTL
- masking rules
- consent or approval requirement
- source lineage
- freshness and validity rules
- policy decision evidence
- explicit consumer and producer

### v2.0 Runtime Readiness Assessment

Purpose: assess what remains before runtime can be considered.

This is not runtime execution.

Runtime readiness remains blocked until all of the following are live evidence,
not fixture or contract evidence:

- external IdP authentication
- production durable case store
- promotion chain with approval and rollback evidence
- runtime control plane
- kill switch
- live observability
- entitlement enforcement
- cost accounting
- independent approval flow
- replay against production-like evidence

### v2.1 Governance Exception and Schema Stability

Purpose: keep the solo-maintainer GitHub workaround governed and prevent
contract drift while the platform remains pre-runtime.

The current GitHub repository has one available maintainer. Because GitHub
cannot provide independent reviewer assignment in that state, DIP may continue
to use a temporary review-count relaxation only as a governed exception.

Required exception evidence:

- solo-maintainer constraint declared
- independent human review availability declared false
- independent human review observation declared false
- CI success required before merge
- branch protection captured before and after relaxation
- review gate restored immediately after merge
- release acceptance artifact generated
- EDI observation required
- runtime and production authority remain blocked

Required schema stability evidence:

- frozen schema versions for every first-wedge contract
- explicit compatibility rules
- negative fixtures for blocked production authority and AI approval
- validation that negative fixtures continue to fail
- runtime authority remains explicit and denied by default

### v2.2 External Approval Boundary

Purpose: separate decision approval authority from GitHub code review and the
solo-maintainer merge exception.

This is not a live external approval integration. It defines the boundary and
evidence required before a live approval system can contribute to runtime
admission.

Required evidence:

- GitHub code review is not decision approval
- solo-maintainer merge exception is not decision approval
- decision approval remains required
- approval subject binding required
- approval role and scope required
- approval expiry required
- MFA evidence required
- approval audit export required
- AI approval blocked
- runtime and production authority remain blocked

### v2.3 Durable Case Store Adapter

Purpose: define the durable case store adapter boundary without claiming a
production storage backend.

This is not a live storage integration. It defines the contract required before
a production durable case store can be considered for runtime admission.

Required evidence:

- append-only writes required
- content-addressed records required
- manifest hash chain required
- deletes and record overwrites denied
- mutation detection required
- replay export required
- audit export required
- retention policy declared
- required adapter operations complete
- denied adapter operations complete
- production storage backend remains unobserved
- runtime and production authority remain blocked

### v2.4 Evidence Store Adapter Parity

Purpose: prove the durable case store adapter contract covers the concrete
pre-runtime operations needed by review, replay, and audit workflows.

This is not a production storage adapter. It computes operation parity from the
contract and committed evidence without invoking a runtime backend.

Required evidence:

- append case record operation declared and evidence-bound
- read case record operation declared and evidence-bound
- verify manifest chain operation declared and evidence-bound
- export replay pack operation declared and evidence-bound
- export audit pack operation declared and evidence-bound
- update/delete/manifest overwrite operations denied
- negative fixtures cover missing hash chain, delete-enabled behavior, and weak retention
- production storage backend remains unobserved
- runtime backend remains uninvoked
- runtime and production authority remain blocked

### v2.5 Policy Engine Hardening

Purpose: move from fixture-shaped policy preflight to a versioned deterministic
policy evaluator with explicit lifecycle, compatibility, and precedence
evidence.

This is not a runtime policy engine. It computes pre-runtime policy evidence
from versioned policy definitions and keeps AI override and runtime authority
blocked.

Required evidence:

- policy lifecycle status evaluated
- revoked policies rejected
- supported rule types declared and checked
- deterministic outcome precedence declared
- deny precedence enforced
- escalation outcome supported
- required evidence rules validated
- negative fixtures cover unknown rules, revoked policies, production authority claims, and missing evidence
- AI override remains blocked
- runtime and production authority remain blocked

### v2.6 External Approval Adapter Boundary

Purpose: define the external approval adapter contract without claiming a live
external approval system.

This is not a production approval integration. It defines the adapter
operations, evidence, lifecycle outcomes, admission controls, and audit
requirements needed before DIP can rely on an external decision approval
system.

Required evidence:

- approval request, approve, reject, expire, delegate, revoke, and audit export operations declared
- AI self-approval, requester self-approval, policy bypass, mutation, and runtime execution operations denied
- approval request evidence fields complete
- approval decision evidence fields complete
- approval lifecycle outcomes complete
- admission controls complete
- audit requirements complete
- adapter remains compatible with the external approval boundary
- live external approval system remains unobserved
- runtime and production authority remain blocked

### v2.7 Live Identity/RBAC Evidence

Purpose: observe live identity and repository RBAC evidence without claiming a
complete external IdP/MFA integration.

This uses the available GitHub identity and repository permission APIs as
pre-runtime evidence. It does not claim full enterprise IdP integration because
the available API path does not expose a usable MFA claim.

Required evidence:

- live provider authentication observed
- authenticated identity subject recorded
- repository permission observed
- permission satisfies approval-role threshold
- decision scope authorization recorded
- MFA claim requirement remains explicit
- MFA claim remains unobserved and blocked
- runtime and production authority remain blocked

### v2.8 Durable Evidence Backend Observation

Purpose: observe the durable evidence backend path without claiming production
storage or runtime backend invocation.

Required evidence:

- append-only case write observed
- content-addressed case record observed
- manifest-chain verification observed from backend evidence
- case record read observed
- replay export observed
- audit export observed
- delete and mutation operations denied
- retention policy observed
- backend health observed
- production storage backend remains unobserved
- runtime backend invocation remains blocked

### v2.9 Promotion Chain And Rollback Evidence

Purpose: bind release evidence to a source commit, immutable artifact digest,
build run, promotion chain, approval requirement, and rollback trail without
executing production deployment.

Required evidence:

- immutable artifact digest observed
- source commit bound
- build run id observed
- dev-test-staging-prod promotion chain declared
- promotion approval requirement recorded
- rollback criteria defined
- rollback artifact observed
- rollback evidence valid
- solo-maintainer exception recorded where independent review is unavailable
- production deployment remains unexecuted

### v3.0 Pre-Runtime GA Acceptance

Purpose: complete the first wedge as pre-runtime GA evidence while preserving the
runtime boundary.

Required evidence:

- governed decision review and simulation complete
- trust surface complete
- policy engine complete
- simulation and diff complete
- approval boundary complete
- live identity/RBAC observed with MFA claim still blocked
- durable evidence backend observed
- promotion chain and rollback evidence observed
- EDI observer evidence remains required
- runtime execution readiness remains `0%`
- production decision authority remains `0%`

### v3.1 Governance Closure

Purpose: close repository governance evidence while preserving the solo-maintainer
exception as an exception.

Required evidence:

- required status check observed
- one-review gate restored
- CODEOWNER gate restored
- admin enforcement observed
- conversation resolution observed
- force pushes and branch deletion blocked
- break-glass policy defined
- solo-maintainer exception recorded
- independent human review remains unobserved unless a second reviewer exists

### v3.2 External Identity Integration Boundary

Purpose: record the live identity/RBAC boundary and make the missing live IdP/MFA
claims explicit.

Required evidence:

- external identity contract valid
- GitHub RBAC observed
- approval permission and decision scope authorized
- live external IdP authentication remains blocked when not observed
- MFA claim remains blocked when not observed

### v3.3 External Approval System Boundary

Purpose: record decision approval system readiness without treating GitHub code
review or solo-maintainer merge exceptions as decision approval.

Required evidence:

- external approval boundary valid
- external approval adapter valid
- decision approval remains separate from code merge
- AI approval remains blocked
- live external approval provider remains blocked when not observed

### v3.4 Production Case Store Backend Boundary

Purpose: define production case-store backend requirements while keeping
production storage unclaimed until observed.

Required evidence:

- append-only writes valid
- content-addressed records valid
- manifest chain valid
- replay and audit export valid
- delete and mutation denial observed
- retention policy observed
- production storage backend remains blocked when not observed

### v3.5 Runtime Control Plane Design

Purpose: define runtime admission controls before runtime authority can be
granted.

Required evidence:

- policy gate
- approval gate
- kill switch
- entitlement check
- cost accounting
- observability trace
- lineage capture
- replay hook
- rollback path
- runtime authority grant remains blocked

### v3.6 Advisory Runtime Pilot

Purpose: prove advisory-only runtime evaluation from simulation evidence without
side effects.

Required evidence:

- advisory-only mode
- simulation evidence reused
- lineage capture observed
- policy and approval gates observed
- no side effects
- no production mutation
- production decision authority remains blocked

### v4.0 Limited Runtime Authority Gate

Purpose: complete the authority gate and explicitly block runtime authority until
all live prerequisites are observed.

Required evidence:

- runtime control-plane design valid
- advisory runtime pilot valid
- live external IdP/MFA readiness evaluated
- live external approval system readiness evaluated
- production case-store backend readiness evaluated
- blocked reasons recorded
- limited runtime authority not granted while prerequisites are missing

### v4.1-v6.0 Readiness Gates and Platform Hardening

Status: complete on `v10.0.0-pre` as evidence gates and assessments, not
production authority.

Purpose: complete the post-v4 readiness sequence while preserving the product
boundary that AI proposes and policy, approval, runtime controls, and evidence
decide.

Required evidence:

- v4.1 live identity evidence gate is evaluated from observed identity/RBAC and
  keeps authority blocked while live external IdP/MFA evidence is missing.
- v4.2 live approval provider gate is evaluated from the approval boundary and
  adapter contracts and keeps readiness blocked while no live provider is
  observed.
- v4.3 production case-store gate is evaluated from durable store/backend
  evidence and keeps readiness blocked while no production backend is observed.
- v4.4 release-promotion execution gate binds artifact digest, source commit,
  build run id, promotion chain, and rollback evidence while recording that prod
  deployment was not executed.
- v5.0 governed advisory runtime can produce recommendations only, with policy,
  approval, lineage, case evidence, and no side effects.
- v5.5 controlled-runtime execution gate is complete but does not authorize
  execution until live identity, live approval, and live case-store prerequisites
  pass.
- v6.0 platform-hardening assessment records isolation, marketplace governance,
  shared context, observability, cost, kill switch, rollback, backup/restore,
  incident response, and compliance-reporting controls while keeping platform
  production readiness false.

Runtime execution readiness and production decision authority remain `0%` until
those live prerequisites are observed and approved.

### v6.1-v9.0 Production Authority Readiness Gates

Status: complete on `v10.0.0-pre` as evidence gates and readiness review, not
production authority.

Purpose: finish the production authority review path without converting DIP into
a hidden runtime or granting production decision authority without live evidence.

Required evidence:

- v6.1 live identity authority contract is complete; live external IdP/MFA
  authority remains blocked when not observed.
- v6.2 live decision approval provider contract is complete; live approval
  provider readiness remains blocked when not observed.
- v6.3 production durable case-store contract is complete; production storage
  readiness remains blocked when no backend is observed.
- v6.4 production promotion-chain contract is complete; production promotion
  readiness remains blocked when no prod deployment has executed.
- v7.0 controlled-runtime pilot admission is complete; pilot authorization
  remains blocked until live identity, live approval, live case store, and
  promotion evidence pass.
- v7.5 marketplace runtime governance is complete; unrestricted marketplace
  execution remains denied and runtime invocation remains blocked.
- v8.0 shared-context runtime governance is complete; direct database access and
  hidden shared state remain denied and runtime context exchange remains blocked.
- v9.0 production authority readiness review is complete; production decision
  authority remains `0%` until every live prerequisite is observed and approved.

### v10.0 Completion Plan Execution Review

Status: complete on `v10.0.0-pre` as an autopilot execution review, not as live
production readiness.

Purpose: execute the nine-step completion plan end to end, record which steps
have complete governance gates, and explicitly block any live/runtime/production
claim whose prerequisite evidence is absent.

Required evidence:

- all nine plan steps are reviewed and recorded;
- every step has an evidence gate result;
- live completion remains blocked for unavailable IdP/MFA, approval provider,
  production durable case-store backend, production promotion execution,
  controlled runtime, marketplace invocation, shared-context exchange, limited
  authority, and production decision authority;
- AI approval, unrestricted marketplace execution, direct database access, and
  hidden production mutation remain blocked;
- runtime execution readiness and production decision authority remain `0%`.

## Completion Gate

The current phase is complete only if:

- DIP release acceptance passes.
- Runtime execution readiness remains `0%`.
- Production decision authority remains `0%`.
- AI remains limited to propose, summarize, compare, and explain.
- Policy, approval, and runtime controls remain authoritative.
- EDI is used only as an observer/evidence-ingestion aid.
