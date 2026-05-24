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

## Completion Gate

The current phase is complete only if:

- DIP release acceptance passes.
- Runtime execution readiness remains `0%`.
- Production decision authority remains `0%`.
- AI remains limited to propose, summarize, compare, and explain.
- Policy, approval, and runtime controls remain authoritative.
- EDI is used only as an observer/evidence-ingestion aid.
