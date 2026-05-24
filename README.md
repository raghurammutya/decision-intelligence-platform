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
