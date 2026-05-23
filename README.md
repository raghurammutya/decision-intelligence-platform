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
python3 -m dip_framework validate
python3 -m unittest discover -s tests -p 'test_*.py'
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
