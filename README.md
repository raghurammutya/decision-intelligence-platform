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
