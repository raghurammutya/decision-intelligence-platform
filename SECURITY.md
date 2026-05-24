# Security Policy

## Supported Scope

DIP is currently a pre-runtime governed decision review and simulation
platform. Security work must preserve the current authority boundary:

- runtime integration remains blocked by default
- production decision authority remains blocked by default
- AI must not approve, bypass policy, or mutate production behavior
- every governed decision artifact must remain evidence-backed and replayable

## Reporting a Vulnerability

Report suspected vulnerabilities privately through GitHub private vulnerability
reporting when available, or to the repository owner directly if private
reporting is not available.

Do not open public issues containing secrets, exploit details, production host
names, credentials, customer data, or unpublished bypass techniques.

## Handling Expectations

- Confirm receipt and triage severity before implementation.
- Keep fixes scoped to the governed platform boundary.
- Validate with `./scripts/validate.sh`.
- Preserve release evidence and branch protection evidence.
- Record any single-maintainer exception explicitly.

## Runtime Boundary

Security fixes must not be used as a path to grant runtime authority. Runtime
authority can only be introduced through explicit evidence, approval, lineage,
replay, and control gates.

