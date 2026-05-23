# Codex Instructions

This repository is the standalone Decision Intelligence Platform implementation.

## Boundaries

- Keep the first wedge pre-runtime.
- Do not add production decision execution without explicit approval.
- Do not add marketplace runtime invocation without explicit approval.
- Do not add shared context runtime exchange without explicit approval.
- Do not store secrets in this repository.

## Required Validation

```bash
python3 -m dip_framework validate
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Relationship To EDI

EDI governs the construction and maturity of this repository. EDI is not the DIP
runtime.
