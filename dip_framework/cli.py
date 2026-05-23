"""CLI for the DIP pre-runtime trust loop."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from dip_framework.contracts import ROOT, validate_default_examples, validate_file
from dip_framework.trust_loop import write_trust_loop
from dip_framework.v02 import write_v0_2_evidence


def print_json(payload: dict) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def validate(args: argparse.Namespace) -> int:
    result = validate_default_examples(ROOT)
    if args.json:
        print_json(result)
    else:
        print(f"validation_passed={result['passed']}")
        print(f"passed={result['passed_count']}/{result['record_count']}")
    return 0 if result["passed"] else 1


def validate_one(args: argparse.Namespace) -> int:
    result = validate_file(args.kind, Path(args.path))
    if args.json:
        print_json(result)
    else:
        print(f"{args.kind}_valid={result['passed']}")
    return 0 if result["passed"] else 1


def trust_loop(args: argparse.Namespace) -> int:
    out = Path(args.out)
    result = write_trust_loop(out, ROOT)
    if args.json:
        print_json(
            {
                "trust_loop_complete": result["acceptance"]["trust_loop_complete"],
                "runtime_execution_requested": result["trust_loop_run"]["runtime_execution_requested"],
                "out": str(out),
            }
        )
    else:
        print(f"wrote={out}")
        print(f"trust_loop_complete={result['acceptance']['trust_loop_complete']}")
        print(f"runtime_execution_requested={result['trust_loop_run']['runtime_execution_requested']}")
    return 0 if result["acceptance"]["trust_loop_complete"] else 1


def release_pack(args: argparse.Namespace) -> int:
    result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", args.version, args.source_commit)
    if args.json:
        print_json(result["release"])
    else:
        print(f"release_version={result['release']['release_version']}")
        print(f"release_acceptance_passed={result['release']['release_acceptance_passed']}")
        print(f"runtime_integration_authorized={result['release']['runtime_integration_authorized']}")
    return 0 if result["release"]["release_acceptance_passed"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate all bundled examples.")
    validate_parser.add_argument("--json", action="store_true")
    validate_parser.set_defaults(func=validate)

    validate_one_parser = subparsers.add_parser("validate-file", help="Validate one file by kind.")
    validate_one_parser.add_argument("kind", choices=[
        "decision_spec",
        "capability_registry",
        "policy_definitions",
        "preflight",
        "simulation",
        "decision_diff",
        "approval",
        "identity_rbac_registry",
        "repository_governance_policy",
        "release_lifecycle_policy",
        "external_identity_evidence",
        "durable_evidence_store_policy",
        "case_evidence",
        "replay",
    ])
    validate_one_parser.add_argument("path")
    validate_one_parser.add_argument("--json", action="store_true")
    validate_one_parser.set_defaults(func=validate_one)

    trust_loop_parser = subparsers.add_parser("trust-loop", help="Write pre-runtime trust-loop evidence.")
    trust_loop_parser.add_argument("--out", default="reports/trust-loop")
    trust_loop_parser.add_argument("--json", action="store_true")
    trust_loop_parser.set_defaults(func=trust_loop)

    release_parser = subparsers.add_parser("release-pack", help="Write DIP release acceptance evidence.")
    release_parser.add_argument("--version", default="v1.0.0-pre")
    release_parser.add_argument("--source-commit", default="local-validation")
    release_parser.add_argument("--json", action="store_true")
    release_parser.set_defaults(func=release_pack)

    args = parser.parse_args()
    return args.func(args)
