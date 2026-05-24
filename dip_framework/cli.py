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
        "solo_maintainer_governance_exception",
        "schema_stability_policy",
        "external_approval_boundary",
        "external_approval_adapter",
        "durable_case_store_adapter",
        "shared_context_contract",
        "case_evidence",
        "replay",
        "api_resource_model",
        "product_pack_registry",
        "shared_service_certification",
        "ml_shared_capability_inventory",
        "adapter_evidence_contract",
        "governance_store_contract",
        "runtime_authority_blocked_model",
        "shared_capability_certification_states",
        "product_pack_contracts",
        "rest_api_contracts",
        "event_recovery_contract",
        "certification_evidence_packs",
        "product_pack_admission",
        "openapi_skeleton",
        "event_recovery_fixtures",
        "governance_store_logical_schema",
        "canonical_openapi_contract",
        "product_pack_contract_kit",
        "adapter_evidence_contract_kit",
        "governance_store_logical_api",
        "event_recovery_contract_v2",
        "shared_capability_certification_workflow",
        "runtime_authority_gate_contract",
        "cost_usage_evidence_contract",
        "shared_context_semantic_projection_contract",
        "product_pack_developer_kit",
        "contract_compatibility_versioning",
        "policy_test_pack_framework",
        "product_pack_cli_scaffold_contract",
        "case_evidence_query_contract",
        "governance_dashboard_data_contract",
        "product_pack_authoring_ux_contract",
        "governance_review_queue_contract",
        "capability_lineage_explorer_contract",
        "replay_workspace_contract",
        "v40_usability_acceptance_pack_contract",
    ])
    validate_one_parser.add_argument("path")
    validate_one_parser.add_argument("--json", action="store_true")
    validate_one_parser.set_defaults(func=validate_one)

    trust_loop_parser = subparsers.add_parser("trust-loop", help="Write pre-runtime trust-loop evidence.")
    trust_loop_parser.add_argument("--out", default="reports/trust-loop")
    trust_loop_parser.add_argument("--json", action="store_true")
    trust_loop_parser.set_defaults(func=trust_loop)

    release_parser = subparsers.add_parser("release-pack", help="Write DIP release acceptance evidence.")
    release_parser.add_argument("--version", default="v40.0.0-pre")
    release_parser.add_argument("--source-commit", default="local-validation")
    release_parser.add_argument("--json", action="store_true")
    release_parser.set_defaults(func=release_pack)

    args = parser.parse_args()
    return args.func(args)
