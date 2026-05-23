"""Pre-runtime trust-loop materialization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dip_framework.contracts import ROOT, load_json, validate_default_examples
from dip_framework.v02 import write_v0_2_evidence


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_trust_loop(root: Path = ROOT) -> dict[str, Any]:
    write_v0_2_evidence(root, version="v0.7.0-pre")
    validation = validate_default_examples(root)
    case_evidence = load_json(root / "reports/trust-loop/case-evidence.json")
    replay_result = load_json(root / "reports/trust-loop/replay-result.json")
    approval_record = load_json(root / "reports/trust-loop/approval-record.json")
    computed_preflight = load_json(root / "reports/trust-loop/computed-policy-preflight.json")
    computed_simulation = load_json(root / "reports/trust-loop/computed-simulation-evidence.json")
    computed_decision_diff = load_json(root / "reports/trust-loop/computed-decision-diff.json")
    case_manifest = load_json(root / "reports/trust-loop/case-manifest.json")
    durable_manifest = load_json(root / "reports/trust-loop/durable-case-manifest.json")
    approval_authority = load_json(root / "reports/trust-loop/approval-authority.json")
    repository_governance = load_json(root / "reports/trust-loop/repository-governance.json")
    trust_loop_run = {
        "schema_version": "trust-loop-run/v1",
        "run_id": "trust-loop-support-ticket-routing-1",
        "decision_id": "support-ticket-routing",
        "decision_version": "1.0.0",
        "completed_steps": [
            "validate_spec",
            "load_capability_registry",
            "compute_policy_preflight",
            "compute_simulation_evidence",
            "compute_decision_diff",
            "write_durable_case_manifest",
            "bind_approval_to_manifest",
            "evaluate_identity_rbac_authority",
            "evaluate_repository_governance_policy",
            "write_case_evidence",
            "replay_from_manifest",
        ],
        "runtime_execution_requested": False,
        "case_evidence_ref": "case-evidence.json",
        "replay_result_ref": "replay-result.json",
    }
    acceptance = {
        "schema_version": "dip-mvp-acceptance/v1",
        "acceptance_id": "dip-mvp-acceptance-1",
        "trust_loop_complete": validation["passed"],
        "case_evidence_complete": bool(case_evidence.get("case_id")),
        "computed_policy_preflight_observed": computed_preflight.get("computed") is True,
        "computed_simulation_observed": computed_simulation.get("computed") is True,
        "computed_simulation_case_count": computed_simulation.get("case_count", 0),
        "computed_simulation_domain_count": computed_simulation.get("domain_count", 0),
        "computed_decision_diff_observed": computed_decision_diff.get("computed") is True,
        "computed_decision_diff_changed_outcomes": computed_decision_diff.get("changed_outcome_count", 0),
        "case_manifest_valid": case_manifest.get("append_only_required") is True and case_manifest.get("mutable") is False,
        "durable_case_manifest_observed": bool(durable_manifest.get("manifest_id")),
        "durable_case_manifest_valid": durable_manifest.get("chain_valid") is True
        and durable_manifest.get("mutable") is False,
        "case_mutation_detected": durable_manifest.get("mutation_detected") is True,
        "replay_evidence_complete": replay_result.get("manifest_replay_valid") is True,
        "approval_bound_to_manifest": approval_record.get("approval_bound_to_manifest") is True,
        "approval_role_binding_valid": approval_record.get("role_binding_valid") is True,
        "approval_authority_evaluated": approval_authority.get("computed") is True,
        "approval_authority_valid": approval_authority.get("approval_authority_valid") is True,
        "external_identity_provider_observed": approval_authority.get("external_identity_provider_observed") is True,
        "repository_governance_policy_observed": repository_governance.get("computed") is True,
        "admin_enforcement_required": repository_governance.get("admin_enforcement_required") is True,
        "break_glass_policy_defined": repository_governance.get("break_glass_policy_defined") is True,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
        "blocked_claims": [
            "runtime integration is authorized",
            "production decision execution is authorized",
        ],
    }
    return {
        "validation": validation,
        "case_evidence": case_evidence,
        "computed_preflight": computed_preflight,
        "computed_simulation": computed_simulation,
        "computed_decision_diff": computed_decision_diff,
        "case_manifest": case_manifest,
        "durable_manifest": durable_manifest,
        "approval_record": approval_record,
        "approval_authority": approval_authority,
        "repository_governance": repository_governance,
        "replay_result": replay_result,
        "trust_loop_run": trust_loop_run,
        "acceptance": acceptance,
    }


def write_trust_loop(out: Path, root: Path = ROOT) -> dict[str, Any]:
    payload = build_trust_loop(root)
    write_json(out / "validation.json", payload["validation"])
    write_json(out / "computed-policy-preflight.json", payload["computed_preflight"])
    write_json(out / "computed-simulation-evidence.json", payload["computed_simulation"])
    write_json(out / "computed-decision-diff.json", payload["computed_decision_diff"])
    write_json(out / "case-evidence.json", payload["case_evidence"])
    write_json(out / "case-manifest.json", payload["case_manifest"])
    write_json(out / "durable-case-manifest.json", payload["durable_manifest"])
    write_json(out / "approval-record.json", payload["approval_record"])
    write_json(out / "approval-authority.json", payload["approval_authority"])
    write_json(out / "repository-governance.json", payload["repository_governance"])
    write_json(out / "replay-result.json", payload["replay_result"])
    write_json(out / "trust-loop-run.json", payload["trust_loop_run"])
    write_json(out / "dip-mvp-acceptance.json", payload["acceptance"])
    return payload
