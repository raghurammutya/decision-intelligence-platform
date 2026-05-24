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
    write_v0_2_evidence(root, version="v2.2.0-pre")
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
    release_lifecycle = load_json(root / "reports/trust-loop/release-lifecycle.json")
    external_identity = load_json(root / "reports/trust-loop/external-identity.json")
    durable_store = load_json(root / "reports/trust-loop/durable-evidence-store.json")
    capability_governance = load_json(root / "reports/trust-loop/capability-governance.json")
    shared_context = load_json(root / "reports/trust-loop/shared-context-governance.json")
    solo_exception = load_json(root / "reports/trust-loop/solo-maintainer-exception.json")
    schema_stability = load_json(root / "reports/trust-loop/schema-stability.json")
    external_approval = load_json(root / "reports/trust-loop/external-approval-boundary.json")
    runtime_readiness = load_json(root / "reports/trust-loop/runtime-readiness-assessment.json")
    product_surface = load_json(root / "reports/trust-loop/product-review-surface.json")
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
            "evaluate_release_lifecycle_policy",
            "evaluate_external_identity_contract",
            "evaluate_durable_evidence_store_contract",
            "evaluate_capability_governance",
            "evaluate_shared_context_contract",
            "evaluate_solo_maintainer_exception",
            "evaluate_schema_stability",
            "evaluate_external_approval_boundary",
            "assess_runtime_readiness",
            "materialize_product_review_surface",
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
        "release_lifecycle_policy_observed": release_lifecycle.get("computed") is True,
        "release_lifecycle_valid": release_lifecycle.get("release_lifecycle_valid") is True,
        "external_identity_contract_observed": external_identity.get("computed") is True,
        "external_identity_contract_valid": external_identity.get("external_identity_contract_valid") is True,
        "live_external_identity_provider_authenticated": external_identity.get("live_provider_authenticated") is True,
        "durable_evidence_store_policy_observed": durable_store.get("computed") is True,
        "durable_store_contract_valid": durable_store.get("durable_store_contract_valid") is True,
        "production_storage_backend_observed": durable_store.get("production_storage_backend_observed") is True,
        "capability_governance_observed": capability_governance.get("computed") is True,
        "capability_governance_valid": capability_governance.get("capability_governance_valid") is True,
        "shared_context_contract_observed": shared_context.get("computed") is True,
        "shared_context_contract_valid": shared_context.get("shared_context_contract_valid") is True,
        "solo_maintainer_exception_observed": solo_exception.get("computed") is True,
        "solo_maintainer_exception_valid": solo_exception.get("exception_valid") is True,
        "independent_human_review_observed": solo_exception.get("independent_human_review_observed") is True,
        "schema_stability_observed": schema_stability.get("computed") is True,
        "schema_stability_valid": schema_stability.get("schema_stability_valid") is True,
        "negative_fixtures_valid": schema_stability.get("negative_fixtures_valid") is True,
        "external_approval_boundary_observed": external_approval.get("computed") is True,
        "external_approval_boundary_valid": external_approval.get("external_approval_boundary_valid") is True,
        "live_external_approval_system_observed": external_approval.get("live_approval_system_observed") is True,
        "decision_approval_separate_from_code_merge": external_approval.get(
            "decision_approval_separate_from_code_merge"
        )
        is True,
        "runtime_readiness_assessment_observed": runtime_readiness.get("computed") is True,
        "runtime_readiness_percent": runtime_readiness.get("runtime_readiness_percent", 0.0),
        "product_review_surface_observed": product_surface.get("computed") is True,
        "product_review_surface_count": product_surface.get("surface_count", 0),
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
        "blocked_claims": [
            "runtime integration is authorized",
            "production decision execution is authorized",
            "independent human review was observed for solo-maintainer merges",
            "live external decision approval system is observed",
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
        "release_lifecycle": release_lifecycle,
        "external_identity": external_identity,
        "durable_store": durable_store,
        "capability_governance": capability_governance,
        "shared_context": shared_context,
        "solo_exception": solo_exception,
        "schema_stability": schema_stability,
        "external_approval": external_approval,
        "runtime_readiness": runtime_readiness,
        "product_surface": product_surface,
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
    write_json(out / "release-lifecycle.json", payload["release_lifecycle"])
    write_json(out / "external-identity.json", payload["external_identity"])
    write_json(out / "durable-evidence-store.json", payload["durable_store"])
    write_json(out / "capability-governance.json", payload["capability_governance"])
    write_json(out / "shared-context-governance.json", payload["shared_context"])
    write_json(out / "solo-maintainer-exception.json", payload["solo_exception"])
    write_json(out / "schema-stability.json", payload["schema_stability"])
    write_json(out / "external-approval-boundary.json", payload["external_approval"])
    write_json(out / "runtime-readiness-assessment.json", payload["runtime_readiness"])
    write_json(out / "product-review-surface.json", payload["product_surface"])
    write_json(out / "replay-result.json", payload["replay_result"])
    write_json(out / "trust-loop-run.json", payload["trust_loop_run"])
    write_json(out / "dip-mvp-acceptance.json", payload["acceptance"])
    return payload
