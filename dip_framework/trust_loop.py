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
    write_v0_2_evidence(root, version="v6.0.0-pre")
    validation = validate_default_examples(root)
    case_evidence = load_json(root / "reports/trust-loop/case-evidence.json")
    replay_result = load_json(root / "reports/trust-loop/replay-result.json")
    approval_record = load_json(root / "reports/trust-loop/approval-record.json")
    policy_engine = load_json(root / "reports/trust-loop/computed-policy-engine.json")
    computed_preflight = load_json(root / "reports/trust-loop/computed-policy-preflight.json")
    computed_simulation = load_json(root / "reports/trust-loop/computed-simulation-evidence.json")
    computed_decision_diff = load_json(root / "reports/trust-loop/computed-decision-diff.json")
    case_manifest = load_json(root / "reports/trust-loop/case-manifest.json")
    durable_manifest = load_json(root / "reports/trust-loop/durable-case-manifest.json")
    approval_authority = load_json(root / "reports/trust-loop/approval-authority.json")
    repository_governance = load_json(root / "reports/trust-loop/repository-governance.json")
    release_lifecycle = load_json(root / "reports/trust-loop/release-lifecycle.json")
    external_identity = load_json(root / "reports/trust-loop/external-identity.json")
    live_identity_rbac = load_json(root / "reports/trust-loop/live-identity-rbac.json")
    durable_store = load_json(root / "reports/trust-loop/durable-evidence-store.json")
    capability_governance = load_json(root / "reports/trust-loop/capability-governance.json")
    shared_context = load_json(root / "reports/trust-loop/shared-context-governance.json")
    solo_exception = load_json(root / "reports/trust-loop/solo-maintainer-exception.json")
    schema_stability = load_json(root / "reports/trust-loop/schema-stability.json")
    external_approval = load_json(root / "reports/trust-loop/external-approval-boundary.json")
    external_approval_adapter = load_json(root / "reports/trust-loop/external-approval-adapter.json")
    durable_adapter = load_json(root / "reports/trust-loop/durable-case-store-adapter.json")
    adapter_parity = load_json(root / "reports/trust-loop/evidence-store-adapter-parity.json")
    durable_backend = load_json(root / "reports/trust-loop/durable-evidence-backend.json")
    promotion_chain = load_json(root / "reports/trust-loop/release-promotion-chain.json")
    pre_runtime_ga = load_json(root / "reports/trust-loop/pre-runtime-ga-acceptance.json")
    governance_closure = load_json(root / "reports/trust-loop/governance-closure.json")
    identity_integration = load_json(root / "reports/trust-loop/external-identity-integration.json")
    approval_system = load_json(root / "reports/trust-loop/external-approval-system.json")
    production_case_store = load_json(root / "reports/trust-loop/production-case-store-backend.json")
    runtime_control_plane = load_json(root / "reports/trust-loop/runtime-control-plane.json")
    advisory_pilot = load_json(root / "reports/trust-loop/advisory-runtime-pilot.json")
    runtime_authority_gate = load_json(root / "reports/trust-loop/limited-runtime-authority-gate.json")
    live_identity_gate = load_json(root / "reports/trust-loop/live-identity-evidence-gate.json")
    live_approval_gate = load_json(root / "reports/trust-loop/live-approval-provider-gate.json")
    production_case_store_gate = load_json(root / "reports/trust-loop/production-case-store-gate.json")
    promotion_execution_gate = load_json(root / "reports/trust-loop/release-promotion-execution-gate.json")
    governed_advisory_runtime = load_json(root / "reports/trust-loop/governed-advisory-runtime.json")
    controlled_runtime_gate = load_json(root / "reports/trust-loop/controlled-runtime-execution-gate.json")
    platform_hardening = load_json(root / "reports/trust-loop/platform-hardening-assessment.json")
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
            "compute_policy_engine",
            "compute_policy_preflight",
            "compute_simulation_evidence",
            "compute_decision_diff",
            "write_durable_case_manifest",
            "bind_approval_to_manifest",
            "evaluate_identity_rbac_authority",
            "evaluate_repository_governance_policy",
            "evaluate_release_lifecycle_policy",
            "evaluate_external_identity_contract",
            "evaluate_live_identity_rbac",
            "evaluate_durable_evidence_store_contract",
            "evaluate_capability_governance",
            "evaluate_shared_context_contract",
            "evaluate_solo_maintainer_exception",
            "evaluate_schema_stability",
            "evaluate_external_approval_boundary",
            "evaluate_external_approval_adapter",
            "evaluate_durable_case_store_adapter",
            "evaluate_evidence_store_adapter_parity",
            "observe_durable_evidence_backend",
            "evaluate_release_promotion_chain",
            "assess_runtime_readiness",
            "evaluate_pre_runtime_ga",
            "evaluate_governance_closure",
            "evaluate_external_identity_integration",
            "evaluate_external_approval_system",
            "evaluate_production_case_store_backend",
            "evaluate_runtime_control_plane",
            "evaluate_advisory_runtime_pilot",
            "evaluate_limited_runtime_authority_gate",
            "evaluate_live_identity_evidence_gate",
            "evaluate_live_approval_provider_gate",
            "evaluate_production_case_store_gate",
            "evaluate_release_promotion_execution_gate",
            "evaluate_governed_advisory_runtime",
            "evaluate_controlled_runtime_execution_gate",
            "evaluate_platform_hardening_assessment",
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
        "computed_policy_engine_observed": policy_engine.get("computed") is True,
        "computed_policy_engine_result": policy_engine.get("result"),
        "policy_engine_valid": policy_engine.get("policy_engine_valid") is True,
        "policy_engine_deny_precedence_enforced": policy_engine.get("deny_precedence_enforced") is True,
        "policy_engine_escalate_outcome_supported": policy_engine.get("escalate_outcome_supported") is True,
        "policy_engine_compatibility_valid": policy_engine.get("policy_compatibility_valid") is True,
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
        "live_identity_rbac_observed": live_identity_rbac.get("computed") is True,
        "live_identity_rbac_valid": live_identity_rbac.get("live_identity_rbac_valid") is True,
        "live_identity_rbac_permission_sufficient": live_identity_rbac.get("permission_satisfies_approval_role")
        is True,
        "live_identity_rbac_decision_scope_authorized": live_identity_rbac.get("decision_scope_authorized") is True,
        "live_identity_rbac_mfa_claim_observed": live_identity_rbac.get("mfa_claim_observed") is True,
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
        "external_approval_adapter_observed": external_approval_adapter.get("computed") is True,
        "external_approval_adapter_valid": external_approval_adapter.get("external_approval_adapter_valid") is True,
        "external_approval_adapter_required_operations_complete": external_approval_adapter.get(
            "required_operations_complete"
        )
        is True,
        "external_approval_adapter_denied_operations_complete": external_approval_adapter.get(
            "denied_operations_complete"
        )
        is True,
        "external_approval_adapter_decision_lifecycle_complete": external_approval_adapter.get(
            "decision_lifecycle_complete"
        )
        is True,
        "external_approval_adapter_live_system_observed": external_approval_adapter.get(
            "live_approval_system_observed"
        )
        is True,
        "external_approval_adapter_ai_approval_allowed": external_approval_adapter.get("ai_approval_allowed") is True,
        "durable_case_store_adapter_observed": durable_adapter.get("computed") is True,
        "durable_case_store_adapter_valid": durable_adapter.get("adapter_boundary_valid") is True,
        "adapter_production_storage_backend_observed": durable_adapter.get("production_storage_backend_observed")
        is True,
        "evidence_store_adapter_parity_observed": adapter_parity.get("computed") is True,
        "evidence_store_adapter_parity_valid": adapter_parity.get("adapter_parity_valid") is True,
        "adapter_runtime_backend_invoked": adapter_parity.get("runtime_backend_invoked") is True,
        "durable_evidence_backend_observed": durable_backend.get("computed") is True,
        "durable_evidence_backend_valid": durable_backend.get("durable_evidence_backend_valid") is True,
        "durable_backend_runtime_backend_invoked": durable_backend.get("runtime_backend_invoked") is True,
        "release_promotion_chain_observed": promotion_chain.get("computed") is True,
        "release_promotion_chain_valid": promotion_chain.get("release_promotion_chain_valid") is True,
        "prod_deployment_executed": promotion_chain.get("prod_deployment_executed") is True,
        "pre_runtime_ga_observed": pre_runtime_ga.get("computed") is True,
        "pre_runtime_ga_valid": pre_runtime_ga.get("pre_runtime_ga_valid") is True,
        "v3_1_governance_closure_valid": governance_closure.get("governance_closure_valid") is True,
        "v3_2_external_identity_boundary_valid": identity_integration.get("external_identity_boundary_valid") is True,
        "v3_2_external_identity_live_ready": identity_integration.get("external_identity_live_ready") is True,
        "v3_2_mfa_claim_observed": identity_integration.get("mfa_claim_observed") is True,
        "v3_3_external_approval_system_boundary_valid": approval_system.get(
            "external_approval_system_boundary_valid"
        )
        is True,
        "v3_3_external_approval_system_live_ready": approval_system.get("external_approval_system_live_ready")
        is True,
        "v3_4_production_case_store_contract_ready": production_case_store.get(
            "production_case_store_contract_ready"
        )
        is True,
        "v3_4_production_case_store_live_ready": production_case_store.get("production_case_store_live_ready")
        is True,
        "v3_5_runtime_control_plane_design_valid": runtime_control_plane.get(
            "runtime_control_plane_design_valid"
        )
        is True,
        "v3_5_runtime_authority_grant_allowed": runtime_control_plane.get("runtime_authority_grant_allowed")
        is True,
        "v3_6_advisory_runtime_pilot_valid": advisory_pilot.get("advisory_runtime_pilot_valid") is True,
        "v3_6_advisory_side_effects_executed": advisory_pilot.get("side_effects_executed") is True,
        "v4_0_limited_runtime_authority_gate_complete": runtime_authority_gate.get(
            "limited_runtime_authority_gate_complete"
        )
        is True,
        "v4_0_limited_runtime_authority_granted": runtime_authority_gate.get(
            "limited_runtime_authority_granted"
        )
        is True,
        "v4_1_live_identity_evidence_gate_complete": live_identity_gate.get(
            "live_identity_evidence_gate_complete"
        )
        is True,
        "v4_1_live_identity_authority_ready": live_identity_gate.get("live_identity_authority_ready") is True,
        "v4_1_mfa_claim_observed": live_identity_gate.get("mfa_claim_observed") is True,
        "v4_2_live_approval_provider_gate_complete": live_approval_gate.get(
            "live_approval_provider_gate_complete"
        )
        is True,
        "v4_2_live_approval_provider_ready": live_approval_gate.get("live_approval_provider_ready") is True,
        "v4_2_ai_approval_allowed": live_approval_gate.get("ai_approval_allowed") is True,
        "v4_3_production_case_store_gate_complete": production_case_store_gate.get(
            "production_case_store_gate_complete"
        )
        is True,
        "v4_3_production_case_store_live_ready": production_case_store_gate.get(
            "production_case_store_live_ready"
        )
        is True,
        "v4_4_release_promotion_execution_gate_complete": promotion_execution_gate.get(
            "release_promotion_execution_gate_complete"
        )
        is True,
        "v4_4_prod_deployment_executed": promotion_execution_gate.get("prod_deployment_executed") is True,
        "v5_0_governed_advisory_runtime_complete": governed_advisory_runtime.get(
            "governed_advisory_runtime_complete"
        )
        is True,
        "v5_0_runtime_recommendation_only": governed_advisory_runtime.get("runtime_recommendation_only") is True,
        "v5_0_side_effects_executed": governed_advisory_runtime.get("side_effects_executed") is True,
        "v5_5_controlled_runtime_execution_gate_complete": controlled_runtime_gate.get(
            "controlled_runtime_execution_gate_complete"
        )
        is True,
        "v5_5_controlled_runtime_execution_authorized": controlled_runtime_gate.get(
            "controlled_runtime_execution_authorized"
        )
        is True,
        "v6_0_platform_hardening_assessment_complete": platform_hardening.get(
            "hardening_assessment_complete"
        )
        is True,
        "v6_0_platform_production_ready": platform_hardening.get("platform_production_ready") is True,
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
            "live external approval adapter system is observed",
            "live external identity MFA claim is observed",
            "production durable case store backend is observed",
            "limited runtime authority is granted",
            "live identity authority is ready",
            "live approval provider is ready",
            "production case store live backend is ready",
            "controlled runtime execution is authorized",
            "platform production readiness is complete",
        ],
    }
    return {
        "validation": validation,
        "case_evidence": case_evidence,
        "policy_engine": policy_engine,
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
        "live_identity_rbac": live_identity_rbac,
        "durable_store": durable_store,
        "capability_governance": capability_governance,
        "shared_context": shared_context,
        "solo_exception": solo_exception,
        "schema_stability": schema_stability,
        "external_approval": external_approval,
        "external_approval_adapter": external_approval_adapter,
        "durable_adapter": durable_adapter,
        "adapter_parity": adapter_parity,
        "durable_backend": durable_backend,
        "promotion_chain": promotion_chain,
        "pre_runtime_ga": pre_runtime_ga,
        "governance_closure": governance_closure,
        "identity_integration": identity_integration,
        "approval_system": approval_system,
        "production_case_store": production_case_store,
        "runtime_control_plane": runtime_control_plane,
        "advisory_pilot": advisory_pilot,
        "runtime_authority_gate": runtime_authority_gate,
        "live_identity_gate": live_identity_gate,
        "live_approval_gate": live_approval_gate,
        "production_case_store_gate": production_case_store_gate,
        "promotion_execution_gate": promotion_execution_gate,
        "governed_advisory_runtime": governed_advisory_runtime,
        "controlled_runtime_gate": controlled_runtime_gate,
        "platform_hardening": platform_hardening,
        "runtime_readiness": runtime_readiness,
        "product_surface": product_surface,
        "replay_result": replay_result,
        "trust_loop_run": trust_loop_run,
        "acceptance": acceptance,
    }


def write_trust_loop(out: Path, root: Path = ROOT) -> dict[str, Any]:
    payload = build_trust_loop(root)
    write_json(out / "validation.json", payload["validation"])
    write_json(out / "computed-policy-engine.json", payload["policy_engine"])
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
    write_json(out / "live-identity-rbac.json", payload["live_identity_rbac"])
    write_json(out / "durable-evidence-store.json", payload["durable_store"])
    write_json(out / "capability-governance.json", payload["capability_governance"])
    write_json(out / "shared-context-governance.json", payload["shared_context"])
    write_json(out / "solo-maintainer-exception.json", payload["solo_exception"])
    write_json(out / "schema-stability.json", payload["schema_stability"])
    write_json(out / "external-approval-boundary.json", payload["external_approval"])
    write_json(out / "external-approval-adapter.json", payload["external_approval_adapter"])
    write_json(out / "durable-case-store-adapter.json", payload["durable_adapter"])
    write_json(out / "evidence-store-adapter-parity.json", payload["adapter_parity"])
    write_json(out / "durable-evidence-backend.json", payload["durable_backend"])
    write_json(out / "release-promotion-chain.json", payload["promotion_chain"])
    write_json(out / "pre-runtime-ga-acceptance.json", payload["pre_runtime_ga"])
    write_json(out / "governance-closure.json", payload["governance_closure"])
    write_json(out / "external-identity-integration.json", payload["identity_integration"])
    write_json(out / "external-approval-system.json", payload["approval_system"])
    write_json(out / "production-case-store-backend.json", payload["production_case_store"])
    write_json(out / "runtime-control-plane.json", payload["runtime_control_plane"])
    write_json(out / "advisory-runtime-pilot.json", payload["advisory_pilot"])
    write_json(out / "limited-runtime-authority-gate.json", payload["runtime_authority_gate"])
    write_json(out / "runtime-readiness-assessment.json", payload["runtime_readiness"])
    write_json(out / "product-review-surface.json", payload["product_surface"])
    write_json(out / "replay-result.json", payload["replay_result"])
    write_json(out / "trust-loop-run.json", payload["trust_loop_run"])
    write_json(out / "dip-mvp-acceptance.json", payload["acceptance"])
    return payload
