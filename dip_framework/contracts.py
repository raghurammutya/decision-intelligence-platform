"""Contract validation for the DIP pre-runtime trust loop."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


REQUIRED = {
    "decision_spec": [
        "schema_version",
        "decision_id",
        "decision_version",
        "owner",
        "environment_scope",
        "intent",
        "inputs",
        "capability_requirements",
        "decision_logic",
        "outputs",
        "side_effects",
        "risk",
        "approval",
        "simulation",
        "evidence_requirements",
        "source_labels",
    ],
    "capability_registry": ["schema_version", "capabilities"],
    "preflight": [
        "schema_version",
        "preflight_id",
        "decision_id",
        "decision_version",
        "result",
        "required_approvals",
        "ai_override_allowed",
    ],
    "policy_definitions": [
        "schema_version",
        "policy_set_id",
        "policy_set_version",
        "policies",
    ],
    "simulation": [
        "schema_version",
        "simulation_run_id",
        "decision_id",
        "decision_version",
        "baseline_decision_version",
        "case_set",
        "changed_outcome_count",
        "side_effects_requested",
        "decision_diff_ref",
    ],
    "decision_diff": [
        "schema_version",
        "diff_id",
        "decision_id",
        "from_decision_version",
        "to_decision_version",
        "changed_outcome_count",
    ],
    "approval": [
        "schema_version",
        "approval_id",
        "decision_id",
        "decision_version",
        "approver_identity",
        "decision",
        "approval_reason",
        "ai_approved",
    ],
    "identity_rbac_registry": [
        "schema_version",
        "registry_id",
        "registry_version",
        "source_boundary",
        "external_identity_provider_observed",
        "roles",
        "identities",
    ],
    "repository_governance_policy": [
        "schema_version",
        "policy_id",
        "policy_version",
        "source_boundary",
        "required_default_branch",
        "required_status_checks",
        "required_approving_review_count",
        "admin_enforcement_required",
        "force_pushes_allowed",
        "branch_deletions_allowed",
        "break_glass",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "release_lifecycle_policy": [
        "schema_version",
        "policy_id",
        "policy_version",
        "source_boundary",
        "stages",
        "independent_approval_required",
        "codeowner_review_required",
        "conversation_resolution_required",
        "release_artifact_required",
        "source_commit_binding_required",
        "rollback_required",
        "rollback_criteria",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "external_identity_evidence": [
        "schema_version",
        "evidence_id",
        "evidence_version",
        "source_boundary",
        "provider_type",
        "live_provider_authenticated",
        "claims_mapped",
        "required_claims",
        "role_mapping",
        "approval_identity_bound_to_subject",
        "mfa_claim_required",
        "mfa_claim_observed_in_contract",
        "ai_identity_excluded_from_approval_roles",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "durable_evidence_store_policy": [
        "schema_version",
        "policy_id",
        "policy_version",
        "source_boundary",
        "storage_model",
        "required_controls",
        "multi_writer_ready",
        "production_storage_backend_observed",
        "append_only_enforced_by_contract",
        "delete_denied_by_contract",
        "mutation_detection_required",
        "replay_required",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "solo_maintainer_governance_exception": [
        "schema_version",
        "exception_id",
        "exception_version",
        "source_boundary",
        "reason",
        "applies_to",
        "solo_maintainer_constraint",
        "independent_human_review_available",
        "independent_human_review_observed",
        "review_relaxation_allowed",
        "max_relaxation_minutes",
        "required_controls",
        "prohibited_claims",
        "restored_protection_required",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "schema_stability_policy": [
        "schema_version",
        "policy_id",
        "policy_version",
        "source_boundary",
        "frozen_contracts",
        "compatibility_rules",
        "negative_fixtures",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "external_approval_boundary": [
        "schema_version",
        "boundary_id",
        "boundary_version",
        "source_boundary",
        "purpose",
        "approval_system_type",
        "live_approval_system_observed",
        "github_code_review_is_decision_approval",
        "solo_maintainer_exception_is_decision_approval",
        "decision_approval_required",
        "decision_approval_source",
        "approval_subject_binding_required",
        "approval_role_scope_required",
        "approval_expiry_required",
        "approval_mfa_required",
        "approval_audit_export_required",
        "ai_approval_allowed",
        "required_evidence",
        "admission_controls",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "durable_case_store_adapter": [
        "schema_version",
        "adapter_id",
        "adapter_version",
        "source_boundary",
        "storage_backend_type",
        "production_storage_backend_observed",
        "append_only_writes_required",
        "content_addressed_records_required",
        "manifest_hash_chain_required",
        "delete_denied_required",
        "mutation_detection_required",
        "retention_policy_required",
        "replay_export_required",
        "audit_export_required",
        "multi_writer_concurrency_control_required",
        "encryption_boundary_required",
        "tenant_namespace_required",
        "required_operations",
        "denied_operations",
        "retention",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "shared_context_contract": [
        "schema_version",
        "contract_id",
        "contract_version",
        "source_boundary",
        "purpose",
        "ttl_seconds",
        "fields",
        "approval",
        "lineage",
        "freshness",
        "policy_decision_evidence",
        "producer",
        "consumer",
        "runtime_context_exchange_authorized",
    ],
    "case_evidence": [
        "schema_version",
        "case_id",
        "decision_id",
        "decision_version",
        "decision_spec_ref",
        "capability_registry_ref",
        "policy_preflight_ref",
        "simulation_ref",
        "decision_diff_ref",
        "approval_record_ref",
        "storage_mode",
        "mutable",
    ],
    "replay": [
        "schema_version",
        "replay_id",
        "case_id",
        "decision_id",
        "original_case_ref",
        "replayed_case_ref",
        "side_effects_executed",
    ],
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def missing_fields(payload: dict[str, Any], required: list[str]) -> list[str]:
    return [field for field in required if field not in payload]


def validate_payload(kind: str, payload: dict[str, Any]) -> list[str]:
    errors = [f"missing {kind} field: {field}" for field in missing_fields(payload, REQUIRED[kind])]
    if kind == "decision_spec" and payload.get("environment_scope", {}).get("production_allowed") is not False:
        errors.append("decision spec production_allowed must be false for the first wedge")
    if kind == "preflight" and payload.get("ai_override_allowed") is not False:
        errors.append("policy preflight cannot allow AI override")
    if kind == "decision_diff" and "runtime_execution_requested" in payload and payload.get("runtime_execution_requested") is not False:
        errors.append("decision diff cannot request runtime execution")
    if kind == "policy_definitions":
        policies = payload.get("policies", [])
        if not policies:
            errors.append("policy definitions must include at least one policy")
        for policy in policies:
            if policy.get("decision") not in {"allow", "approval_required", "deny"}:
                errors.append(f"policy {policy.get('policy_id')} has invalid decision")
    if kind == "approval" and payload.get("ai_approved") is not False:
        errors.append("approval cannot be AI-approved")
    if kind == "identity_rbac_registry":
        if payload.get("external_identity_provider_observed") is not False:
            errors.append("identity registry must not claim external IdP evidence")
        if not payload.get("roles"):
            errors.append("identity registry must include roles")
        if not payload.get("identities"):
            errors.append("identity registry must include identities")
        for identity in payload.get("identities", []):
            if not identity.get("identity_id"):
                errors.append("identity registry identity missing identity_id")
            if not isinstance(identity.get("roles"), list) or not identity.get("roles"):
                errors.append(f"identity {identity.get('identity_id')} missing roles")
    if kind == "repository_governance_policy":
        if payload.get("admin_enforcement_required") is not True:
            errors.append("repository governance must require admin enforcement")
        if payload.get("force_pushes_allowed") is not False:
            errors.append("repository governance must block force pushes")
        if payload.get("branch_deletions_allowed") is not False:
            errors.append("repository governance must block branch deletions")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("repository governance cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("repository governance cannot authorize production decisions")
    if kind == "release_lifecycle_policy":
        if payload.get("independent_approval_required") is not True:
            errors.append("release lifecycle must require independent approval")
        if payload.get("rollback_required") is not True:
            errors.append("release lifecycle must require rollback criteria")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("release lifecycle cannot authorize runtime integration")
    if kind == "external_identity_evidence":
        if payload.get("live_provider_authenticated") is not False:
            errors.append("external identity evidence must not claim live authentication")
        if payload.get("approval_identity_bound_to_subject") is not True:
            errors.append("external identity evidence must bind approval identity to subject")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("external identity evidence cannot authorize production decisions")
    if kind == "durable_evidence_store_policy":
        if payload.get("production_storage_backend_observed") is not False:
            errors.append("durable evidence store policy must not claim production storage")
        if payload.get("append_only_enforced_by_contract") is not True:
            errors.append("durable evidence store policy must require append-only contract")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("durable evidence store policy cannot authorize runtime integration")
    if kind == "solo_maintainer_governance_exception":
        if payload.get("solo_maintainer_constraint") is not True:
            errors.append("solo-maintainer exception must declare the solo maintainer constraint")
        if payload.get("independent_human_review_available") is not False:
            errors.append("solo-maintainer exception cannot claim independent review availability")
        if payload.get("independent_human_review_observed") is not False:
            errors.append("solo-maintainer exception cannot claim independent human review")
        if payload.get("review_relaxation_allowed") is not True:
            errors.append("solo-maintainer exception must explicitly allow temporary review relaxation")
        if int(payload.get("max_relaxation_minutes", 0) or 0) <= 0:
            errors.append("solo-maintainer exception must declare a positive max relaxation window")
        if payload.get("restored_protection_required") is not True:
            errors.append("solo-maintainer exception must require restored protection")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("solo-maintainer exception cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("solo-maintainer exception cannot authorize production decisions")
    if kind == "schema_stability_policy":
        if not payload.get("frozen_contracts"):
            errors.append("schema stability policy must freeze at least one contract")
        if not payload.get("compatibility_rules"):
            errors.append("schema stability policy must declare compatibility rules")
        if not payload.get("negative_fixtures"):
            errors.append("schema stability policy must declare negative fixtures")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("schema stability policy cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("schema stability policy cannot authorize production decisions")
    if kind == "external_approval_boundary":
        if payload.get("github_code_review_is_decision_approval") is not False:
            errors.append("external approval boundary cannot treat GitHub review as decision approval")
        if payload.get("solo_maintainer_exception_is_decision_approval") is not False:
            errors.append("external approval boundary cannot treat solo-maintainer exception as decision approval")
        if payload.get("decision_approval_required") is not True:
            errors.append("external approval boundary must require decision approval")
        if payload.get("approval_subject_binding_required") is not True:
            errors.append("external approval boundary must require subject binding")
        if payload.get("approval_role_scope_required") is not True:
            errors.append("external approval boundary must require role and scope")
        if payload.get("approval_mfa_required") is not True:
            errors.append("external approval boundary must require MFA")
        if payload.get("approval_audit_export_required") is not True:
            errors.append("external approval boundary must require audit export")
        if payload.get("ai_approval_allowed") is not False:
            errors.append("external approval boundary cannot allow AI approval")
        if not payload.get("required_evidence"):
            errors.append("external approval boundary must declare required evidence")
        if not payload.get("admission_controls"):
            errors.append("external approval boundary must declare admission controls")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("external approval boundary cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("external approval boundary cannot authorize production decisions")
    if kind == "durable_case_store_adapter":
        if payload.get("production_storage_backend_observed") is not False:
            errors.append("durable case store adapter must not claim production storage")
        if payload.get("append_only_writes_required") is not True:
            errors.append("durable case store adapter must require append-only writes")
        if payload.get("content_addressed_records_required") is not True:
            errors.append("durable case store adapter must require content-addressed records")
        if payload.get("manifest_hash_chain_required") is not True:
            errors.append("durable case store adapter must require manifest hash chain")
        if payload.get("delete_denied_required") is not True:
            errors.append("durable case store adapter must deny deletes")
        if payload.get("mutation_detection_required") is not True:
            errors.append("durable case store adapter must require mutation detection")
        if payload.get("replay_export_required") is not True:
            errors.append("durable case store adapter must require replay export")
        if payload.get("audit_export_required") is not True:
            errors.append("durable case store adapter must require audit export")
        if int(payload.get("retention", {}).get("minimum_days", 0) or 0) < 365:
            errors.append("durable case store adapter must require at least 365 days retention")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("durable case store adapter cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("durable case store adapter cannot authorize production decisions")
    if kind == "shared_context_contract":
        if payload.get("runtime_context_exchange_authorized") is not False:
            errors.append("shared context contract cannot authorize runtime exchange")
        if not payload.get("purpose"):
            errors.append("shared context contract must declare purpose")
        if int(payload.get("ttl_seconds", 0) or 0) <= 0:
            errors.append("shared context contract must declare TTL")
        if payload.get("approval", {}).get("approval_required") is not True:
            errors.append("shared context contract must require approval")
        for field in payload.get("fields", []):
            if not field.get("masking_rule"):
                errors.append(f"shared context field {field.get('field_id')} missing masking rule")
    if kind == "case_evidence" and payload.get("mutable") is not False:
        errors.append("case evidence must be immutable or append-only")
    if kind == "replay" and payload.get("side_effects_executed") is not False:
        errors.append("replay cannot execute side effects")
    return errors


def validate_file(kind: str, path: Path) -> dict[str, Any]:
    payload = load_json(path)
    errors = validate_payload(kind, payload)
    return {"kind": kind, "path": str(path), "passed": not errors, "errors": errors}


def validate_default_examples(root: Path = ROOT) -> dict[str, Any]:
    examples = root / "examples"
    files = {
        "decision_spec": examples / "support-ticket-routing-decision-spec.json",
        "capability_registry": examples / "support-ticket-capability-registry.json",
        "preflight": examples / "support-ticket-policy-preflight.json",
        "policy_definitions": examples / "support-ticket-policy-definitions.json",
        "simulation": examples / "support-ticket-simulation-evidence.json",
        "decision_diff": examples / "support-ticket-decision-diff.json",
        "approval": examples / "support-ticket-approval-record.json",
        "identity_rbac_registry": examples / "identity-rbac-registry.json",
        "repository_governance_policy": examples / "repository-governance-policy.json",
        "release_lifecycle_policy": examples / "release-lifecycle-policy.json",
        "external_identity_evidence": examples / "external-identity-evidence.json",
        "durable_evidence_store_policy": examples / "durable-evidence-store-policy.json",
        "solo_maintainer_governance_exception": examples / "solo-maintainer-governance-exception.json",
        "schema_stability_policy": examples / "schema-stability-policy.json",
        "external_approval_boundary": examples / "external-approval-boundary.json",
        "durable_case_store_adapter": examples / "durable-case-store-adapter.json",
        "shared_context_contract": examples / "shared-context-contract.json",
        "case_evidence": examples / "support-ticket-case-evidence.json",
        "replay": examples / "support-ticket-replay-result.json",
    }
    records = [validate_file(kind, path) for kind, path in files.items()]
    return {
        "record_count": len(records),
        "passed_count": len([record for record in records if record["passed"]]),
        "passed": all(record["passed"] for record in records),
        "records": records,
    }
