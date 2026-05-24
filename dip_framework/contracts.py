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
        "supported_rule_types",
        "outcome_precedence",
        "policies",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
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
    "external_approval_adapter": [
        "schema_version",
        "adapter_id",
        "adapter_version",
        "source_boundary",
        "purpose",
        "adapter_type",
        "live_approval_system_observed",
        "decision_approval_source",
        "github_code_review_is_decision_approval",
        "solo_maintainer_exception_is_decision_approval",
        "ai_approval_allowed",
        "required_operations",
        "denied_operations",
        "required_request_fields",
        "required_decision_fields",
        "allowed_decisions",
        "admission_controls",
        "audit_requirements",
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
    "api_resource_model": [
        "schema_version",
        "architecture_id",
        "architecture_statement",
        "deployment_topology",
        "rest_authoritative",
        "realtime_authoritative",
        "resource_groups",
        "canonical_resource_model",
        "command_query_rules",
        "event_recovery",
        "gateway_boundary",
        "runtime_authority_default",
        "production_decision_authority_default",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "product_pack_registry": [
        "schema_version",
        "registry_id",
        "product_packs",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "shared_service_certification": [
        "schema_version",
        "certification_id",
        "maturity_levels",
        "required_evidence",
        "promotion_rule",
        "services",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "ml_shared_capability_inventory": [
        "schema_version",
        "inventory_id",
        "source_repo",
        "edi_evidence_source",
        "classification_values",
        "capabilities",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "adapter_evidence_contract": [
        "schema_version",
        "contract_id",
        "required_result_fields",
        "required_evidence_fields",
        "adapter_types",
        "evidence_required",
        "result_without_evidence_allowed",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "governance_store_contract": [
        "schema_version",
        "contract_id",
        "source_boundary",
        "edi_is_universal_governance_store",
        "append_only_evidence_required",
        "projection_reconstructable",
        "required_record_types",
        "direct_database_access_allowed",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "runtime_authority_blocked_model": [
        "schema_version",
        "model_id",
        "runtime_authority",
        "production_decision_authority",
        "blocked_reasons",
        "runtime_apis_defined",
        "runtime_api_absent",
        "authority_granted",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "shared_capability_certification_states": [
        "schema_version",
        "certification_id",
        "allowed_states",
        "promotion_evidence_required",
        "capabilities",
        "certified_capability_count",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "product_pack_contracts": [
        "schema_version",
        "contract_id",
        "required_sections",
        "products",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "rest_api_contracts": [
        "schema_version",
        "contract_id",
        "authority",
        "required_headers_for_mutations",
        "commands_return_resource_ids",
        "queries_return_state_or_projection",
        "resources",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "event_recovery_contract": [
        "schema_version",
        "contract_id",
        "websocket_endpoint",
        "websocket_authoritative",
        "events_mutate_business_state",
        "rest_recovery_required",
        "rest_recovery_endpoints",
        "required_event_fields",
        "recoverable_event_types",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "certification_evidence_packs": [
        "schema_version",
        "pack_id",
        "required_evidence",
        "service_packs",
        "certified_service_count",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "product_pack_admission": [
        "schema_version",
        "admission_id",
        "required_checks",
        "admission_records",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "openapi_skeleton": [
        "schema_version",
        "openapi_version",
        "api_id",
        "authority",
        "mutation_headers_required",
        "paths",
        "runtime_authority_response",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "event_recovery_fixtures": [
        "schema_version",
        "fixture_id",
        "websocket_authoritative",
        "rest_recovery_required",
        "events_mutate_business_state",
        "events",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "governance_store_logical_schema": [
        "schema_version",
        "schema_id",
        "storage_backend_selected",
        "append_only_required",
        "projection_rebuild_required",
        "direct_database_access_allowed",
        "record_types",
        "retention",
        "masking",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "canonical_openapi_contract": [
        "schema_version",
        "contract_id",
        "openapi_version",
        "authority",
        "mutation_headers_required",
        "resource_operations",
        "runtime_authority_response",
        "websocket_authoritative",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "product_pack_contract_kit": [
        "schema_version",
        "kit_id",
        "required_fields",
        "templates",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "adapter_evidence_contract_kit": [
        "schema_version",
        "kit_id",
        "required_response_fields",
        "required_evidence_fields",
        "adapter_contracts",
        "sample_response",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "governance_store_logical_api": [
        "schema_version",
        "api_id",
        "storage_backend_selected",
        "append_only_required",
        "projection_rebuild_required",
        "direct_database_access_allowed",
        "mutation_headers_required",
        "operations",
        "delete_operation_allowed",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
    ],
    "event_recovery_contract_v2": [
        "schema_version",
        "contract_id",
        "websocket_endpoint",
        "websocket_authoritative",
        "events_mutate_business_state",
        "rest_event_log_required",
        "reconnect_recovery_required",
        "required_event_fields",
        "rest_recovery_endpoints",
        "recoverable_event_types",
        "runtime_integration_authorized",
        "production_decision_execution_authorized",
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
        supported_rule_types = set(payload.get("supported_rule_types", []))
        if payload.get("outcome_precedence") != ["deny", "escalate", "approval_required", "allow"]:
            errors.append("policy definitions must declare deterministic outcome precedence")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("policy definitions cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("policy definitions cannot authorize production decisions")
        if not policies:
            errors.append("policy definitions must include at least one policy")
        for policy in policies:
            if policy.get("decision") not in {"allow", "approval_required", "deny", "escalate"}:
                errors.append(f"policy {policy.get('policy_id')} has invalid decision")
            if policy.get("lifecycle_status") not in {"draft", "active", "deprecated"}:
                errors.append(f"policy {policy.get('policy_id')} has invalid lifecycle status")
            if policy.get("lifecycle_status") == "revoked":
                errors.append(f"policy {policy.get('policy_id')} is revoked")
            if policy.get("rule_type") not in supported_rule_types:
                errors.append(f"policy {policy.get('policy_id')} has unknown rule type")
            if policy.get("rule_type") == "required_evidence_present" and not policy.get("required_evidence"):
                errors.append(f"policy {policy.get('policy_id')} missing required evidence")
            if policy.get("runtime_integration_authorized") is True:
                errors.append(f"policy {policy.get('policy_id')} cannot authorize runtime integration")
            if policy.get("production_decision_execution_authorized") is True:
                errors.append(f"policy {policy.get('policy_id')} cannot authorize production decisions")
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
    if kind == "external_approval_adapter":
        if payload.get("adapter_type") != "contract_only":
            errors.append("external approval adapter must remain contract-only")
        if payload.get("live_approval_system_observed") is not False:
            errors.append("external approval adapter cannot claim a live approval system")
        if payload.get("github_code_review_is_decision_approval") is not False:
            errors.append("external approval adapter cannot treat GitHub review as decision approval")
        if payload.get("solo_maintainer_exception_is_decision_approval") is not False:
            errors.append("external approval adapter cannot treat solo-maintainer exception as decision approval")
        if payload.get("ai_approval_allowed") is not False:
            errors.append("external approval adapter cannot allow AI self-approval")
        required_operations = set(payload.get("required_operations", []))
        denied_operations = set(payload.get("denied_operations", []))
        required_request_fields = set(payload.get("required_request_fields", []))
        required_decision_fields = set(payload.get("required_decision_fields", []))
        allowed_decisions = set(payload.get("allowed_decisions", []))
        admission_controls = set(payload.get("admission_controls", []))
        audit_requirements = set(payload.get("audit_requirements", []))
        if not {
            "request_approval",
            "approve_decision",
            "reject_decision",
            "expire_approval",
            "delegate_approval",
            "revoke_approval",
            "export_approval_audit",
        }.issubset(required_operations):
            errors.append("external approval adapter missing required operations")
        if not {
            "ai_self_approval",
            "requester_self_approval",
            "mutate_approved_decision",
            "bypass_policy_preflight",
            "execute_runtime_decision",
        }.issubset(denied_operations):
            errors.append("external approval adapter missing denied operations")
        if not {
            "approval_request_id",
            "decision_id",
            "decision_version",
            "requester_subject",
            "required_approver_role",
            "decision_scope",
            "case_manifest_hash",
            "policy_preflight_ref",
            "simulation_evidence_ref",
            "decision_diff_ref",
            "approval_expires_at",
        }.issubset(required_request_fields):
            errors.append("external approval adapter missing request evidence fields")
        if not {
            "approval_record_id",
            "approval_request_id",
            "approver_subject",
            "approver_role",
            "decision",
            "approval_reason",
            "approval_timestamp",
            "mfa_evidence",
            "case_manifest_hash",
            "audit_export_ref",
        }.issubset(required_decision_fields):
            errors.append("external approval adapter missing decision evidence fields")
        if not {"approved", "rejected", "expired", "delegated", "revoked"}.issubset(allowed_decisions):
            errors.append("external approval adapter missing decision lifecycle outcomes")
        if not {
            "policy_preflight_requires_approval",
            "approval_bound_to_case_manifest",
            "approver_cannot_be_requester",
            "ai_identity_excluded",
            "approval_expiry_enforced",
            "decision_scope_enforced",
            "runtime_authority_denied",
        }.issubset(admission_controls):
            errors.append("external approval adapter missing admission controls")
        if not {
            "append_only_approval_records",
            "content_addressed_case_binding",
            "approval_decision_lineage",
            "exportable_audit_pack",
        }.issubset(audit_requirements):
            errors.append("external approval adapter missing audit requirements")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("external approval adapter cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("external approval adapter cannot authorize production decisions")
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
    if kind == "api_resource_model":
        if payload.get("rest_authoritative") is not True:
            errors.append("api resource model must make REST authoritative")
        if payload.get("realtime_authoritative") is not False:
            errors.append("api resource model cannot make realtime authoritative")
        if payload.get("deployment_topology", {}).get("forced_microservice_topology") is not False:
            errors.append("api resource model cannot force microservice topology")
        if len(payload.get("resource_groups", [])) < 15:
            errors.append("api resource model must declare core resource groups")
        rules = payload.get("command_query_rules", {})
        if rules.get("commands_create_durable_records") is not True:
            errors.append("api commands must create durable records")
        if set(rules.get("required_mutation_headers", [])) != {"Idempotency-Key", "Correlation-Id"}:
            errors.append("api mutation commands must require idempotency and correlation headers")
        recovery = payload.get("event_recovery", {})
        if recovery.get("events_can_mutate_business_state") is not False:
            errors.append("realtime events cannot mutate business state")
        if len(recovery.get("rest_recovery_endpoints", [])) < 2:
            errors.append("realtime events must have REST recovery endpoints")
        if payload.get("gateway_boundary", {}).get("gateway_owns_truth") is not False:
            errors.append("gateway cannot own durable truth")
        if payload.get("runtime_authority_default") != "blocked":
            errors.append("runtime authority must default to blocked")
        if payload.get("production_decision_authority_default") != "blocked":
            errors.append("production decision authority must default to blocked")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("api resource model cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("api resource model cannot authorize production decisions")
    if kind == "product_pack_registry":
        packs = payload.get("product_packs", [])
        if len(packs) < 3:
            errors.append("product pack registry must include initial EDI, ML, and support fixtures")
        for pack in packs:
            for field in [
                "product_id",
                "product_pack_id",
                "product_pack_version",
                "owned_decisions",
                "provided_capabilities",
                "consumed_capabilities",
                "required_policies",
                "approval_authorities",
                "emitted_evidence",
                "replay_guarantees",
                "runtime_authority_level",
                "cost_and_entitlement_model",
                "product_local_services",
                "shared_certified_services_used",
            ]:
                if field not in pack:
                    errors.append(f"product pack {pack.get('product_id')} missing {field}")
            if pack.get("runtime_authority_level") != "none":
                errors.append(f"product pack {pack.get('product_id')} cannot grant runtime authority")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("product pack registry cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("product pack registry cannot authorize production decisions")
    if kind == "shared_service_certification":
        required = set(payload.get("required_evidence", []))
        expected = {
            "neutral_contract",
            "domain_coupling_review",
            "authn_authz_boundary",
            "tenant_isolation",
            "policy_hooks",
            "audit_logging",
            "evidence_export",
            "replay_or_reconstruction",
            "failure_mode_tests",
            "observability",
            "cost_attribution",
            "promotion_evidence",
            "rollback_evidence",
        }
        if not expected.issubset(required):
            errors.append("shared service certification missing required evidence categories")
        if "Shared Certified" not in payload.get("maturity_levels", []):
            errors.append("shared service certification must include Shared Certified maturity")
        for service in payload.get("services", []):
            if service.get("recommended_posture") not in {"observe", "adapter_candidate", "shared_capability_candidate"}:
                errors.append(f"service {service.get('service_id')} has invalid posture")
            if service.get("evidence_complete") is not False:
                errors.append(f"service {service.get('service_id')} cannot claim certification evidence complete")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("shared service certification cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("shared service certification cannot authorize production decisions")
    if kind == "ml_shared_capability_inventory":
        classifications = set(payload.get("classification_values", []))
        if not {"do_not_use", "observe", "adapter_candidate", "shared_capability_candidate"}.issubset(classifications):
            errors.append("ML inventory missing required classification values")
        if len(payload.get("capabilities", [])) < 10:
            errors.append("ML inventory must include core candidate services and infrastructure")
        for capability in payload.get("capabilities", []):
            if capability.get("classification") not in classifications:
                errors.append(f"ML capability {capability.get('asset_id')} has invalid classification")
            if not capability.get("required_contract"):
                errors.append(f"ML capability {capability.get('asset_id')} missing required contract")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("ML inventory cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("ML inventory cannot authorize production decisions")
    if kind == "adapter_evidence_contract":
        evidence = set(payload.get("required_evidence_fields", []))
        expected = {
            "provider",
            "provider_version",
            "checked_at",
            "correlation_id",
            "policy_decision",
            "source_lineage",
            "runtime_authority",
        }
        if not expected.issubset(evidence):
            errors.append("adapter evidence contract missing required evidence fields")
        if payload.get("evidence_required") is not True:
            errors.append("adapter evidence contract must require evidence")
        if payload.get("result_without_evidence_allowed") is not False:
            errors.append("adapter evidence contract cannot allow result without evidence")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("adapter evidence contract cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("adapter evidence contract cannot authorize production decisions")
    if kind == "governance_store_contract":
        records = set(payload.get("required_record_types", []))
        expected = {
            "product_registry_record",
            "product_pack_version",
            "decision_spec",
            "capability_graph_snapshot",
            "policy_decision",
            "approval_record",
            "shared_context_contract",
            "release_evidence",
            "runtime_authority_record",
            "case_evidence",
            "replay_pack",
            "lineage_record",
        }
        if not expected.issubset(records):
            errors.append("governance store contract missing required record types")
        if payload.get("edi_is_universal_governance_store") is not False:
            errors.append("EDI cannot be the universal governance store")
        if payload.get("append_only_evidence_required") is not True:
            errors.append("governance store must require append-only evidence")
        if payload.get("projection_reconstructable") is not True:
            errors.append("governance store projections must be reconstructable")
        if payload.get("direct_database_access_allowed") is not False:
            errors.append("governance store cannot allow direct database access")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("governance store contract cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("governance store contract cannot authorize production decisions")
    if kind == "runtime_authority_blocked_model":
        if payload.get("runtime_authority") != "blocked":
            errors.append("runtime authority must be blocked")
        if payload.get("production_decision_authority") != "blocked":
            errors.append("production decision authority must be blocked")
        if len(payload.get("blocked_reasons", [])) < 3:
            errors.append("runtime authority blocked model must declare blocked reasons")
        if payload.get("runtime_apis_defined") is not True:
            errors.append("runtime APIs should be defined")
        if payload.get("runtime_api_absent") is not False:
            errors.append("runtime APIs should be gated, not absent")
        if payload.get("authority_granted") is not False:
            errors.append("runtime authority cannot be granted")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("runtime authority model cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("runtime authority model cannot authorize production decisions")
    if kind == "shared_capability_certification_states":
        states = set(payload.get("allowed_states", []))
        if not {"candidate", "observed", "certified", "restricted", "revoked"}.issubset(states):
            errors.append("shared capability certification states missing required lifecycle states")
        if int(payload.get("certified_capability_count", -1)) != 0:
            errors.append("shared capabilities cannot claim certification yet")
        for capability in payload.get("capabilities", []):
            if capability.get("state") not in states:
                errors.append(f"capability {capability.get('capability_id')} has invalid state")
            if capability.get("certification_evidence_complete") is not False:
                errors.append(f"capability {capability.get('capability_id')} cannot claim complete certification evidence")
            if capability.get("runtime_invocation_allowed") is not False:
                errors.append(f"capability {capability.get('capability_id')} cannot allow runtime invocation")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("shared capability certification cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("shared capability certification cannot authorize production decisions")
    if kind == "product_pack_contracts":
        if len(payload.get("required_sections", [])) < 10:
            errors.append("product pack contracts must declare required sections")
        for product in payload.get("products", []):
            if product.get("declares_all_required_sections") is not True:
                errors.append(f"product {product.get('product_id')} must declare all required sections")
            if product.get("cross_product_database_access_allowed") is not False:
                errors.append(f"product {product.get('product_id')} cannot allow cross-product database access")
            if product.get("runtime_authority") != "none":
                errors.append(f"product {product.get('product_id')} cannot grant runtime authority")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("product pack contracts cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("product pack contracts cannot authorize production decisions")
    if kind == "rest_api_contracts":
        if payload.get("authority") != "rest":
            errors.append("REST API contracts must make REST authoritative")
        if set(payload.get("required_headers_for_mutations", [])) != {"Idempotency-Key", "Correlation-Id"}:
            errors.append("REST API mutations must require idempotency and correlation headers")
        if payload.get("commands_return_resource_ids") is not True:
            errors.append("REST commands must return resource ids")
        if payload.get("queries_return_state_or_projection") is not True:
            errors.append("REST queries must return state or projections")
        if len(payload.get("resources", [])) < 6:
            errors.append("REST API contracts must include core resource groups")
        for resource in payload.get("resources", []):
            if not resource.get("collection_path", "").startswith("/api/v1/"):
                errors.append(f"resource {resource.get('resource')} must use /api/v1")
            if resource.get("evidence_produced") is not True:
                errors.append(f"resource {resource.get('resource')} must produce evidence")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("REST API contracts cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("REST API contracts cannot authorize production decisions")
    if kind == "event_recovery_contract":
        if payload.get("websocket_authoritative") is not False:
            errors.append("event recovery cannot make websocket authoritative")
        if payload.get("events_mutate_business_state") is not False:
            errors.append("events cannot mutate business state")
        if payload.get("rest_recovery_required") is not True:
            errors.append("event recovery must require REST recovery")
        if len(payload.get("rest_recovery_endpoints", [])) < 3:
            errors.append("event recovery must declare REST recovery endpoints")
        required = {"event_id", "event_type", "occurred_at", "correlation_id", "resource_uri", "evidence_uri"}
        if not required.issubset(set(payload.get("required_event_fields", []))):
            errors.append("event recovery missing required event fields")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("event recovery cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("event recovery cannot authorize production decisions")
    if kind == "certification_evidence_packs":
        if len(payload.get("required_evidence", [])) < 10:
            errors.append("certification packs must declare required evidence")
        if int(payload.get("certified_service_count", -1)) != 0:
            errors.append("certification packs cannot claim certified services yet")
        for pack in payload.get("service_packs", []):
            if pack.get("evidence_complete") is not False:
                errors.append(f"service {pack.get('service_id')} cannot claim evidence complete")
            if pack.get("runtime_invocation_allowed") is not False:
                errors.append(f"service {pack.get('service_id')} cannot allow runtime invocation")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("certification packs cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("certification packs cannot authorize production decisions")
    if kind == "product_pack_admission":
        if len(payload.get("required_checks", [])) < 8:
            errors.append("product-pack admission must declare admission checks")
        if len(payload.get("admission_records", [])) < 3:
            errors.append("product-pack admission must include initial products")
        for record in payload.get("admission_records", []):
            if record.get("admitted") is not True:
                errors.append(f"product {record.get('product_id')} must be admitted by contract evidence")
            if record.get("runtime_authority") != "none":
                errors.append(f"product {record.get('product_id')} cannot have runtime authority")
            if record.get("direct_database_access_allowed") is not False:
                errors.append(f"product {record.get('product_id')} cannot allow direct database access")
            if record.get("hidden_shared_state_allowed") is not False:
                errors.append(f"product {record.get('product_id')} cannot allow hidden shared state")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("product-pack admission cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("product-pack admission cannot authorize production decisions")
    if kind == "openapi_skeleton":
        if payload.get("openapi_version") != "3.1.0":
            errors.append("OpenAPI skeleton must use 3.1.0")
        if payload.get("authority") != "rest":
            errors.append("OpenAPI skeleton must keep REST authoritative")
        if set(payload.get("mutation_headers_required", [])) != {"Idempotency-Key", "Correlation-Id"}:
            errors.append("OpenAPI skeleton must require idempotency and correlation")
        if len(payload.get("paths", [])) < 15:
            errors.append("OpenAPI skeleton must include core paths")
        if payload.get("runtime_authority_response", {}).get("authority") != "blocked":
            errors.append("OpenAPI skeleton must expose blocked runtime authority")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("OpenAPI skeleton cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("OpenAPI skeleton cannot authorize production decisions")
    if kind == "event_recovery_fixtures":
        if payload.get("websocket_authoritative") is not False:
            errors.append("event fixtures cannot make WebSocket authoritative")
        if payload.get("events_mutate_business_state") is not False:
            errors.append("event fixtures cannot mutate business state")
        if payload.get("rest_recovery_required") is not True:
            errors.append("event fixtures must require REST recovery")
        if len(payload.get("events", [])) < 4:
            errors.append("event fixtures must include core event types")
        for event in payload.get("events", []):
            if event.get("recoverable_by_rest") is not True:
                errors.append(f"event {event.get('event_type')} must be REST recoverable")
            if not event.get("resource_uri") or not event.get("evidence_uri"):
                errors.append(f"event {event.get('event_type')} missing resource/evidence URI")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("event fixtures cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("event fixtures cannot authorize production decisions")
    if kind == "governance_store_logical_schema":
        if payload.get("storage_backend_selected") is not False:
            errors.append("governance store logical schema cannot select storage backend yet")
        if payload.get("append_only_required") is not True:
            errors.append("governance store logical schema must require append-only records")
        if payload.get("projection_rebuild_required") is not True:
            errors.append("governance store logical schema must require projection rebuild")
        if payload.get("direct_database_access_allowed") is not False:
            errors.append("governance store logical schema cannot allow direct database access")
        if len(payload.get("record_types", [])) < 12:
            errors.append("governance store logical schema must include core record types")
        if int(payload.get("retention", {}).get("minimum_days", 0) or 0) < 365:
            errors.append("governance store logical schema must retain evidence for at least 365 days")
        if payload.get("retention", {}).get("delete_allowed") is not False:
            errors.append("governance store logical schema cannot allow deletes")
        if payload.get("masking", {}).get("purpose_bound_access_required") is not True:
            errors.append("governance store logical schema must require purpose-bound access")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("governance store logical schema cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("governance store logical schema cannot authorize production decisions")
    if kind == "canonical_openapi_contract":
        if payload.get("openapi_version") != "3.1.0":
            errors.append("canonical OpenAPI contract must use 3.1.0")
        if payload.get("authority") != "rest":
            errors.append("canonical OpenAPI contract must keep REST authoritative")
        required_headers = {"Idempotency-Key", "Correlation-Id"}
        if set(payload.get("mutation_headers_required", [])) != required_headers:
            errors.append("canonical OpenAPI contract must require idempotency and correlation")
        operations = payload.get("resource_operations", [])
        if len(operations) < 20:
            errors.append("canonical OpenAPI contract must include core resource operations")
        for operation in operations:
            if operation.get("operation") == "command" and set(operation.get("headers_required", [])) != required_headers:
                errors.append(f"command {operation.get('method')} {operation.get('path')} missing required headers")
        if payload.get("runtime_authority_response", {}).get("authority") != "blocked":
            errors.append("canonical OpenAPI contract must expose blocked runtime authority")
        if payload.get("websocket_authoritative") is not False:
            errors.append("canonical OpenAPI contract cannot make WebSocket authoritative")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("canonical OpenAPI contract cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("canonical OpenAPI contract cannot authorize production decisions")
    if kind == "product_pack_contract_kit":
        if len(payload.get("required_fields", [])) < 10:
            errors.append("product-pack kit must declare required fields")
        if len(payload.get("templates", [])) < 3:
            errors.append("product-pack kit must include initial product templates")
        for template in payload.get("templates", []):
            missing = [field for field in payload.get("required_fields", []) if field not in template]
            if missing:
                errors.append(f"product template {template.get('product_id')} missing fields: {missing}")
            if template.get("runtime_authority") != "none":
                errors.append(f"product template {template.get('product_id')} cannot have runtime authority")
            if template.get("direct_database_access_allowed") is not False:
                errors.append(f"product template {template.get('product_id')} cannot allow direct database access")
            if template.get("hidden_shared_state_allowed") is not False:
                errors.append(f"product template {template.get('product_id')} cannot allow hidden shared state")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("product-pack kit cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("product-pack kit cannot authorize production decisions")
    if kind == "adapter_evidence_contract_kit":
        if set(payload.get("required_response_fields", [])) != {"result", "evidence"}:
            errors.append("adapter evidence kit must require result and evidence")
        evidence_fields = set(payload.get("required_evidence_fields", []))
        required_evidence = {
            "provider",
            "provider_version",
            "contract_id",
            "operation",
            "subject",
            "decision",
            "lineage",
            "checked_at",
            "correlation_id",
        }
        if not required_evidence.issubset(evidence_fields):
            errors.append("adapter evidence kit missing required evidence fields")
        if len(payload.get("adapter_contracts", [])) < 10:
            errors.append("adapter evidence kit must include core adapter contracts")
        for adapter in payload.get("adapter_contracts", []):
            if adapter.get("live_invocation_allowed") is not False:
                errors.append(f"adapter {adapter.get('adapter_id')} cannot allow live invocation")
        sample = payload.get("sample_response", {})
        if set(sample.keys()) != {"result", "evidence"}:
            errors.append("adapter evidence kit sample response must include result and evidence")
        if not required_evidence.issubset(set(sample.get("evidence", {}).keys())):
            errors.append("adapter evidence kit sample response missing evidence fields")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("adapter evidence kit cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("adapter evidence kit cannot authorize production decisions")
    if kind == "governance_store_logical_api":
        if payload.get("storage_backend_selected") is not False:
            errors.append("governance store logical API cannot select storage backend yet")
        if payload.get("append_only_required") is not True:
            errors.append("governance store logical API must require append-only records")
        if payload.get("projection_rebuild_required") is not True:
            errors.append("governance store logical API must require projection rebuild")
        if payload.get("direct_database_access_allowed") is not False:
            errors.append("governance store logical API cannot allow direct database access")
        required_headers = {"Idempotency-Key", "Correlation-Id"}
        if set(payload.get("mutation_headers_required", [])) != required_headers:
            errors.append("governance store logical API must require idempotency and correlation")
        if len(payload.get("operations", [])) < 8:
            errors.append("governance store logical API must include core operations")
        append_operations = [item for item in payload.get("operations", []) if item.get("operation") == "append_record"]
        if not append_operations or any(item.get("append_only") is not True for item in append_operations):
            errors.append("governance store logical API must include append-only append operation")
        for operation in payload.get("operations", []):
            if operation.get("method") == "POST" and set(operation.get("headers_required", [])) != required_headers:
                errors.append(f"governance store command {operation.get('path')} missing required headers")
        if payload.get("delete_operation_allowed") is not False:
            errors.append("governance store logical API cannot allow deletes")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("governance store logical API cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("governance store logical API cannot authorize production decisions")
    if kind == "event_recovery_contract_v2":
        if payload.get("websocket_authoritative") is not False:
            errors.append("event recovery v2 cannot make WebSocket authoritative")
        if payload.get("events_mutate_business_state") is not False:
            errors.append("event recovery v2 cannot mutate business state")
        if payload.get("rest_event_log_required") is not True:
            errors.append("event recovery v2 must require REST event log")
        if payload.get("reconnect_recovery_required") is not True:
            errors.append("event recovery v2 must require reconnect recovery")
        required_fields = {
            "event_id",
            "event_type",
            "occurred_at",
            "tenant_id",
            "product_id",
            "correlation_id",
            "resource_type",
            "resource_id",
            "resource_uri",
            "evidence_uri",
        }
        if not required_fields.issubset(set(payload.get("required_event_fields", []))):
            errors.append("event recovery v2 missing required event fields")
        if len(payload.get("rest_recovery_endpoints", [])) < 3:
            errors.append("event recovery v2 must declare REST recovery endpoints")
        if len(payload.get("recoverable_event_types", [])) < 7:
            errors.append("event recovery v2 must include core event types")
        for event in payload.get("recoverable_event_types", []):
            if not event.get("resource_uri") or not event.get("evidence_uri"):
                errors.append(f"event {event.get('event_type')} missing resource/evidence URI")
        if payload.get("runtime_integration_authorized") is not False:
            errors.append("event recovery v2 cannot authorize runtime integration")
        if payload.get("production_decision_execution_authorized") is not False:
            errors.append("event recovery v2 cannot authorize production decisions")
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
        "external_approval_adapter": examples / "external-approval-adapter.json",
        "durable_case_store_adapter": examples / "durable-case-store-adapter.json",
        "shared_context_contract": examples / "shared-context-contract.json",
        "case_evidence": examples / "support-ticket-case-evidence.json",
        "replay": examples / "support-ticket-replay-result.json",
        "api_resource_model": examples / "api-resource-model.json",
        "product_pack_registry": examples / "product-pack-registry.json",
        "shared_service_certification": examples / "shared-service-certification.json",
        "ml_shared_capability_inventory": examples / "ml-shared-capability-inventory.json",
        "adapter_evidence_contract": examples / "adapter-evidence-contract.json",
        "governance_store_contract": examples / "governance-store-contract.json",
        "runtime_authority_blocked_model": examples / "runtime-authority-blocked-model.json",
        "shared_capability_certification_states": examples / "shared-capability-certification-states.json",
        "product_pack_contracts": examples / "product-pack-contracts.json",
        "rest_api_contracts": examples / "rest-api-contracts.json",
        "event_recovery_contract": examples / "event-recovery-contract.json",
        "certification_evidence_packs": examples / "certification-evidence-packs.json",
        "product_pack_admission": examples / "product-pack-admission.json",
        "openapi_skeleton": examples / "openapi-skeleton.json",
        "event_recovery_fixtures": examples / "event-recovery-fixtures.json",
        "governance_store_logical_schema": examples / "governance-store-logical-schema.json",
        "canonical_openapi_contract": examples / "canonical-openapi-contract.json",
        "product_pack_contract_kit": examples / "product-pack-contract-kit.json",
        "adapter_evidence_contract_kit": examples / "adapter-evidence-contract-kit.json",
        "governance_store_logical_api": examples / "governance-store-logical-api.json",
        "event_recovery_contract_v2": examples / "event-recovery-contract-v2.json",
    }
    records = [validate_file(kind, path) for kind, path in files.items()]
    return {
        "record_count": len(records),
        "passed_count": len([record for record in records if record["passed"]]),
        "passed": all(record["passed"] for record in records),
        "records": records,
    }
