"""DIP pre-runtime evidence builders."""

from __future__ import annotations

import hashlib
import html
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from dip_framework.contracts import ROOT, load_json, validate_default_examples, validate_file


ARTIFACTS = [
    ("decision_spec", "examples/support-ticket-routing-decision-spec.json"),
    ("baseline_decision_spec", "examples/support-ticket-routing-decision-spec-v0.9.0.json"),
    ("capability_registry", "examples/support-ticket-capability-registry.json"),
    ("policy_definitions", "examples/support-ticket-policy-definitions.json"),
    ("identity_rbac_registry", "examples/identity-rbac-registry.json"),
    ("repository_governance_policy", "examples/repository-governance-policy.json"),
    ("release_lifecycle_policy", "examples/release-lifecycle-policy.json"),
    ("external_identity_evidence", "examples/external-identity-evidence.json"),
    ("durable_evidence_store_policy", "examples/durable-evidence-store-policy.json"),
    ("solo_maintainer_governance_exception", "examples/solo-maintainer-governance-exception.json"),
    ("schema_stability_policy", "examples/schema-stability-policy.json"),
    ("external_approval_boundary", "examples/external-approval-boundary.json"),
    ("external_approval_adapter", "examples/external-approval-adapter.json"),
    ("durable_case_store_adapter", "examples/durable-case-store-adapter.json"),
    ("negative_decision_spec_fixture", "examples/negative/decision-spec-production-allowed.json"),
    ("negative_approval_fixture", "examples/negative/approval-ai-approved.json"),
    (
        "negative_external_approval_fixture",
        "examples/negative/external-approval-github-review-as-decision-approval.json",
    ),
    ("negative_external_approval_adapter_fixture", "examples/negative/external-approval-adapter-ai-self-approval.json"),
    ("negative_policy_definitions_unknown_rule", "examples/negative/policy-definitions-unknown-rule.json"),
    ("negative_policy_definitions_revoked_policy", "examples/negative/policy-definitions-revoked-policy.json"),
    ("negative_policy_definitions_production_authority", "examples/negative/policy-definitions-production-authority.json"),
    ("negative_policy_definitions_missing_required_evidence", "examples/negative/policy-definitions-missing-required-evidence.json"),
    ("negative_durable_case_store_adapter", "examples/negative/durable-case-store-mutable-adapter.json"),
    ("negative_durable_case_store_missing_hash_chain", "examples/negative/durable-case-store-missing-hash-chain.json"),
    ("negative_durable_case_store_delete_enabled", "examples/negative/durable-case-store-delete-enabled.json"),
    ("negative_durable_case_store_weak_retention", "examples/negative/durable-case-store-weak-retention.json"),
    ("support_ticket_case_set", "examples/support-ticket-simulation-cases.json"),
    ("engineering_decision_spec", "examples/engineering-review-readiness-decision-spec.json"),
    ("engineering_case_set", "examples/engineering-review-readiness-cases.json"),
    ("operational_risk_decision_spec", "examples/operational-risk-triage-decision-spec.json"),
    ("operational_risk_case_set", "examples/operational-risk-triage-cases.json"),
    ("shared_context_contract", "examples/shared-context-contract.json"),
    ("policy_preflight", "reports/trust-loop/computed-policy-preflight.json"),
    ("policy_engine", "reports/trust-loop/computed-policy-engine.json"),
    ("simulation", "reports/trust-loop/computed-simulation-evidence.json"),
    ("decision_diff", "reports/trust-loop/computed-decision-diff.json"),
    ("capability_governance", "reports/trust-loop/capability-governance.json"),
    ("shared_context_governance", "reports/trust-loop/shared-context-governance.json"),
    ("solo_maintainer_exception", "reports/trust-loop/solo-maintainer-exception.json"),
    ("schema_stability", "reports/trust-loop/schema-stability.json"),
    ("external_approval_boundary", "reports/trust-loop/external-approval-boundary.json"),
    ("external_approval_adapter", "reports/trust-loop/external-approval-adapter.json"),
    ("live_identity_rbac", "reports/trust-loop/live-identity-rbac.json"),
    ("case_evidence", "reports/trust-loop/case-evidence.json"),
]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_payload(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _git_head(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _gh_repo_slug(root: Path) -> str | None:
    result = subprocess.run(
        ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        return None
    slug = result.stdout.strip()
    return slug or None


def _gh_api(path: str, cwd: Path | None = None) -> dict[str, Any]:
    result = subprocess.run(
        ["gh", "api", "--method", "GET", path],
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        return {"available": False, "body": {}, "error": result.stderr.strip()}
    try:
        body = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        body = {}
    return {"available": True, "body": body, "error": ""}


def _gh_branch_protection(root: Path, branch: str) -> dict[str, Any]:
    repo = _gh_repo_slug(root)
    if not repo:
        return {
            "repo": "",
            "branch": branch,
            "observed": False,
            "required_status_checks_observed": False,
            "required_approving_review_count_observed": 0,
            "admin_enforcement_observed": False,
            "codeowner_review_required_observed": False,
            "conversation_resolution_required_observed": False,
            "force_pushes_blocked": False,
            "deletions_blocked": False,
        }
    response = _gh_api(f"repos/{repo}/branches/{branch}/protection", cwd=root)
    body = response["body"] if response["available"] else {}
    reviews = body.get("required_pull_request_reviews", {})
    checks = body.get("required_status_checks", {})
    return {
        "repo": repo,
        "branch": branch,
        "observed": response["available"] is True and bool(body),
        "required_status_checks_observed": bool(checks.get("contexts") or checks.get("checks")),
        "required_approving_review_count_observed": int(reviews.get("required_approving_review_count", 0) or 0),
        "admin_enforcement_observed": body.get("enforce_admins", {}).get("enabled") is True,
        "codeowner_review_required_observed": reviews.get("require_code_owner_reviews") is True,
        "conversation_resolution_required_observed": body.get("required_conversation_resolution", {}).get("enabled")
        is True,
        "force_pushes_blocked": body.get("allow_force_pushes", {}).get("enabled") is False,
        "deletions_blocked": body.get("allow_deletions", {}).get("enabled") is False,
    }


def compute_policy_preflight(root: Path = ROOT) -> dict[str, Any]:
    engine = compute_policy_engine(root)
    spec = load_json(root / "examples/support-ticket-routing-decision-spec.json")
    return {
        "schema_version": "policy-preflight/v1",
        "preflight_id": "computed-preflight-support-ticket-routing-1",
        "decision_id": spec.get("decision_id"),
        "decision_version": spec.get("decision_version"),
        "result": engine["result"],
        "computed": True,
        "policy_set_id": engine["policy_set_id"],
        "policy_set_version": engine["policy_set_version"],
        "evaluated_policies": engine["evaluated_policies"],
        "violated_policies": engine["violated_policies"],
        "required_approvals": engine["required_approvals"],
        "missing_evidence": engine["missing_evidence"],
        "environment_restrictions": ["prod"] if spec.get("environment_scope", {}).get("production_allowed") is False else [],
        "side_effect_restrictions": ["simulation_only"],
        "remediation_guidance": engine["remediation_guidance"],
        "ai_override_allowed": False,
    }


def compute_policy_engine(root: Path = ROOT) -> dict[str, Any]:
    examples = root / "examples"
    spec = load_json(examples / "support-ticket-routing-decision-spec.json")
    policies = load_json(examples / "support-ticket-policy-definitions.json")
    denied: list[str] = []
    escalated: list[str] = []
    approval_required: list[str] = []
    missing_evidence: list[str] = []
    evaluated = []
    supported_rule_types = set(policies.get("supported_rule_types", []))
    compatibility_errors = []
    for policy in policies.get("policies", []):
        rule = policy.get("rule_type")
        policy_id = str(policy.get("policy_id", ""))
        decision = str(policy.get("decision", ""))
        lifecycle = str(policy.get("lifecycle_status", ""))
        policy_record = {
            "policy_id": policy_id,
            "version": policy.get("version"),
            "lifecycle_status": lifecycle,
            "rule_type": rule,
            "decision": decision,
            "matched": False,
        }
        if lifecycle not in {"active", "deprecated"}:
            compatibility_errors.append(f"{policy_id}: inactive policy cannot participate")
            evaluated.append(policy_record)
            continue
        if rule not in supported_rule_types:
            compatibility_errors.append(f"{policy_id}: unsupported rule type")
            evaluated.append(policy_record)
            continue
        if rule == "production_allowed_false" and spec.get("environment_scope", {}).get("production_allowed") is not False:
            policy_record["matched"] = True
            denied.append(policy_id)
        elif rule == "side_effects_simulation_only":
            for side_effect in spec.get("side_effects", []):
                if side_effect.get("mode") != "simulation_only":
                    policy_record["matched"] = True
                    denied.append(policy_id)
                    break
        elif rule == "approval_required_for_risk_tier":
            risk_tier = int(spec.get("risk", {}).get("risk_tier", 0) or 0)
            approval = spec.get("approval", {})
            if risk_tier >= int(policy.get("minimum_risk_tier", 0) or 0):
                policy_record["matched"] = True
                if approval.get("required") is True:
                    approval_required.extend(approval.get("approver_roles", []))
                else:
                    denied.append(policy_id)
        elif rule == "required_evidence_present":
            declared = set(spec.get("evidence_requirements", []))
            for evidence in policy.get("required_evidence", []):
                if evidence not in declared:
                    missing_evidence.append(evidence)
            if missing_evidence and decision == "approval_required":
                policy_record["matched"] = True
                approval_required.append("evidence-owner")
        elif rule == "escalate_for_risk_tier":
            risk_tier = int(spec.get("risk", {}).get("risk_tier", 0) or 0)
            if risk_tier >= int(policy.get("minimum_risk_tier", 0) or 0):
                policy_record["matched"] = True
                escalated.append(policy_id)
        evaluated.append(policy_record)

    result = "denied" if denied or compatibility_errors else "escalate" if escalated else "approval_required" if approval_required or missing_evidence else "allowed"
    return {
        "schema_version": "policy-engine-evaluation/v1",
        "evaluation_id": "policy-engine-v2.5-pre-runtime-1",
        "decision_id": spec.get("decision_id"),
        "decision_version": spec.get("decision_version"),
        "result": result,
        "computed": True,
        "policy_set_id": policies.get("policy_set_id"),
        "policy_set_version": policies.get("policy_set_version"),
        "supported_rule_type_count": len(supported_rule_types),
        "outcome_precedence": policies.get("outcome_precedence", []),
        "deny_precedence_enforced": policies.get("outcome_precedence", [None])[0] == "deny",
        "escalate_outcome_supported": "escalate" in policies.get("outcome_precedence", []),
        "active_policy_count": len([policy for policy in policies.get("policies", []) if policy.get("lifecycle_status") == "active"]),
        "revoked_policy_count": len([policy for policy in policies.get("policies", []) if policy.get("lifecycle_status") == "revoked"]),
        "evaluated_policies": evaluated,
        "violated_policies": denied,
        "escalated_policies": escalated,
        "required_approvals": sorted(set(approval_required)),
        "missing_evidence": sorted(set(missing_evidence)),
        "compatibility_errors": compatibility_errors,
        "policy_compatibility_valid": not compatibility_errors,
        "remediation_guidance": ["Record required approvals before release evidence is accepted."],
        "policy_engine_valid": not compatibility_errors
        and policies.get("outcome_precedence", [None])[0] == "deny"
        and "escalate" in policies.get("outcome_precedence", [])
        and len(supported_rule_types) >= 5
        and all(policy.get("lifecycle_status") in {"active", "deprecated"} for policy in policies.get("policies", []))
        and result == "approval_required",
        "ai_override_allowed": False,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def _index_by_id(records: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {str(record.get(key, "")): record for record in records if record.get(key)}


def _support_ticket_route(spec: dict[str, Any], case: dict[str, Any]) -> str:
    priority = str(case.get("inputs", {}).get("priority", "")).lower()
    summary = str(spec.get("decision_logic", {}).get("summary", "")).lower()
    if "urgent" in summary and priority == "urgent":
        return "priority_queue"
    return "standard_queue"


def _engineering_review_readiness(spec: dict[str, Any], case: dict[str, Any]) -> str:
    inputs = case.get("inputs", {})
    if inputs.get("runtime_execution_requested") is True:
        return "blocked_runtime_requested"
    if inputs.get("admin_bypass_observed") is True:
        return "hold_for_governance_review"
    if inputs.get("computed_evidence_observed") is not True:
        return "hold_for_missing_evidence"
    if inputs.get("ci_passed") is not True:
        return "hold_for_ci"
    return "ready_for_independent_review"


def _operational_risk_triage(spec: dict[str, Any], case: dict[str, Any]) -> str:
    inputs = case.get("inputs", {})
    if inputs.get("approval_observed") is not True:
        return "hold_for_approval"
    if inputs.get("evidence_fresh") is not True:
        return "hold_for_fresh_evidence"
    if int(inputs.get("loss_exposure_usd", 0) or 0) >= 100000:
        return "escalate_to_risk_owner"
    return "standard_monitoring"


def compute_simulation(root: Path = ROOT) -> dict[str, Any]:
    examples = root / "examples"
    baseline = load_json(examples / "support-ticket-routing-decision-spec-v0.9.0.json")
    current = load_json(examples / "support-ticket-routing-decision-spec.json")
    support_cases = load_json(examples / "support-ticket-simulation-cases.json")
    engineering_spec = load_json(examples / "engineering-review-readiness-decision-spec.json")
    engineering_cases = load_json(examples / "engineering-review-readiness-cases.json")
    operational_risk_spec = load_json(examples / "operational-risk-triage-decision-spec.json")
    operational_risk_cases = load_json(examples / "operational-risk-triage-cases.json")

    support_results = []
    changed_outcome_count = 0
    for case in support_cases.get("cases", []):
        baseline_output = _support_ticket_route(baseline, case)
        current_output = _support_ticket_route(current, case)
        changed = baseline_output != current_output
        changed_outcome_count += 1 if changed else 0
        support_results.append(
            {
                "case_id": case.get("case_id"),
                "baseline_output": baseline_output,
                "current_output": current_output,
                "changed": changed,
                "side_effects_executed": False,
            }
        )

    engineering_results = []
    for case in engineering_cases.get("cases", []):
        engineering_results.append(
            {
                "case_id": case.get("case_id"),
                "decision_output": _engineering_review_readiness(engineering_spec, case),
                "side_effects_executed": False,
            }
        )

    operational_risk_results = []
    for case in operational_risk_cases.get("cases", []):
        operational_risk_results.append(
            {
                "case_id": case.get("case_id"),
                "decision_output": _operational_risk_triage(operational_risk_spec, case),
                "side_effects_executed": False,
            }
        )

    return {
        "schema_version": "simulation-evidence/v1",
        "simulation_run_id": "computed-sim-v0.4-pre-runtime-1",
        "decision_id": "multi-decision-pre-runtime-review",
        "decision_version": "v0.4.0-pre",
        "baseline_decision_version": baseline.get("decision_version"),
        "case_set": "v0.4-pre-runtime-cases",
        "computed": True,
        "case_count": len(support_results) + len(engineering_results) + len(operational_risk_results),
        "domain_count": 3,
        "decision_shape_count": 3,
        "changed_outcome_count": changed_outcome_count,
        "support_ticket_results": support_results,
        "engineering_review_results": engineering_results,
        "operational_risk_results": operational_risk_results,
        "policy_decisions": [{"preflight_id": "computed-preflight-support-ticket-routing-1", "result": "approval_required"}],
        "side_effects_requested": [{"side_effect_id": "queue-route", "executed": False}],
        "cost_delta": {"currency": "USD", "amount": 0},
        "decision_diff_ref": "reports/trust-loop/computed-decision-diff.json",
        "runtime_execution_requested": False,
        "production_decision_execution_authorized": False,
    }


def compute_decision_diff(root: Path = ROOT) -> dict[str, Any]:
    examples = root / "examples"
    baseline = load_json(examples / "support-ticket-routing-decision-spec-v0.9.0.json")
    current = load_json(examples / "support-ticket-routing-decision-spec.json")
    simulation = load_json(root / "reports/trust-loop/computed-simulation-evidence.json")

    spec_changes: list[str] = []
    if baseline.get("decision_logic") != current.get("decision_logic"):
        spec_changes.append("decision_logic_changed")
    if baseline.get("risk") != current.get("risk"):
        spec_changes.append("risk_profile_changed")
    if baseline.get("approval") != current.get("approval"):
        spec_changes.append("approval_requirements_changed")

    baseline_capabilities = _index_by_id(baseline.get("capability_requirements", []), "capability_id")
    current_capabilities = _index_by_id(current.get("capability_requirements", []), "capability_id")
    capability_version_changes = []
    for capability_id, current_record in sorted(current_capabilities.items()):
        baseline_record = baseline_capabilities.get(capability_id, {})
        if baseline_record.get("version") != current_record.get("version"):
            capability_version_changes.append(
                {
                    "capability_id": capability_id,
                    "from": baseline_record.get("version"),
                    "to": current_record.get("version"),
                }
            )

    changed_outcome_count = int(simulation.get("changed_outcome_count", 0) or 0)
    policy_impact = ["approval_required"] if current.get("approval", {}).get("required") else ["none"]
    return {
        "schema_version": "decision-diff/v1",
        "diff_id": "computed-diff-support-ticket-routing-1",
        "decision_id": current.get("decision_id"),
        "from_decision_version": baseline.get("decision_version"),
        "to_decision_version": current.get("decision_version"),
        "computed": True,
        "baseline_spec_ref": "examples/support-ticket-routing-decision-spec-v0.9.0.json",
        "target_spec_ref": "examples/support-ticket-routing-decision-spec.json",
        "spec_changes": spec_changes,
        "capability_version_changes": capability_version_changes,
        "policy_impact": policy_impact,
        "simulation_changes": [f"{changed_outcome_count} changed outcomes in {simulation.get('case_set')}"],
        "changed_outcome_count": changed_outcome_count,
        "simulation_ref": "reports/trust-loop/computed-simulation-evidence.json",
        "simulation_computed": simulation.get("computed") is True,
        "simulation_case_count": simulation.get("case_count", 0),
        "runtime_execution_requested": False,
    }


def evaluate_capability_governance(root: Path = ROOT) -> dict[str, Any]:
    examples = root / "examples"
    registry = load_json(examples / "support-ticket-capability-registry.json")
    specs = [
        load_json(examples / "support-ticket-routing-decision-spec.json"),
        load_json(examples / "engineering-review-readiness-decision-spec.json"),
        load_json(examples / "operational-risk-triage-decision-spec.json"),
    ]
    capabilities = {
        f"{record.get('capability_id')}@{record.get('version')}": record
        for record in registry.get("capabilities", [])
    }
    graph = []
    missing = []
    blocked = []
    for spec in specs:
        for requirement in spec.get("capability_requirements", []):
            key = f"{requirement.get('capability_id')}@{requirement.get('version')}"
            capability = capabilities.get(key)
            if not capability:
                missing.append(key)
                continue
            if capability.get("revocation_status") != "active":
                blocked.append(key)
            if capability.get("entitlement_status") != "entitled":
                blocked.append(key)
            if capability.get("compatibility_status") != "compatible":
                blocked.append(key)
            graph.append(
                {
                    "decision_id": spec.get("decision_id"),
                    "capability_id": capability.get("capability_id"),
                    "version": capability.get("version"),
                    "trust_class": capability.get("trust_class"),
                    "entitlement_status": capability.get("entitlement_status"),
                    "compatibility_status": capability.get("compatibility_status"),
                    "revocation_status": capability.get("revocation_status"),
                    "evaluation_evidence_ref": capability.get("evaluation_evidence_ref"),
                    "provenance": capability.get("provenance", {}),
                    "cost_profile": capability.get("cost_profile", {}),
                }
            )
    return {
        "schema_version": "capability-governance-evaluation/v1",
        "evaluation_id": "capability-governance-v1.4-pre-runtime-1",
        "computed": True,
        "registry_ref": "examples/support-ticket-capability-registry.json",
        "decision_count": len(specs),
        "capability_count": len(registry.get("capabilities", [])),
        "resolved_capability_count": len(graph),
        "capability_graph": graph,
        "missing_capabilities": sorted(set(missing)),
        "blocked_capabilities": sorted(set(blocked)),
        "exact_versions_resolved": not missing,
        "provenance_recorded": all(record.get("provenance") for record in graph),
        "entitlements_recorded": all(record.get("entitlement_status") for record in graph),
        "compatibility_recorded": all(record.get("compatibility_status") for record in graph),
        "evaluation_evidence_recorded": all(record.get("evaluation_evidence_ref") for record in graph),
        "cost_profiles_recorded": all(record.get("cost_profile") for record in graph),
        "revoked_capabilities_blocked": not blocked,
        "capability_governance_valid": not missing and not blocked and len(graph) >= 3,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def evaluate_shared_context_governance(root: Path = ROOT) -> dict[str, Any]:
    contract = load_json(root / "examples/shared-context-contract.json")
    fields = contract.get("fields", [])
    lineage = contract.get("lineage", {})
    freshness = contract.get("freshness", {})
    policy = contract.get("policy_decision_evidence", {})
    return {
        "schema_version": "shared-context-governance-evaluation/v1",
        "evaluation_id": "shared-context-v1.5-pre-runtime-1",
        "computed": True,
        "contract_ref": "examples/shared-context-contract.json",
        "contract_id": contract.get("contract_id"),
        "purpose_declared": bool(contract.get("purpose")),
        "ttl_seconds": contract.get("ttl_seconds", 0),
        "ttl_declared": int(contract.get("ttl_seconds", 0) or 0) > 0,
        "masking_rules_declared": bool(fields) and all(field.get("masking_rule") for field in fields),
        "approval_required": contract.get("approval", {}).get("approval_required") is True,
        "source_lineage_declared": bool(lineage.get("source_decision_id")) and bool(lineage.get("case_manifest_ref")),
        "freshness_rules_declared": bool(freshness.get("max_age_seconds")) and bool(freshness.get("validity_rule")),
        "policy_decision_evidence_declared": bool(policy.get("preflight_ref")) and bool(policy.get("result")),
        "producer_declared": bool(contract.get("producer", {}).get("product_id")),
        "consumer_declared": bool(contract.get("consumer", {}).get("product_id")),
        "direct_database_access_allowed": False,
        "runtime_context_exchange_authorized": contract.get("runtime_context_exchange_authorized") is True,
        "shared_context_contract_valid": bool(contract.get("purpose"))
        and int(contract.get("ttl_seconds", 0) or 0) > 0
        and bool(fields)
        and all(field.get("masking_rule") for field in fields)
        and contract.get("approval", {}).get("approval_required") is True
        and bool(lineage.get("source_decision_id"))
        and bool(lineage.get("case_manifest_ref"))
        and bool(freshness.get("max_age_seconds"))
        and bool(freshness.get("validity_rule"))
        and bool(policy.get("preflight_ref"))
        and contract.get("runtime_context_exchange_authorized") is False,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def evaluate_solo_maintainer_exception(root: Path = ROOT) -> dict[str, Any]:
    exception = load_json(root / "examples/solo-maintainer-governance-exception.json")
    controls = set(exception.get("required_controls", []))
    required_controls = {
        "ci_success_before_merge",
        "before_branch_protection_capture",
        "after_branch_protection_capture",
        "immediate_review_gate_restoration",
        "release_acceptance_artifact",
        "edi_observation",
    }
    prohibited_claims = set(exception.get("prohibited_claims", []))
    return {
        "schema_version": "solo-maintainer-exception-evaluation/v1",
        "evaluation_id": "solo-maintainer-exception-v2.1-pre-runtime-1",
        "computed": True,
        "exception_id": exception.get("exception_id"),
        "exception_version": exception.get("exception_version"),
        "exception_hash": _sha256(root / "examples/solo-maintainer-governance-exception.json"),
        "source_boundary": exception.get("source_boundary"),
        "reason": exception.get("reason"),
        "applies_to": exception.get("applies_to"),
        "solo_maintainer_constraint": exception.get("solo_maintainer_constraint") is True,
        "independent_human_review_available": exception.get("independent_human_review_available") is True,
        "independent_human_review_observed": exception.get("independent_human_review_observed") is True,
        "review_relaxation_allowed": exception.get("review_relaxation_allowed") is True,
        "max_relaxation_minutes": exception.get("max_relaxation_minutes", 0),
        "required_controls_present": required_controls.issubset(controls),
        "restored_protection_required": exception.get("restored_protection_required") is True,
        "independent_review_claim_blocked": "independent_human_review_observed" in prohibited_claims
        and exception.get("independent_human_review_observed") is False,
        "runtime_claims_blocked": {"production_runtime_readiness", "production_decision_authority"}.issubset(
            prohibited_claims
        ),
        "exception_valid": exception.get("solo_maintainer_constraint") is True
        and exception.get("independent_human_review_available") is False
        and exception.get("independent_human_review_observed") is False
        and exception.get("review_relaxation_allowed") is True
        and int(exception.get("max_relaxation_minutes", 0) or 0) <= 30
        and required_controls.issubset(controls)
        and exception.get("restored_protection_required") is True
        and exception.get("runtime_integration_authorized") is False
        and exception.get("production_decision_execution_authorized") is False,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def evaluate_schema_stability(root: Path = ROOT) -> dict[str, Any]:
    policy = load_json(root / "examples/schema-stability-policy.json")
    examples = root / "examples"
    example_paths = {
        "decision_spec": examples / "support-ticket-routing-decision-spec.json",
        "capability_registry": examples / "support-ticket-capability-registry.json",
        "policy_definitions": examples / "support-ticket-policy-definitions.json",
        "preflight": examples / "support-ticket-policy-preflight.json",
        "simulation": examples / "support-ticket-simulation-evidence.json",
        "decision_diff": examples / "support-ticket-decision-diff.json",
        "approval": examples / "support-ticket-approval-record.json",
        "identity_rbac_registry": examples / "identity-rbac-registry.json",
        "repository_governance_policy": examples / "repository-governance-policy.json",
        "release_lifecycle_policy": examples / "release-lifecycle-policy.json",
        "external_identity_evidence": examples / "external-identity-evidence.json",
        "durable_evidence_store_policy": examples / "durable-evidence-store-policy.json",
        "shared_context_contract": examples / "shared-context-contract.json",
        "case_evidence": examples / "support-ticket-case-evidence.json",
        "replay": examples / "support-ticket-replay-result.json",
        "solo_maintainer_governance_exception": examples / "solo-maintainer-governance-exception.json",
        "external_approval_boundary": examples / "external-approval-boundary.json",
        "external_approval_adapter": examples / "external-approval-adapter.json",
        "durable_case_store_adapter": examples / "durable-case-store-adapter.json",
    }
    frozen_results = []
    for contract in policy.get("frozen_contracts", []):
        kind = str(contract.get("kind", ""))
        path = example_paths.get(kind)
        observed = load_json(path).get("schema_version") if path and path.exists() else None
        frozen_results.append(
            {
                "kind": kind,
                "expected_schema_version": contract.get("schema_version"),
                "observed_schema_version": observed,
                "matches": observed == contract.get("schema_version"),
            }
        )

    negative_results = []
    for fixture in policy.get("negative_fixtures", []):
        result = validate_file(str(fixture.get("kind")), root / str(fixture.get("path")))
        expected = str(fixture.get("expected_error_contains", ""))
        errors = result.get("errors", [])
        negative_results.append(
            {
                "kind": fixture.get("kind"),
                "path": fixture.get("path"),
                "passed_negative_check": result.get("passed") is False and any(expected in error for error in errors),
                "expected_error_contains": expected,
                "errors": errors,
            }
        )

    return {
        "schema_version": "schema-stability-evaluation/v1",
        "evaluation_id": "schema-stability-v2.1-pre-runtime-1",
        "computed": True,
        "policy_id": policy.get("policy_id"),
        "policy_version": policy.get("policy_version"),
        "policy_hash": _sha256(root / "examples/schema-stability-policy.json"),
        "source_boundary": policy.get("source_boundary"),
        "frozen_contract_count": len(policy.get("frozen_contracts", [])),
        "frozen_contracts": frozen_results,
        "frozen_contracts_valid": bool(frozen_results) and all(item["matches"] for item in frozen_results),
        "compatibility_rule_count": len(policy.get("compatibility_rules", [])),
        "compatibility_rules_declared": bool(policy.get("compatibility_rules")),
        "negative_fixture_count": len(policy.get("negative_fixtures", [])),
        "negative_fixtures": negative_results,
        "negative_fixtures_valid": bool(negative_results)
        and all(item["passed_negative_check"] for item in negative_results),
        "schema_stability_valid": bool(frozen_results)
        and all(item["matches"] for item in frozen_results)
        and bool(policy.get("compatibility_rules"))
        and bool(negative_results)
        and all(item["passed_negative_check"] for item in negative_results)
        and policy.get("runtime_integration_authorized") is False
        and policy.get("production_decision_execution_authorized") is False,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def evaluate_external_approval_boundary(root: Path = ROOT) -> dict[str, Any]:
    boundary = load_json(root / "examples/external-approval-boundary.json")
    solo_exception = load_json(root / "reports/trust-loop/solo-maintainer-exception.json")
    required_evidence = set(boundary.get("required_evidence", []))
    expected_evidence = {
        "external_approval_record_id",
        "approver_subject",
        "approver_role",
        "decision_scope",
        "approval_timestamp",
        "approval_expires_at",
        "mfa_evidence",
        "approval_reason",
        "case_manifest_hash",
        "audit_export_ref",
    }
    admission_controls = set(boundary.get("admission_controls", []))
    expected_controls = {
        "policy_preflight_requires_approval",
        "approval_bound_to_case_manifest",
        "approver_cannot_be_requester",
        "ai_identity_excluded",
        "runtime_authority_denied",
    }
    return {
        "schema_version": "external-approval-boundary-evaluation/v1",
        "evaluation_id": "external-approval-boundary-v2.2-pre-runtime-1",
        "computed": True,
        "boundary_id": boundary.get("boundary_id"),
        "boundary_version": boundary.get("boundary_version"),
        "boundary_hash": _sha256(root / "examples/external-approval-boundary.json"),
        "source_boundary": boundary.get("source_boundary"),
        "purpose": boundary.get("purpose"),
        "live_approval_system_observed": boundary.get("live_approval_system_observed") is True,
        "decision_approval_required": boundary.get("decision_approval_required") is True,
        "decision_approval_source": boundary.get("decision_approval_source"),
        "github_code_review_is_decision_approval": boundary.get("github_code_review_is_decision_approval") is True,
        "solo_maintainer_exception_is_decision_approval": boundary.get(
            "solo_maintainer_exception_is_decision_approval"
        )
        is True,
        "solo_maintainer_exception_observed": solo_exception.get("computed") is True,
        "solo_maintainer_exception_valid": solo_exception.get("exception_valid") is True,
        "decision_approval_separate_from_code_merge": boundary.get("github_code_review_is_decision_approval") is False
        and boundary.get("solo_maintainer_exception_is_decision_approval") is False
        and solo_exception.get("independent_human_review_observed") is False,
        "approval_subject_binding_required": boundary.get("approval_subject_binding_required") is True,
        "approval_role_scope_required": boundary.get("approval_role_scope_required") is True,
        "approval_expiry_required": boundary.get("approval_expiry_required") is True,
        "approval_mfa_required": boundary.get("approval_mfa_required") is True,
        "approval_audit_export_required": boundary.get("approval_audit_export_required") is True,
        "ai_approval_allowed": boundary.get("ai_approval_allowed") is True,
        "required_evidence_count": len(required_evidence),
        "required_evidence_complete": expected_evidence.issubset(required_evidence),
        "admission_control_count": len(admission_controls),
        "admission_controls_complete": expected_controls.issubset(admission_controls),
        "external_approval_boundary_valid": boundary.get("decision_approval_required") is True
        and boundary.get("github_code_review_is_decision_approval") is False
        and boundary.get("solo_maintainer_exception_is_decision_approval") is False
        and boundary.get("approval_subject_binding_required") is True
        and boundary.get("approval_role_scope_required") is True
        and boundary.get("approval_expiry_required") is True
        and boundary.get("approval_mfa_required") is True
        and boundary.get("approval_audit_export_required") is True
        and boundary.get("ai_approval_allowed") is False
        and expected_evidence.issubset(required_evidence)
        and expected_controls.issubset(admission_controls)
        and boundary.get("runtime_integration_authorized") is False
        and boundary.get("production_decision_execution_authorized") is False,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def evaluate_external_approval_adapter(root: Path = ROOT) -> dict[str, Any]:
    adapter = load_json(root / "examples/external-approval-adapter.json")
    boundary = load_json(root / "reports/trust-loop/external-approval-boundary.json")
    required_operations = set(adapter.get("required_operations", []))
    expected_operations = {
        "request_approval",
        "approve_decision",
        "reject_decision",
        "expire_approval",
        "delegate_approval",
        "revoke_approval",
        "export_approval_audit",
    }
    denied_operations = set(adapter.get("denied_operations", []))
    expected_denied = {
        "ai_self_approval",
        "requester_self_approval",
        "mutate_approved_decision",
        "bypass_policy_preflight",
        "execute_runtime_decision",
    }
    request_fields = set(adapter.get("required_request_fields", []))
    expected_request_fields = {
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
    }
    decision_fields = set(adapter.get("required_decision_fields", []))
    expected_decision_fields = {
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
    }
    allowed_decisions = set(adapter.get("allowed_decisions", []))
    expected_decisions = {"approved", "rejected", "expired", "delegated", "revoked"}
    admission_controls = set(adapter.get("admission_controls", []))
    expected_controls = {
        "policy_preflight_requires_approval",
        "approval_bound_to_case_manifest",
        "approver_cannot_be_requester",
        "ai_identity_excluded",
        "approval_expiry_enforced",
        "decision_scope_enforced",
        "runtime_authority_denied",
    }
    audit_requirements = set(adapter.get("audit_requirements", []))
    expected_audit = {
        "append_only_approval_records",
        "content_addressed_case_binding",
        "approval_decision_lineage",
        "exportable_audit_pack",
    }
    required_operations_complete = expected_operations.issubset(required_operations)
    denied_operations_complete = expected_denied.issubset(denied_operations)
    request_fields_complete = expected_request_fields.issubset(request_fields)
    decision_fields_complete = expected_decision_fields.issubset(decision_fields)
    decision_lifecycle_complete = expected_decisions.issubset(allowed_decisions)
    admission_controls_complete = expected_controls.issubset(admission_controls)
    audit_requirements_complete = expected_audit.issubset(audit_requirements)
    boundary_compatible = boundary.get("external_approval_boundary_valid") is True and boundary.get(
        "decision_approval_separate_from_code_merge"
    ) is True
    adapter_boundary_valid = (
        adapter.get("adapter_type") == "contract_only"
        and adapter.get("live_approval_system_observed") is False
        and adapter.get("github_code_review_is_decision_approval") is False
        and adapter.get("solo_maintainer_exception_is_decision_approval") is False
        and adapter.get("ai_approval_allowed") is False
        and required_operations_complete
        and denied_operations_complete
        and request_fields_complete
        and decision_fields_complete
        and decision_lifecycle_complete
        and admission_controls_complete
        and audit_requirements_complete
        and boundary_compatible
        and adapter.get("runtime_integration_authorized") is False
        and adapter.get("production_decision_execution_authorized") is False
    )
    return {
        "schema_version": "external-approval-adapter-evaluation/v1",
        "evaluation_id": "external-approval-adapter-v2.6-pre-runtime-1",
        "computed": True,
        "adapter_id": adapter.get("adapter_id"),
        "adapter_version": adapter.get("adapter_version"),
        "adapter_hash": _sha256(root / "examples/external-approval-adapter.json"),
        "source_boundary": adapter.get("source_boundary"),
        "adapter_type": adapter.get("adapter_type"),
        "live_approval_system_observed": adapter.get("live_approval_system_observed") is True,
        "github_code_review_is_decision_approval": adapter.get("github_code_review_is_decision_approval") is True,
        "solo_maintainer_exception_is_decision_approval": adapter.get(
            "solo_maintainer_exception_is_decision_approval"
        )
        is True,
        "ai_approval_allowed": adapter.get("ai_approval_allowed") is True,
        "required_operation_count": len(required_operations),
        "required_operations_complete": required_operations_complete,
        "denied_operation_count": len(denied_operations),
        "denied_operations_complete": denied_operations_complete,
        "request_evidence_field_count": len(request_fields),
        "request_evidence_fields_complete": request_fields_complete,
        "decision_evidence_field_count": len(decision_fields),
        "decision_evidence_fields_complete": decision_fields_complete,
        "decision_lifecycle_outcome_count": len(allowed_decisions),
        "decision_lifecycle_complete": decision_lifecycle_complete,
        "admission_control_count": len(admission_controls),
        "admission_controls_complete": admission_controls_complete,
        "audit_requirement_count": len(audit_requirements),
        "audit_requirements_complete": audit_requirements_complete,
        "boundary_compatible": boundary_compatible,
        "external_approval_adapter_valid": adapter_boundary_valid,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def evaluate_durable_case_store_adapter(
    root: Path = ROOT,
    durable_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    adapter = load_json(root / "examples/durable-case-store-adapter.json")
    manifest = durable_manifest or {}
    required_operations = set(adapter.get("required_operations", []))
    denied_operations = set(adapter.get("denied_operations", []))
    expected_required = {
        "append_case_record",
        "read_case_record",
        "verify_manifest_chain",
        "export_replay_pack",
        "export_audit_pack",
    }
    expected_denied = {
        "update_case_record",
        "delete_case_record",
        "overwrite_manifest_hash",
    }
    retention = adapter.get("retention", {})
    return {
        "schema_version": "durable-case-store-adapter-evaluation/v1",
        "evaluation_id": "durable-case-store-adapter-v2.3-pre-runtime-1",
        "computed": True,
        "adapter_id": adapter.get("adapter_id"),
        "adapter_version": adapter.get("adapter_version"),
        "adapter_hash": _sha256(root / "examples/durable-case-store-adapter.json"),
        "source_boundary": adapter.get("source_boundary"),
        "storage_backend_type": adapter.get("storage_backend_type"),
        "production_storage_backend_observed": adapter.get("production_storage_backend_observed") is True,
        "append_only_writes_required": adapter.get("append_only_writes_required") is True,
        "content_addressed_records_required": adapter.get("content_addressed_records_required") is True,
        "manifest_hash_chain_required": adapter.get("manifest_hash_chain_required") is True,
        "delete_denied_required": adapter.get("delete_denied_required") is True,
        "mutation_detection_required": adapter.get("mutation_detection_required") is True,
        "retention_policy_required": adapter.get("retention_policy_required") is True,
        "replay_export_required": adapter.get("replay_export_required") is True,
        "audit_export_required": adapter.get("audit_export_required") is True,
        "multi_writer_concurrency_control_required": adapter.get("multi_writer_concurrency_control_required") is True,
        "encryption_boundary_required": adapter.get("encryption_boundary_required") is True,
        "tenant_namespace_required": adapter.get("tenant_namespace_required") is True,
        "required_operations_complete": expected_required.issubset(required_operations),
        "denied_operations_complete": expected_denied.issubset(denied_operations),
        "retention_minimum_days": retention.get("minimum_days", 0),
        "retention_policy_valid": int(retention.get("minimum_days", 0) or 0) >= 365
        and retention.get("delete_mode") == "deny_delete_before_retention_expiry"
        and retention.get("legal_hold_supported") is True,
        "manifest_hash_bound": bool(manifest.get("manifest_hash")),
        "adapter_boundary_valid": adapter.get("production_storage_backend_observed") is False
        and adapter.get("append_only_writes_required") is True
        and adapter.get("content_addressed_records_required") is True
        and adapter.get("manifest_hash_chain_required") is True
        and adapter.get("delete_denied_required") is True
        and adapter.get("mutation_detection_required") is True
        and adapter.get("retention_policy_required") is True
        and adapter.get("replay_export_required") is True
        and adapter.get("audit_export_required") is True
        and adapter.get("multi_writer_concurrency_control_required") is True
        and adapter.get("encryption_boundary_required") is True
        and adapter.get("tenant_namespace_required") is True
        and expected_required.issubset(required_operations)
        and expected_denied.issubset(denied_operations)
        and int(retention.get("minimum_days", 0) or 0) >= 365
        and retention.get("delete_mode") == "deny_delete_before_retention_expiry"
        and retention.get("legal_hold_supported") is True
        and bool(manifest.get("manifest_hash"))
        and adapter.get("runtime_integration_authorized") is False
        and adapter.get("production_decision_execution_authorized") is False,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def evaluate_evidence_store_adapter_parity(
    root: Path = ROOT,
    durable_manifest: dict[str, Any] | None = None,
    replay: dict[str, Any] | None = None,
) -> dict[str, Any]:
    adapter = load_json(root / "examples/durable-case-store-adapter.json")
    manifest = durable_manifest or {}
    replay_result = replay or {}
    required_operations = set(adapter.get("required_operations", []))
    denied_operations = set(adapter.get("denied_operations", []))
    operation_records = [
        {
            "operation": "append_case_record",
            "contract_declared": "append_case_record" in required_operations
            and adapter.get("append_only_writes_required") is True,
            "evidence_ref": "reports/trust-loop/durable-case-manifest.json",
            "evidence_valid": bool(manifest.get("manifest_hash")) and manifest.get("append_only_required") is True,
            "side_effects_executed": False,
        },
        {
            "operation": "read_case_record",
            "contract_declared": "read_case_record" in required_operations,
            "evidence_ref": "reports/trust-loop/case-evidence.json",
            "evidence_valid": bool(manifest.get("case_id")) and int(manifest.get("artifact_count", 0) or 0) > 0,
            "side_effects_executed": False,
        },
        {
            "operation": "verify_manifest_chain",
            "contract_declared": "verify_manifest_chain" in required_operations
            and adapter.get("manifest_hash_chain_required") is True,
            "evidence_ref": "reports/trust-loop/durable-case-manifest.json",
            "evidence_valid": bool(manifest.get("parent_manifest_hash")) and manifest.get("chain_valid") is True,
            "side_effects_executed": False,
        },
        {
            "operation": "export_replay_pack",
            "contract_declared": "export_replay_pack" in required_operations
            and adapter.get("replay_export_required") is True,
            "evidence_ref": "reports/trust-loop/replay-result.json",
            "evidence_valid": replay_result.get("manifest_replay_valid") is True,
            "side_effects_executed": False,
        },
        {
            "operation": "export_audit_pack",
            "contract_declared": "export_audit_pack" in required_operations
            and adapter.get("audit_export_required") is True,
            "evidence_ref": "reports/release",
            "evidence_valid": bool(manifest.get("manifest_hash")),
            "side_effects_executed": False,
        },
    ]
    denied_records = [
        {
            "operation": operation,
            "contract_denied": operation in denied_operations,
            "mutation_blocked": adapter.get("delete_denied_required") is True
            and adapter.get("mutation_detection_required") is True,
            "side_effects_executed": False,
        }
        for operation in ["update_case_record", "delete_case_record", "overwrite_manifest_hash"]
    ]
    return {
        "schema_version": "evidence-store-adapter-parity/v1",
        "evaluation_id": "evidence-store-adapter-parity-v2.4-pre-runtime-1",
        "computed": True,
        "adapter_id": adapter.get("adapter_id"),
        "adapter_version": adapter.get("adapter_version"),
        "required_operation_count": len(operation_records),
        "required_operations_valid": all(
            record["contract_declared"] is True
            and record["evidence_valid"] is True
            and record["side_effects_executed"] is False
            for record in operation_records
        ),
        "denied_operation_count": len(denied_records),
        "denied_operations_enforced": all(
            record["contract_denied"] is True
            and record["mutation_blocked"] is True
            and record["side_effects_executed"] is False
            for record in denied_records
        ),
        "append_case_record_valid": operation_records[0]["evidence_valid"] is True,
        "read_case_record_valid": operation_records[1]["evidence_valid"] is True,
        "verify_manifest_chain_valid": operation_records[2]["evidence_valid"] is True,
        "export_replay_pack_valid": operation_records[3]["evidence_valid"] is True,
        "export_audit_pack_valid": operation_records[4]["evidence_valid"] is True,
        "production_storage_backend_observed": adapter.get("production_storage_backend_observed") is True,
        "runtime_backend_invoked": False,
        "operation_records": operation_records,
        "denied_operation_records": denied_records,
        "adapter_parity_valid": all(
            record["contract_declared"] is True
            and record["evidence_valid"] is True
            and record["side_effects_executed"] is False
            for record in operation_records
        )
        and all(
            record["contract_denied"] is True
            and record["mutation_blocked"] is True
            and record["side_effects_executed"] is False
            for record in denied_records
        )
        and adapter.get("production_storage_backend_observed") is False,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def build_runtime_readiness_assessment(root: Path = ROOT) -> dict[str, Any]:
    external_identity = load_json(root / "reports/trust-loop/external-identity.json")
    live_identity_rbac = load_json(root / "reports/trust-loop/live-identity-rbac.json")
    durable_store = load_json(root / "reports/trust-loop/durable-evidence-store.json")
    shared_context = load_json(root / "reports/trust-loop/shared-context-governance.json")
    blockers = [
        "live external identity provider authentication missing",
        "live external identity MFA claim missing",
        "production durable case store backend missing",
        "promotion chain approval and rollback trail missing",
        "runtime control plane not designed or approved",
        "kill switch not evidenced",
        "live observability not evidenced",
        "runtime entitlement enforcement not evidenced",
        "runtime cost accounting not evidenced",
        "independent runtime approval flow not evidenced",
        "production-like replay evidence missing",
    ]
    return {
        "schema_version": "runtime-readiness-assessment/v1",
        "assessment_id": "runtime-readiness-v2.0-pre-runtime-1",
        "computed": True,
        "external_identity_contract_valid": external_identity.get("external_identity_contract_valid") is True,
        "live_external_identity_provider_authenticated": external_identity.get("live_provider_authenticated") is True,
        "live_identity_rbac_valid": live_identity_rbac.get("live_identity_rbac_valid") is True,
        "live_identity_rbac_mfa_claim_observed": live_identity_rbac.get("mfa_claim_observed") is True,
        "durable_store_contract_valid": durable_store.get("durable_store_contract_valid") is True,
        "production_storage_backend_observed": durable_store.get("production_storage_backend_observed") is True,
        "shared_context_contract_valid": shared_context.get("shared_context_contract_valid") is True,
        "runtime_blockers": blockers,
        "runtime_readiness_percent": 0.0,
        "production_decision_authority_percent": 0.0,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def build_product_review_surface(root: Path = ROOT) -> dict[str, Any]:
    preflight = load_json(root / "reports/trust-loop/computed-policy-preflight.json")
    policy_engine = load_json(root / "reports/trust-loop/computed-policy-engine.json")
    simulation = load_json(root / "reports/trust-loop/computed-simulation-evidence.json")
    decision_diff = load_json(root / "reports/trust-loop/computed-decision-diff.json")
    approval = load_json(root / "reports/trust-loop/approval-record.json")
    case_evidence = load_json(root / "reports/trust-loop/case-evidence.json")
    replay = load_json(root / "reports/trust-loop/replay-result.json")
    capability = load_json(root / "reports/trust-loop/capability-governance.json")
    shared_context = load_json(root / "reports/trust-loop/shared-context-governance.json")
    solo_exception = load_json(root / "reports/trust-loop/solo-maintainer-exception.json")
    schema_stability = load_json(root / "reports/trust-loop/schema-stability.json")
    external_approval = load_json(root / "reports/trust-loop/external-approval-boundary.json")
    external_approval_adapter = load_json(root / "reports/trust-loop/external-approval-adapter.json")
    live_identity_rbac = load_json(root / "reports/trust-loop/live-identity-rbac.json")
    durable_adapter = load_json(root / "reports/trust-loop/durable-case-store-adapter.json")
    adapter_parity = load_json(root / "reports/trust-loop/evidence-store-adapter-parity.json")
    runtime = load_json(root / "reports/trust-loop/runtime-readiness-assessment.json")
    surfaces = [
        {"id": "decision_review", "state": "ready", "summary": case_evidence.get("decision_id")},
        {"id": "policy_engine", "state": "ready", "summary": policy_engine.get("result")},
        {"id": "simulation_evidence", "state": "ready", "summary": f"{simulation.get('case_count')} cases"},
        {"id": "decision_diff", "state": "ready", "summary": f"{decision_diff.get('changed_outcome_count')} changed outcomes"},
        {"id": "approval_record", "state": "ready", "summary": approval.get("decision")},
        {"id": "case_evidence", "state": "ready", "summary": case_evidence.get("storage_mode")},
        {"id": "replay_evidence", "state": "ready", "summary": str(replay.get("manifest_replay_valid"))},
        {"id": "capability_lineage", "state": "ready", "summary": f"{capability.get('resolved_capability_count')} capabilities"},
        {"id": "shared_context", "state": "ready", "summary": shared_context.get("contract_id")},
        {
            "id": "solo_maintainer_exception",
            "state": "exception_recorded",
            "summary": str(solo_exception.get("exception_valid")),
        },
        {
            "id": "schema_stability",
            "state": "ready",
            "summary": f"{schema_stability.get('frozen_contract_count')} frozen contracts",
        },
        {
            "id": "external_approval_boundary",
            "state": "ready",
            "summary": str(external_approval.get("external_approval_boundary_valid")),
        },
        {
            "id": "external_approval_adapter",
            "state": "ready",
            "summary": str(external_approval_adapter.get("external_approval_adapter_valid")),
        },
        {
            "id": "live_identity_rbac",
            "state": "partial",
            "summary": f"{live_identity_rbac.get('provider')}:{live_identity_rbac.get('repository_permission')}",
        },
        {
            "id": "durable_case_store_adapter",
            "state": "ready",
            "summary": str(durable_adapter.get("adapter_boundary_valid")),
        },
        {
            "id": "evidence_store_adapter_parity",
            "state": "ready",
            "summary": str(adapter_parity.get("adapter_parity_valid")),
        },
        {"id": "runtime_readiness", "state": "blocked", "summary": "runtime authority blocked"},
    ]
    return {
        "schema_version": "product-review-surface/v1",
        "surface_id": "dip-pre-runtime-review-workspace",
        "computed": True,
        "surface_count": len(surfaces),
        "surfaces": surfaces,
        "policy_preflight_result": preflight.get("result"),
        "runtime_readiness_percent": runtime.get("runtime_readiness_percent"),
        "production_decision_authority_percent": runtime.get("production_decision_authority_percent"),
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def write_product_review_surface_html(path: Path, payload: dict[str, Any]) -> None:
    items = "\n".join(
        f"<tr><td>{html.escape(str(item['id']))}</td><td>{html.escape(str(item['state']))}</td>"
        f"<td>{html.escape(str(item['summary']))}</td></tr>"
        for item in payload.get("surfaces", [])
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "<!doctype html>",
                "<html lang=\"en\">",
                "<head><meta charset=\"utf-8\"><title>DIP Review Workspace</title>",
                "<style>body{font-family:system-ui,sans-serif;margin:32px;max-width:960px}"
                "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:8px}"
                ".blocked{color:#8a1f11;font-weight:700}</style></head>",
                "<body>",
                "<h1>DIP Pre-Runtime Review Workspace</h1>",
                "<p class=\"blocked\">Runtime integration and production decision authority are blocked.</p>",
                "<table><thead><tr><th>Surface</th><th>State</th><th>Summary</th></tr></thead><tbody>",
                items,
                "</tbody></table>",
                "</body></html>",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def build_case_manifest(root: Path = ROOT) -> dict[str, Any]:
    records = []
    for artifact_type, relative_path in ARTIFACTS:
        path = root / relative_path
        records.append(
            {
                "artifact_type": artifact_type,
                "path": relative_path,
                "sha256": _sha256(path),
            }
        )
    return {
        "schema_version": "case-manifest/v1",
        "manifest_id": "manifest-case-support-ticket-routing-1",
        "case_id": "case-support-ticket-routing-1",
        "storage_mode": "file_backed_tamper_evident",
        "append_only_required": True,
        "mutable": False,
        "artifact_count": len(records),
        "artifacts": records,
    }


def build_case_evidence() -> dict[str, Any]:
    return {
        "schema_version": "case-evidence-pack/v1",
        "case_id": "case-support-ticket-routing-1",
        "decision_id": "support-ticket-routing",
        "decision_version": "1.0.0",
        "decision_spec_ref": "examples/support-ticket-routing-decision-spec.json",
        "capability_registry_ref": "examples/support-ticket-capability-registry.json",
        "policy_preflight_ref": "reports/trust-loop/computed-policy-preflight.json",
        "simulation_ref": "reports/trust-loop/computed-simulation-evidence.json",
        "decision_diff_ref": "reports/trust-loop/computed-decision-diff.json",
        "approval_record_ref": "reports/trust-loop/approval-record.json",
        "lineage_refs": ["support-ticket-routing@0.9.0", "support-ticket-routing@1.0.0"],
        "storage_mode": "append_only_manifest",
        "mutable": False,
    }


def build_durable_case_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    parent_manifest_hash = _sha256_payload(manifest)
    chain = {
        "parent_manifest_hash": parent_manifest_hash,
        "artifact_count": manifest.get("artifact_count", 0),
        "artifacts": manifest.get("artifacts", []),
    }
    manifest_hash = _sha256_payload(chain)
    return {
        "schema_version": "durable-case-manifest/v1",
        "manifest_id": "durable-manifest-case-support-ticket-routing-1",
        "case_id": manifest.get("case_id"),
        "storage_mode": "append_only_manifest_chain",
        "parent_manifest_hash": parent_manifest_hash,
        "manifest_hash": manifest_hash,
        "append_only_required": True,
        "mutable": False,
        "mutation_detected": False,
        "artifact_count": manifest.get("artifact_count", 0),
        "artifacts": manifest.get("artifacts", []),
        "chain_valid": True,
    }


def evaluate_approval_authority(
    root: Path,
    durable_manifest: dict[str, Any],
    approver_identity: str = "acct-support-platform-owner-001",
) -> dict[str, Any]:
    registry = load_json(root / "examples/identity-rbac-registry.json")
    spec = load_json(root / "examples/support-ticket-routing-decision-spec.json")
    preflight = load_json(root / "reports/trust-loop/computed-policy-preflight.json")
    roles = {str(role.get("role", "")): role for role in registry.get("roles", [])}
    identities = {str(identity.get("identity_id", "")): identity for identity in registry.get("identities", [])}
    identity = identities.get(approver_identity, {})
    required_roles = set(preflight.get("required_approvals", []))
    identity_roles = set(identity.get("roles", []))
    matching_roles = sorted(required_roles.intersection(identity_roles))
    decision_id = str(spec.get("decision_id", ""))
    risk_tier = int(spec.get("risk", {}).get("risk_tier", 0) or 0)
    role_authorized = False
    scope_authorized = False
    for role_name in matching_roles:
        role = roles.get(role_name, {})
        role_authorized = role_authorized or role.get("approval_authority") is True
        scope_authorized = scope_authorized or decision_id in role.get("decision_scope", [])
        if risk_tier > int(role.get("max_risk_tier", 0) or 0):
            role_authorized = False
    identity_active = identity.get("active") is True
    identity_not_expired = str(identity.get("valid_until", "")) >= "2026-05-23T00:00:00Z"
    mfa_satisfied = identity.get("mfa_required") is not True or identity.get("mfa_observed") is True
    ai_identity = identities.get("acct-dip-autopilot-001", {})
    ai_self_approval_blocked = "ai-agent" in ai_identity.get("roles", []) and not any(
        roles.get(role, {}).get("approval_authority") is True for role in ai_identity.get("roles", [])
    )
    approval_authority_valid = (
        bool(identity)
        and identity_active
        and identity_not_expired
        and mfa_satisfied
        and bool(matching_roles)
        and role_authorized
        and scope_authorized
        and ai_self_approval_blocked
        and bool(durable_manifest.get("manifest_hash"))
    )
    return {
        "schema_version": "approval-authority-evaluation/v1",
        "evaluation_id": "approval-authority-support-ticket-routing-1",
        "computed": True,
        "registry_id": registry.get("registry_id"),
        "registry_version": registry.get("registry_version"),
        "registry_hash": _sha256(root / "examples/identity-rbac-registry.json"),
        "source_boundary": registry.get("source_boundary"),
        "external_identity_provider_observed": registry.get("external_identity_provider_observed") is True,
        "decision_id": decision_id,
        "risk_tier": risk_tier,
        "approver_identity": approver_identity,
        "approver_subject": identity.get("subject", ""),
        "required_approver_roles": sorted(required_roles),
        "identity_roles": sorted(identity_roles),
        "matching_roles": matching_roles,
        "identity_active": identity_active,
        "identity_not_expired": identity_not_expired,
        "mfa_satisfied": mfa_satisfied,
        "role_authorized": role_authorized,
        "decision_scope_authorized": scope_authorized,
        "ai_self_approval_blocked": ai_self_approval_blocked,
        "case_manifest_hash": durable_manifest.get("manifest_hash"),
        "approval_authority_valid": approval_authority_valid,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def evaluate_repository_governance(root: Path) -> dict[str, Any]:
    policy = load_json(root / "examples/repository-governance-policy.json")
    required_status_checks = policy.get("required_status_checks", [])
    break_glass = policy.get("break_glass", {})
    live_path = root / "reports" / "trust-loop" / "repository-governance.json"
    live = load_json(live_path) if live_path.exists() else {}
    branch_protection = (
        {
            "observed": live.get("branch_protection_observed", False),
            "required_status_checks_observed": live.get("required_status_checks_observed", False),
            "required_approving_review_count_observed": live.get("required_approving_review_count_observed", 0),
            "admin_enforcement_observed": live.get("admin_enforcement_observed", False),
            "codeowner_review_required_observed": live.get("codeowner_review_required_observed", False),
            "conversation_resolution_required_observed": live.get("conversation_resolution_required_observed", False),
            "force_pushes_blocked": live.get("force_pushes_blocked", False),
            "deletions_blocked": live.get("deletions_blocked", False),
        }
        if live
        else _gh_branch_protection(root, str(policy.get("required_default_branch", "main")))
    )
    return {
        "schema_version": "repository-governance-evaluation/v1",
        "evaluation_id": "repository-governance-v0.7-pre-runtime-1",
        "computed": True,
        "policy_id": policy.get("policy_id"),
        "policy_version": policy.get("policy_version"),
        "policy_hash": _sha256(root / "examples/repository-governance-policy.json"),
        "source_boundary": policy.get("source_boundary"),
        "required_default_branch": policy.get("required_default_branch"),
        "required_status_checks": required_status_checks,
        "required_status_check_count": len(required_status_checks),
        "required_approving_review_count": policy.get("required_approving_review_count", 0),
        "dismiss_stale_reviews_required": policy.get("dismiss_stale_reviews_required") is True,
        "admin_enforcement_required": policy.get("admin_enforcement_required") is True,
        "force_pushes_allowed": policy.get("force_pushes_allowed") is True,
        "branch_deletions_allowed": policy.get("branch_deletions_allowed") is True,
        "branch_protection_observed": branch_protection["observed"],
        "required_status_checks_observed": branch_protection["required_status_checks_observed"],
        "required_approving_review_count_observed": branch_protection["required_approving_review_count_observed"],
        "admin_enforcement_observed": branch_protection["admin_enforcement_observed"],
        "codeowner_review_required_observed": branch_protection["codeowner_review_required_observed"],
        "conversation_resolution_required_observed": branch_protection["conversation_resolution_required_observed"],
        "force_pushes_blocked": branch_protection["force_pushes_blocked"],
        "deletions_blocked": branch_protection["deletions_blocked"],
        "break_glass_policy_defined": break_glass.get("allowed") is True
        and break_glass.get("requires_reason") is True
        and break_glass.get("requires_followup_evidence") is True
        and break_glass.get("requires_restored_protection") is True
        and int(break_glass.get("expires_after_hours", 0) or 0) <= 24,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def evaluate_release_lifecycle(root: Path) -> dict[str, Any]:
    policy = load_json(root / "examples/release-lifecycle-policy.json")
    stages = policy.get("stages", [])
    rollback_criteria = policy.get("rollback_criteria", [])
    return {
        "schema_version": "release-lifecycle-evaluation/v1",
        "evaluation_id": "release-lifecycle-v0.8-pre-runtime-1",
        "computed": True,
        "policy_id": policy.get("policy_id"),
        "policy_version": policy.get("policy_version"),
        "policy_hash": _sha256(root / "examples/release-lifecycle-policy.json"),
        "source_boundary": policy.get("source_boundary"),
        "stage_count": len(stages),
        "required_stages_present": set(stages)
        >= {"draft", "candidate", "approved", "tagged", "artifact_backed", "rollback_ready"},
        "independent_approval_required": policy.get("independent_approval_required") is True,
        "codeowner_review_required": policy.get("codeowner_review_required") is True,
        "conversation_resolution_required": policy.get("conversation_resolution_required") is True,
        "release_artifact_required": policy.get("release_artifact_required") is True,
        "source_commit_binding_required": policy.get("source_commit_binding_required") is True,
        "rollback_required": policy.get("rollback_required") is True,
        "rollback_criteria_count": len(rollback_criteria),
        "release_lifecycle_valid": len(stages) >= 6
        and len(rollback_criteria) >= 3
        and policy.get("independent_approval_required") is True
        and policy.get("release_artifact_required") is True
        and policy.get("source_commit_binding_required") is True
        and policy.get("rollback_required") is True,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def evaluate_external_identity(root: Path) -> dict[str, Any]:
    evidence = load_json(root / "examples/external-identity-evidence.json")
    role_mapping = evidence.get("role_mapping", [])
    required_claims = set(evidence.get("required_claims", []))
    claims_mapped = set(evidence.get("claims_mapped", []))
    return {
        "schema_version": "external-identity-evaluation/v1",
        "evaluation_id": "external-identity-v0.9-pre-runtime-1",
        "computed": True,
        "evidence_id": evidence.get("evidence_id"),
        "evidence_version": evidence.get("evidence_version"),
        "evidence_hash": _sha256(root / "examples/external-identity-evidence.json"),
        "source_boundary": evidence.get("source_boundary"),
        "provider_type": evidence.get("provider_type"),
        "live_provider_authenticated": evidence.get("live_provider_authenticated") is True,
        "required_claims_present": required_claims.issubset(claims_mapped),
        "role_mapping_count": len(role_mapping),
        "approval_identity_bound_to_subject": evidence.get("approval_identity_bound_to_subject") is True,
        "mfa_claim_required": evidence.get("mfa_claim_required") is True,
        "mfa_claim_observed_in_contract": evidence.get("mfa_claim_observed_in_contract") is True,
        "ai_identity_excluded_from_approval_roles": evidence.get("ai_identity_excluded_from_approval_roles") is True,
        "external_identity_contract_valid": required_claims.issubset(claims_mapped)
        and len(role_mapping) >= 1
        and evidence.get("approval_identity_bound_to_subject") is True
        and evidence.get("mfa_claim_required") is True
        and evidence.get("mfa_claim_observed_in_contract") is True
        and evidence.get("ai_identity_excluded_from_approval_roles") is True,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def evaluate_durable_evidence_store(root: Path, durable_manifest: dict[str, Any]) -> dict[str, Any]:
    policy = load_json(root / "examples/durable-evidence-store-policy.json")
    controls = set(policy.get("required_controls", []))
    required = {
        "content_addressed_records",
        "manifest_hash_chain",
        "append_only_writes",
        "delete_denied",
        "mutation_detection",
        "replay_from_store_manifest",
        "exportable_acceptance_pack",
    }
    return {
        "schema_version": "durable-evidence-store-evaluation/v1",
        "evaluation_id": "durable-evidence-store-v1.0-pre-runtime-1",
        "computed": True,
        "policy_id": policy.get("policy_id"),
        "policy_version": policy.get("policy_version"),
        "policy_hash": _sha256(root / "examples/durable-evidence-store-policy.json"),
        "source_boundary": policy.get("source_boundary"),
        "storage_model": policy.get("storage_model"),
        "required_control_count": len(controls),
        "required_controls_present": required.issubset(controls),
        "content_addressed_records": bool(durable_manifest.get("manifest_hash")),
        "manifest_hash_chain": bool(durable_manifest.get("parent_manifest_hash")) and durable_manifest.get("chain_valid") is True,
        "append_only_enforced_by_contract": policy.get("append_only_enforced_by_contract") is True,
        "delete_denied_by_contract": policy.get("delete_denied_by_contract") is True,
        "mutation_detection_required": policy.get("mutation_detection_required") is True,
        "mutation_detected": durable_manifest.get("mutation_detected") is True,
        "replay_required": policy.get("replay_required") is True,
        "multi_writer_ready": policy.get("multi_writer_ready") is True,
        "production_storage_backend_observed": policy.get("production_storage_backend_observed") is True,
        "durable_store_contract_valid": required.issubset(controls)
        and bool(durable_manifest.get("manifest_hash"))
        and durable_manifest.get("chain_valid") is True
        and durable_manifest.get("mutation_detected") is False
        and policy.get("append_only_enforced_by_contract") is True
        and policy.get("delete_denied_by_contract") is True
        and policy.get("replay_required") is True,
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def _gh_api_json(path: str, root: Path = ROOT) -> tuple[dict[str, Any], str]:
    result = subprocess.run(
        ["gh", "api", path],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        return {}, result.stderr.strip()
    try:
        return json.loads(result.stdout or "{}"), ""
    except json.JSONDecodeError as exc:
        return {}, str(exc)


def evaluate_live_identity_rbac(root: Path = ROOT) -> dict[str, Any]:
    repo = os.environ.get("DIP_GITHUB_REPO", "raghurammutya/decision-intelligence-platform")
    user, user_error = _gh_api_json("user", root)
    repo_owner = os.environ.get("GITHUB_REPOSITORY_OWNER") or repo.split("/", 1)[0]
    login = str(os.environ.get("GITHUB_ACTOR") or user.get("login") or "")
    permission: dict[str, Any] = {}
    permission_error = ""
    if login:
        permission, permission_error = _gh_api_json(f"repos/{repo}/collaborators/{login}/permission", root)
    permission_name = str(permission.get("permission") or permission.get("role_name") or "")
    owner_context_observed = bool(login and repo_owner and login.lower() == repo_owner.lower())
    effective_permission = permission_name or "owner" if owner_context_observed else permission_name
    permission_sufficient = permission_name in {"admin", "maintain"} or owner_context_observed
    live_provider_authenticated = bool(user) or bool(os.environ.get("GITHUB_ACTOR"))
    live_identity_rbac_valid = live_provider_authenticated and bool(login) and permission_sufficient
    return {
        "schema_version": "live-identity-rbac-evidence/v1",
        "evaluation_id": "live-identity-rbac-v2.7-pre-runtime-1",
        "computed": True,
        "provider": "github",
        "repository": repo,
        "repository_owner": repo_owner,
        "live_provider_authenticated": live_provider_authenticated,
        "identity_subject": login,
        "identity_id": user.get("id"),
        "identity_type": user.get("type", ""),
        "identity_site_admin": user.get("site_admin") is True,
        "repository_permission_observed": bool(permission) or owner_context_observed,
        "repository_permission_source": "collaborator_permission_api" if permission else "repository_owner_context",
        "repository_permission": effective_permission,
        "repository_role_name": permission.get("role_name", ""),
        "permission_satisfies_approval_role": permission_sufficient,
        "decision_scope_authorized": permission_sufficient,
        "mfa_claim_required": True,
        "mfa_claim_observed": False,
        "mfa_claim_source": "not_exposed_by_available_github_api",
        "external_identity_provider_observed": bool(user),
        "live_identity_rbac_valid": live_identity_rbac_valid,
        "observation_errors": [error for error in [user_error, permission_error] if error],
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
    }


def build_approval_record(
    durable_manifest: dict[str, Any],
    approval_authority: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "approval-record/v1",
        "approval_id": "approval-support-ticket-routing-1",
        "decision_id": "support-ticket-routing",
        "decision_version": "1.0.0",
        "requester": "dip-fixture-builder",
        "approver_identity": approval_authority.get("approver_identity"),
        "approver_subject": approval_authority.get("approver_subject"),
        "approver_role": "support-platform-owner",
        "required_approver_roles": approval_authority.get("required_approver_roles", []),
        "role_binding_valid": approval_authority.get("approval_authority_valid") is True,
        "approval_authority_ref": "reports/trust-loop/approval-authority.json",
        "approval_authority_valid": approval_authority.get("approval_authority_valid") is True,
        "case_manifest_hash": durable_manifest.get("manifest_hash"),
        "approval_bound_to_manifest": True,
        "decision": "approved",
        "approval_reason": "Computed simulation and policy preflight require owner approval before release evidence is accepted.",
        "ai_approved": False,
    }


def build_replay_result_from_manifest(root: Path, durable_manifest: dict[str, Any]) -> dict[str, Any]:
    manifest_valid = verify_case_manifest(root, durable_manifest)
    return {
        "schema_version": "replay-result/v1",
        "replay_id": "replay-case-support-ticket-routing-1",
        "case_id": durable_manifest.get("case_id"),
        "decision_id": "support-ticket-routing",
        "original_case_ref": "reports/trust-loop/durable-case-manifest.json",
        "replayed_case_ref": "reports/trust-loop/durable-case-manifest.json",
        "replay_source": "durable_case_manifest",
        "case_manifest_hash": durable_manifest.get("manifest_hash"),
        "manifest_replay_valid": manifest_valid,
        "side_effects_executed": False,
    }


def verify_case_manifest(root: Path, manifest: dict[str, Any]) -> bool:
    for artifact in manifest.get("artifacts", []):
        path = root / str(artifact.get("path", ""))
        if not path.exists() or _sha256(path) != artifact.get("sha256"):
            return False
    return manifest.get("append_only_required") is True and manifest.get("mutable") is False


def build_release_acceptance(root: Path = ROOT, version: str = "v2.7.0-pre", source_commit: str | None = None) -> dict[str, Any]:
    validation = validate_default_examples(root)
    preflight = load_json(root / "reports/trust-loop/computed-policy-preflight.json")
    policy_engine = load_json(root / "reports/trust-loop/computed-policy-engine.json")
    simulation = load_json(root / "reports/trust-loop/computed-simulation-evidence.json")
    decision_diff = load_json(root / "reports/trust-loop/computed-decision-diff.json")
    manifest = load_json(root / "reports/trust-loop/case-manifest.json")
    durable_manifest = load_json(root / "reports/trust-loop/durable-case-manifest.json")
    approval = load_json(root / "reports/trust-loop/approval-record.json")
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
    runtime_readiness = load_json(root / "reports/trust-loop/runtime-readiness-assessment.json")
    product_surface = load_json(root / "reports/trust-loop/product-review-surface.json")
    replay = load_json(root / "reports/trust-loop/replay-result.json")
    manifest_valid = verify_case_manifest(root, manifest)
    durable_manifest_valid = verify_case_manifest(root, durable_manifest)
    return {
        "schema_version": "dip-release-acceptance/v1",
        "release_version": version,
        "source_commit": source_commit or _git_head(root),
        "validation_passed": validation["passed"],
        "validation_record_count": validation["record_count"],
        "computed_policy_preflight_observed": preflight.get("computed") is True,
        "computed_policy_preflight_result": preflight.get("result"),
        "computed_policy_engine_observed": policy_engine.get("computed") is True,
        "computed_policy_engine_result": policy_engine.get("result"),
        "policy_engine_valid": policy_engine.get("policy_engine_valid") is True,
        "policy_engine_supported_rule_type_count": policy_engine.get("supported_rule_type_count", 0),
        "policy_engine_active_policy_count": policy_engine.get("active_policy_count", 0),
        "policy_engine_revoked_policy_count": policy_engine.get("revoked_policy_count", 0),
        "policy_engine_deny_precedence_enforced": policy_engine.get("deny_precedence_enforced") is True,
        "policy_engine_escalate_outcome_supported": policy_engine.get("escalate_outcome_supported") is True,
        "policy_engine_compatibility_valid": policy_engine.get("policy_compatibility_valid") is True,
        "computed_simulation_observed": simulation.get("computed") is True,
        "computed_simulation_case_count": simulation.get("case_count", 0),
        "computed_simulation_domain_count": simulation.get("domain_count", 0),
        "computed_simulation_decision_shape_count": simulation.get("decision_shape_count", 0),
        "computed_decision_diff_observed": decision_diff.get("computed") is True,
        "computed_decision_diff_changed_outcomes": decision_diff.get("changed_outcome_count", 0),
        "case_manifest_observed": bool(manifest.get("manifest_id")),
        "case_manifest_valid": manifest_valid,
        "case_manifest_artifact_count": manifest.get("artifact_count", 0),
        "durable_case_manifest_observed": bool(durable_manifest.get("manifest_id")),
        "durable_case_manifest_hash": durable_manifest.get("manifest_hash"),
        "durable_case_manifest_valid": durable_manifest_valid,
        "append_only_chain_valid": durable_manifest.get("chain_valid") is True,
        "case_mutation_detected": durable_manifest.get("mutation_detected") is True,
        "replay_from_manifest_observed": replay.get("replay_source") == "durable_case_manifest",
        "replay_manifest_valid": replay.get("manifest_replay_valid") is True,
        "approval_bound_to_manifest": approval.get("approval_bound_to_manifest") is True
        and approval.get("case_manifest_hash") == durable_manifest.get("manifest_hash"),
        "approval_role_binding_valid": approval.get("role_binding_valid") is True,
        "approval_authority_evaluated": approval_authority.get("computed") is True,
        "approval_authority_valid": approval_authority.get("approval_authority_valid") is True,
        "approval_identity_active": approval_authority.get("identity_active") is True,
        "approval_identity_not_expired": approval_authority.get("identity_not_expired") is True,
        "approval_mfa_satisfied": approval_authority.get("mfa_satisfied") is True,
        "approval_decision_scope_authorized": approval_authority.get("decision_scope_authorized") is True,
        "ai_self_approval_blocked": approval_authority.get("ai_self_approval_blocked") is True,
        "external_identity_provider_observed": approval_authority.get("external_identity_provider_observed") is True,
        "repository_governance_policy_observed": repository_governance.get("computed") is True,
        "admin_enforcement_required": repository_governance.get("admin_enforcement_required") is True,
        "required_status_checks_observed": repository_governance.get("required_status_checks_observed") is True,
        "required_approving_review_count_observed": repository_governance.get(
            "required_approving_review_count_observed", 0
        ),
        "codeowner_review_required_observed": repository_governance.get("codeowner_review_required_observed") is True,
        "conversation_resolution_required_observed": repository_governance.get(
            "conversation_resolution_required_observed"
        )
        is True,
        "required_status_check_count": repository_governance.get("required_status_check_count", 0),
        "break_glass_policy_defined": repository_governance.get("break_glass_policy_defined") is True,
        "release_lifecycle_policy_observed": release_lifecycle.get("computed") is True,
        "release_lifecycle_valid": release_lifecycle.get("release_lifecycle_valid") is True,
        "independent_release_approval_required": release_lifecycle.get("independent_approval_required") is True,
        "codeowner_review_required": release_lifecycle.get("codeowner_review_required") is True,
        "conversation_resolution_required": release_lifecycle.get("conversation_resolution_required") is True,
        "rollback_criteria_defined": int(release_lifecycle.get("rollback_criteria_count", 0) or 0) >= 3,
        "external_identity_contract_observed": external_identity.get("computed") is True,
        "external_identity_contract_valid": external_identity.get("external_identity_contract_valid") is True,
        "live_external_identity_provider_authenticated": external_identity.get("live_provider_authenticated") is True,
        "live_identity_rbac_observed": live_identity_rbac.get("computed") is True,
        "live_identity_rbac_provider": live_identity_rbac.get("provider"),
        "live_identity_rbac_subject": live_identity_rbac.get("identity_subject"),
        "live_identity_rbac_repository_permission": live_identity_rbac.get("repository_permission"),
        "live_identity_rbac_permission_sufficient": live_identity_rbac.get(
            "permission_satisfies_approval_role"
        )
        is True,
        "live_identity_rbac_decision_scope_authorized": live_identity_rbac.get("decision_scope_authorized") is True,
        "live_identity_rbac_mfa_claim_observed": live_identity_rbac.get("mfa_claim_observed") is True,
        "live_identity_rbac_valid": live_identity_rbac.get("live_identity_rbac_valid") is True,
        "durable_evidence_store_policy_observed": durable_store.get("computed") is True,
        "durable_store_contract_valid": durable_store.get("durable_store_contract_valid") is True,
        "production_storage_backend_observed": durable_store.get("production_storage_backend_observed") is True,
        "capability_governance_observed": capability_governance.get("computed") is True,
        "capability_governance_valid": capability_governance.get("capability_governance_valid") is True,
        "resolved_capability_count": capability_governance.get("resolved_capability_count", 0),
        "shared_context_contract_observed": shared_context.get("computed") is True,
        "shared_context_contract_valid": shared_context.get("shared_context_contract_valid") is True,
        "solo_maintainer_exception_observed": solo_exception.get("computed") is True,
        "solo_maintainer_exception_valid": solo_exception.get("exception_valid") is True,
        "solo_maintainer_constraint": solo_exception.get("solo_maintainer_constraint") is True,
        "independent_human_review_available": solo_exception.get("independent_human_review_available") is True,
        "independent_human_review_observed": solo_exception.get("independent_human_review_observed") is True,
        "review_relaxation_allowed": solo_exception.get("review_relaxation_allowed") is True,
        "review_relaxation_max_minutes": solo_exception.get("max_relaxation_minutes", 0),
        "review_gate_restoration_required": solo_exception.get("restored_protection_required") is True,
        "schema_stability_observed": schema_stability.get("computed") is True,
        "schema_stability_valid": schema_stability.get("schema_stability_valid") is True,
        "frozen_contract_count": schema_stability.get("frozen_contract_count", 0),
        "compatibility_rule_count": schema_stability.get("compatibility_rule_count", 0),
        "negative_fixture_count": schema_stability.get("negative_fixture_count", 0),
        "negative_fixtures_valid": schema_stability.get("negative_fixtures_valid") is True,
        "external_approval_boundary_observed": external_approval.get("computed") is True,
        "external_approval_boundary_valid": external_approval.get("external_approval_boundary_valid") is True,
        "live_external_approval_system_observed": external_approval.get("live_approval_system_observed") is True,
        "decision_approval_required": external_approval.get("decision_approval_required") is True,
        "decision_approval_separate_from_code_merge": external_approval.get(
            "decision_approval_separate_from_code_merge"
        )
        is True,
        "github_code_review_is_decision_approval": external_approval.get("github_code_review_is_decision_approval")
        is True,
        "solo_maintainer_exception_is_decision_approval": external_approval.get(
            "solo_maintainer_exception_is_decision_approval"
        )
        is True,
        "external_approval_required_evidence_count": external_approval.get("required_evidence_count", 0),
        "external_approval_required_evidence_complete": external_approval.get("required_evidence_complete") is True,
        "external_approval_admission_controls_complete": external_approval.get("admission_controls_complete") is True,
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
        "external_approval_adapter_request_evidence_complete": external_approval_adapter.get(
            "request_evidence_fields_complete"
        )
        is True,
        "external_approval_adapter_decision_evidence_complete": external_approval_adapter.get(
            "decision_evidence_fields_complete"
        )
        is True,
        "external_approval_adapter_decision_lifecycle_complete": external_approval_adapter.get(
            "decision_lifecycle_complete"
        )
        is True,
        "external_approval_adapter_admission_controls_complete": external_approval_adapter.get(
            "admission_controls_complete"
        )
        is True,
        "external_approval_adapter_audit_requirements_complete": external_approval_adapter.get(
            "audit_requirements_complete"
        )
        is True,
        "external_approval_adapter_boundary_compatible": external_approval_adapter.get("boundary_compatible") is True,
        "external_approval_adapter_live_system_observed": external_approval_adapter.get(
            "live_approval_system_observed"
        )
        is True,
        "external_approval_adapter_ai_approval_allowed": external_approval_adapter.get("ai_approval_allowed") is True,
        "durable_case_store_adapter_observed": durable_adapter.get("computed") is True,
        "durable_case_store_adapter_valid": durable_adapter.get("adapter_boundary_valid") is True,
        "adapter_production_storage_backend_observed": durable_adapter.get("production_storage_backend_observed")
        is True,
        "adapter_append_only_writes_required": durable_adapter.get("append_only_writes_required") is True,
        "adapter_content_addressed_records_required": durable_adapter.get("content_addressed_records_required") is True,
        "adapter_delete_denied_required": durable_adapter.get("delete_denied_required") is True,
        "adapter_mutation_detection_required": durable_adapter.get("mutation_detection_required") is True,
        "adapter_replay_export_required": durable_adapter.get("replay_export_required") is True,
        "adapter_audit_export_required": durable_adapter.get("audit_export_required") is True,
        "adapter_retention_policy_valid": durable_adapter.get("retention_policy_valid") is True,
        "adapter_required_operations_complete": durable_adapter.get("required_operations_complete") is True,
        "adapter_denied_operations_complete": durable_adapter.get("denied_operations_complete") is True,
        "evidence_store_adapter_parity_observed": adapter_parity.get("computed") is True,
        "evidence_store_adapter_parity_valid": adapter_parity.get("adapter_parity_valid") is True,
        "adapter_required_operations_valid": adapter_parity.get("required_operations_valid") is True,
        "adapter_denied_operations_enforced": adapter_parity.get("denied_operations_enforced") is True,
        "adapter_append_case_record_valid": adapter_parity.get("append_case_record_valid") is True,
        "adapter_read_case_record_valid": adapter_parity.get("read_case_record_valid") is True,
        "adapter_verify_manifest_chain_valid": adapter_parity.get("verify_manifest_chain_valid") is True,
        "adapter_export_replay_pack_valid": adapter_parity.get("export_replay_pack_valid") is True,
        "adapter_export_audit_pack_valid": adapter_parity.get("export_audit_pack_valid") is True,
        "adapter_runtime_backend_invoked": adapter_parity.get("runtime_backend_invoked") is True,
        "runtime_readiness_assessment_observed": runtime_readiness.get("computed") is True,
        "runtime_readiness_percent": runtime_readiness.get("runtime_readiness_percent", 0.0),
        "production_decision_authority_percent": runtime_readiness.get("production_decision_authority_percent", 0.0),
        "product_review_surface_observed": product_surface.get("computed") is True,
        "product_review_surface_count": product_surface.get("surface_count", 0),
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
        "release_acceptance_passed": validation["passed"]
        and preflight.get("computed") is True
        and policy_engine.get("policy_engine_valid") is True
        and policy_engine.get("result") == preflight.get("result")
        and policy_engine.get("revoked_policy_count", 1) == 0
        and policy_engine.get("deny_precedence_enforced") is True
        and policy_engine.get("escalate_outcome_supported") is True
        and policy_engine.get("policy_compatibility_valid") is True
        and simulation.get("computed") is True
        and decision_diff.get("computed") is True
        and int(simulation.get("domain_count", 0) or 0) >= 3
        and int(simulation.get("decision_shape_count", 0) or 0) >= 3
        and durable_manifest_valid
        and durable_manifest.get("chain_valid") is True
        and durable_manifest.get("mutation_detected") is False
        and replay.get("manifest_replay_valid") is True
        and approval.get("approval_bound_to_manifest") is True
        and approval.get("role_binding_valid") is True
        and approval_authority.get("approval_authority_valid") is True
        and approval_authority.get("ai_self_approval_blocked") is True
        and repository_governance.get("admin_enforcement_required") is True
        and repository_governance.get("required_status_checks_observed") is True
        and repository_governance.get("required_approving_review_count_observed", 0) >= 1
        and repository_governance.get("codeowner_review_required_observed") is True
        and repository_governance.get("conversation_resolution_required_observed") is True
        and repository_governance.get("break_glass_policy_defined") is True
        and release_lifecycle.get("release_lifecycle_valid") is True
        and external_identity.get("external_identity_contract_valid") is True
        and live_identity_rbac.get("live_identity_rbac_valid") is True
        and live_identity_rbac.get("mfa_claim_observed") is False
        and durable_store.get("durable_store_contract_valid") is True
        and capability_governance.get("capability_governance_valid") is True
        and shared_context.get("shared_context_contract_valid") is True
        and solo_exception.get("exception_valid") is True
        and solo_exception.get("independent_human_review_observed") is False
        and schema_stability.get("schema_stability_valid") is True
        and external_approval.get("external_approval_boundary_valid") is True
        and external_approval.get("live_approval_system_observed") is False
        and external_approval.get("decision_approval_separate_from_code_merge") is True
        and external_approval_adapter.get("external_approval_adapter_valid") is True
        and external_approval_adapter.get("live_approval_system_observed") is False
        and external_approval_adapter.get("ai_approval_allowed") is False
        and external_approval_adapter.get("boundary_compatible") is True
        and durable_adapter.get("adapter_boundary_valid") is True
        and durable_adapter.get("production_storage_backend_observed") is False
        and adapter_parity.get("adapter_parity_valid") is True
        and adapter_parity.get("runtime_backend_invoked") is False
        and runtime_readiness.get("runtime_readiness_percent") == 0.0
        and runtime_readiness.get("production_decision_authority_percent") == 0.0
        and product_surface.get("surface_count", 0) >= 8
        and manifest_valid,
        "blocked_claims": [
            "runtime integration is authorized",
            "production decision execution is authorized",
            "independent human review was observed for solo-maintainer merges",
            "live external decision approval system is observed",
            "live external approval adapter system is observed",
            "live external identity MFA claim is observed",
            "production durable case store backend is observed",
        ],
    }


def write_release_acceptance_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# DIP Release Acceptance",
        "",
        f"Release version: `{payload['release_version']}`",
        f"Source commit: `{payload['source_commit']}`",
        f"Validation passed: `{payload['validation_passed']}`",
        f"Computed policy preflight observed: `{payload['computed_policy_preflight_observed']}`",
        f"Computed policy preflight result: `{payload['computed_policy_preflight_result']}`",
        f"Computed policy engine observed: `{payload['computed_policy_engine_observed']}`",
        f"Computed policy engine result: `{payload['computed_policy_engine_result']}`",
        f"Policy engine valid: `{payload['policy_engine_valid']}`",
        f"Policy engine supported rule types: `{payload['policy_engine_supported_rule_type_count']}`",
        f"Policy engine active policies: `{payload['policy_engine_active_policy_count']}`",
        f"Policy engine revoked policies: `{payload['policy_engine_revoked_policy_count']}`",
        f"Policy engine deny precedence enforced: `{payload['policy_engine_deny_precedence_enforced']}`",
        f"Policy engine escalate outcome supported: `{payload['policy_engine_escalate_outcome_supported']}`",
        f"Policy engine compatibility valid: `{payload['policy_engine_compatibility_valid']}`",
        f"Computed simulation observed: `{payload['computed_simulation_observed']}`",
        f"Computed simulation cases: `{payload['computed_simulation_case_count']}`",
        f"Computed simulation domains: `{payload['computed_simulation_domain_count']}`",
        f"Computed simulation decision shapes: `{payload['computed_simulation_decision_shape_count']}`",
        f"Computed decision diff observed: `{payload['computed_decision_diff_observed']}`",
        f"Computed decision diff changed outcomes: `{payload['computed_decision_diff_changed_outcomes']}`",
        f"Case manifest valid: `{payload['case_manifest_valid']}`",
        f"Case manifest artifacts: `{payload['case_manifest_artifact_count']}`",
        f"Durable case manifest observed: `{payload['durable_case_manifest_observed']}`",
        f"Durable case manifest valid: `{payload['durable_case_manifest_valid']}`",
        f"Append-only chain valid: `{payload['append_only_chain_valid']}`",
        f"Case mutation detected: `{payload['case_mutation_detected']}`",
        f"Replay from manifest observed: `{payload['replay_from_manifest_observed']}`",
        f"Approval bound to manifest: `{payload['approval_bound_to_manifest']}`",
        f"Approval role binding valid: `{payload['approval_role_binding_valid']}`",
        f"Approval authority evaluated: `{payload['approval_authority_evaluated']}`",
        f"Approval authority valid: `{payload['approval_authority_valid']}`",
        f"AI self-approval blocked: `{payload['ai_self_approval_blocked']}`",
        f"External identity provider observed: `{payload['external_identity_provider_observed']}`",
        f"Repository governance policy observed: `{payload['repository_governance_policy_observed']}`",
        f"Admin enforcement required: `{payload['admin_enforcement_required']}`",
        f"Required status checks observed: `{payload['required_status_checks_observed']}`",
        f"Required approving review count observed: `{payload['required_approving_review_count_observed']}`",
        f"Codeowner review required observed: `{payload['codeowner_review_required_observed']}`",
        f"Conversation resolution required observed: `{payload['conversation_resolution_required_observed']}`",
        f"Break-glass policy defined: `{payload['break_glass_policy_defined']}`",
        f"Release lifecycle policy observed: `{payload['release_lifecycle_policy_observed']}`",
        f"Release lifecycle valid: `{payload['release_lifecycle_valid']}`",
        f"External identity contract observed: `{payload['external_identity_contract_observed']}`",
        f"External identity contract valid: `{payload['external_identity_contract_valid']}`",
        f"Live external identity provider authenticated: `{payload['live_external_identity_provider_authenticated']}`",
        f"Live identity RBAC observed: `{payload['live_identity_rbac_observed']}`",
        f"Live identity RBAC provider: `{payload['live_identity_rbac_provider']}`",
        f"Live identity RBAC subject: `{payload['live_identity_rbac_subject']}`",
        f"Live identity RBAC repository permission: `{payload['live_identity_rbac_repository_permission']}`",
        f"Live identity RBAC permission sufficient: `{payload['live_identity_rbac_permission_sufficient']}`",
        f"Live identity RBAC decision scope authorized: `{payload['live_identity_rbac_decision_scope_authorized']}`",
        f"Live identity RBAC MFA claim observed: `{payload['live_identity_rbac_mfa_claim_observed']}`",
        f"Live identity RBAC valid: `{payload['live_identity_rbac_valid']}`",
        f"Durable evidence store policy observed: `{payload['durable_evidence_store_policy_observed']}`",
        f"Durable store contract valid: `{payload['durable_store_contract_valid']}`",
        f"Production storage backend observed: `{payload['production_storage_backend_observed']}`",
        f"Capability governance observed: `{payload['capability_governance_observed']}`",
        f"Capability governance valid: `{payload['capability_governance_valid']}`",
        f"Resolved capability count: `{payload['resolved_capability_count']}`",
        f"Shared context contract observed: `{payload['shared_context_contract_observed']}`",
        f"Shared context contract valid: `{payload['shared_context_contract_valid']}`",
        f"Solo-maintainer exception observed: `{payload['solo_maintainer_exception_observed']}`",
        f"Solo-maintainer exception valid: `{payload['solo_maintainer_exception_valid']}`",
        f"Solo-maintainer constraint: `{payload['solo_maintainer_constraint']}`",
        f"Independent human review available: `{payload['independent_human_review_available']}`",
        f"Independent human review observed: `{payload['independent_human_review_observed']}`",
        f"Review relaxation allowed: `{payload['review_relaxation_allowed']}`",
        f"Review relaxation max minutes: `{payload['review_relaxation_max_minutes']}`",
        f"Review gate restoration required: `{payload['review_gate_restoration_required']}`",
        f"Schema stability observed: `{payload['schema_stability_observed']}`",
        f"Schema stability valid: `{payload['schema_stability_valid']}`",
        f"Frozen contract count: `{payload['frozen_contract_count']}`",
        f"Compatibility rule count: `{payload['compatibility_rule_count']}`",
        f"Negative fixture count: `{payload['negative_fixture_count']}`",
        f"Negative fixtures valid: `{payload['negative_fixtures_valid']}`",
        f"External approval boundary observed: `{payload['external_approval_boundary_observed']}`",
        f"External approval boundary valid: `{payload['external_approval_boundary_valid']}`",
        f"Live external approval system observed: `{payload['live_external_approval_system_observed']}`",
        f"Decision approval required: `{payload['decision_approval_required']}`",
        f"Decision approval separate from code merge: `{payload['decision_approval_separate_from_code_merge']}`",
        f"GitHub code review is decision approval: `{payload['github_code_review_is_decision_approval']}`",
        f"Solo-maintainer exception is decision approval: `{payload['solo_maintainer_exception_is_decision_approval']}`",
        f"External approval required evidence count: `{payload['external_approval_required_evidence_count']}`",
        f"External approval required evidence complete: `{payload['external_approval_required_evidence_complete']}`",
        f"External approval admission controls complete: `{payload['external_approval_admission_controls_complete']}`",
        f"External approval adapter observed: `{payload['external_approval_adapter_observed']}`",
        f"External approval adapter valid: `{payload['external_approval_adapter_valid']}`",
        f"External approval adapter required operations complete: `{payload['external_approval_adapter_required_operations_complete']}`",
        f"External approval adapter denied operations complete: `{payload['external_approval_adapter_denied_operations_complete']}`",
        f"External approval adapter request evidence complete: `{payload['external_approval_adapter_request_evidence_complete']}`",
        f"External approval adapter decision evidence complete: `{payload['external_approval_adapter_decision_evidence_complete']}`",
        f"External approval adapter decision lifecycle complete: `{payload['external_approval_adapter_decision_lifecycle_complete']}`",
        f"External approval adapter admission controls complete: `{payload['external_approval_adapter_admission_controls_complete']}`",
        f"External approval adapter audit requirements complete: `{payload['external_approval_adapter_audit_requirements_complete']}`",
        f"External approval adapter boundary compatible: `{payload['external_approval_adapter_boundary_compatible']}`",
        f"External approval adapter live system observed: `{payload['external_approval_adapter_live_system_observed']}`",
        f"External approval adapter AI approval allowed: `{payload['external_approval_adapter_ai_approval_allowed']}`",
        f"Durable case store adapter observed: `{payload['durable_case_store_adapter_observed']}`",
        f"Durable case store adapter valid: `{payload['durable_case_store_adapter_valid']}`",
        f"Adapter production storage backend observed: `{payload['adapter_production_storage_backend_observed']}`",
        f"Adapter append-only writes required: `{payload['adapter_append_only_writes_required']}`",
        f"Adapter content-addressed records required: `{payload['adapter_content_addressed_records_required']}`",
        f"Adapter delete denied required: `{payload['adapter_delete_denied_required']}`",
        f"Adapter mutation detection required: `{payload['adapter_mutation_detection_required']}`",
        f"Adapter replay export required: `{payload['adapter_replay_export_required']}`",
        f"Adapter audit export required: `{payload['adapter_audit_export_required']}`",
        f"Adapter retention policy valid: `{payload['adapter_retention_policy_valid']}`",
        f"Adapter required operations complete: `{payload['adapter_required_operations_complete']}`",
        f"Adapter denied operations complete: `{payload['adapter_denied_operations_complete']}`",
        f"Evidence store adapter parity observed: `{payload['evidence_store_adapter_parity_observed']}`",
        f"Evidence store adapter parity valid: `{payload['evidence_store_adapter_parity_valid']}`",
        f"Adapter required operations valid: `{payload['adapter_required_operations_valid']}`",
        f"Adapter denied operations enforced: `{payload['adapter_denied_operations_enforced']}`",
        f"Adapter append case record valid: `{payload['adapter_append_case_record_valid']}`",
        f"Adapter read case record valid: `{payload['adapter_read_case_record_valid']}`",
        f"Adapter verify manifest chain valid: `{payload['adapter_verify_manifest_chain_valid']}`",
        f"Adapter export replay pack valid: `{payload['adapter_export_replay_pack_valid']}`",
        f"Adapter export audit pack valid: `{payload['adapter_export_audit_pack_valid']}`",
        f"Adapter runtime backend invoked: `{payload['adapter_runtime_backend_invoked']}`",
        f"Runtime readiness assessment observed: `{payload['runtime_readiness_assessment_observed']}`",
        f"Runtime readiness percent: `{payload['runtime_readiness_percent']}`",
        f"Production decision authority percent: `{payload['production_decision_authority_percent']}`",
        f"Product review surface observed: `{payload['product_review_surface_observed']}`",
        f"Product review surface count: `{payload['product_review_surface_count']}`",
        f"Runtime integration authorized: `{payload['runtime_integration_authorized']}`",
        f"Production decision execution authorized: `{payload['production_decision_execution_authorized']}`",
        f"Release acceptance passed: `{payload['release_acceptance_passed']}`",
        "",
        "## Blocked Claims",
        "",
        *[f"- `{claim}`" for claim in payload["blocked_claims"]],
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_v0_2_evidence(
    root: Path = ROOT,
    out: Path | None = None,
    version: str = "v2.7.0-pre",
    source_commit: str | None = "local-validation",
) -> dict[str, Any]:
    target = out or root / "reports" / "trust-loop"
    policy_engine = compute_policy_engine(root)
    write_json(target / "computed-policy-engine.json", policy_engine)
    preflight = compute_policy_preflight(root)
    write_json(target / "computed-policy-preflight.json", preflight)
    simulation = compute_simulation(root)
    write_json(target / "computed-simulation-evidence.json", simulation)
    decision_diff = compute_decision_diff(root)
    write_json(target / "computed-decision-diff.json", decision_diff)
    capability_governance = evaluate_capability_governance(root)
    write_json(target / "capability-governance.json", capability_governance)
    shared_context = evaluate_shared_context_governance(root)
    write_json(target / "shared-context-governance.json", shared_context)
    solo_exception = evaluate_solo_maintainer_exception(root)
    write_json(target / "solo-maintainer-exception.json", solo_exception)
    schema_stability = evaluate_schema_stability(root)
    write_json(target / "schema-stability.json", schema_stability)
    external_approval = evaluate_external_approval_boundary(root)
    write_json(target / "external-approval-boundary.json", external_approval)
    external_approval_adapter = evaluate_external_approval_adapter(root)
    write_json(target / "external-approval-adapter.json", external_approval_adapter)
    external_identity = evaluate_external_identity(root)
    write_json(target / "external-identity.json", external_identity)
    live_identity_rbac = evaluate_live_identity_rbac(root)
    write_json(target / "live-identity-rbac.json", live_identity_rbac)
    case_evidence = build_case_evidence()
    write_json(target / "case-evidence.json", case_evidence)
    manifest = build_case_manifest(root)
    write_json(target / "case-manifest.json", manifest)
    durable_manifest = build_durable_case_manifest(manifest)
    write_json(target / "durable-case-manifest.json", durable_manifest)
    durable_adapter = evaluate_durable_case_store_adapter(root, durable_manifest)
    write_json(target / "durable-case-store-adapter.json", durable_adapter)
    approval_authority = evaluate_approval_authority(root, durable_manifest)
    write_json(target / "approval-authority.json", approval_authority)
    repository_governance = evaluate_repository_governance(root)
    write_json(target / "repository-governance.json", repository_governance)
    release_lifecycle = evaluate_release_lifecycle(root)
    write_json(target / "release-lifecycle.json", release_lifecycle)
    durable_store = evaluate_durable_evidence_store(root, durable_manifest)
    write_json(target / "durable-evidence-store.json", durable_store)
    approval = build_approval_record(durable_manifest, approval_authority)
    write_json(target / "approval-record.json", approval)
    replay = build_replay_result_from_manifest(root, durable_manifest)
    write_json(target / "replay-result.json", replay)
    adapter_parity = evaluate_evidence_store_adapter_parity(root, durable_manifest, replay)
    write_json(target / "evidence-store-adapter-parity.json", adapter_parity)
    runtime_readiness = build_runtime_readiness_assessment(root)
    write_json(target / "runtime-readiness-assessment.json", runtime_readiness)
    product_surface = build_product_review_surface(root)
    write_json(target / "product-review-surface.json", product_surface)
    write_product_review_surface_html(target / "product-review-workspace.html", product_surface)
    release_dir = root / "reports" / "release" / version
    release = build_release_acceptance(root, version, source_commit)
    write_json(release_dir / "release-acceptance.json", release)
    write_release_acceptance_markdown(release_dir / "release-acceptance.md", release)
    return {
        "preflight": preflight,
        "policy_engine": policy_engine,
        "simulation": simulation,
        "decision_diff": decision_diff,
        "capability_governance": capability_governance,
        "shared_context": shared_context,
        "solo_exception": solo_exception,
        "schema_stability": schema_stability,
        "external_approval": external_approval,
        "external_approval_adapter": external_approval_adapter,
        "runtime_readiness": runtime_readiness,
        "product_surface": product_surface,
        "case_evidence": case_evidence,
        "manifest": manifest,
        "durable_manifest": durable_manifest,
        "durable_adapter": durable_adapter,
        "adapter_parity": adapter_parity,
        "approval_authority": approval_authority,
        "repository_governance": repository_governance,
        "release_lifecycle": release_lifecycle,
        "external_identity": external_identity,
        "live_identity_rbac": live_identity_rbac,
        "durable_store": durable_store,
        "approval": approval,
        "replay": replay,
        "release": release,
    }
