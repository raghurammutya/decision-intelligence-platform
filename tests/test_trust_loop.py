import json
import tempfile
import unittest
from pathlib import Path

from dip_framework.contracts import ROOT, validate_default_examples, validate_file
from dip_framework.trust_loop import build_trust_loop, write_trust_loop
from dip_framework.v02 import (
    build_product_review_surface,
    build_runtime_readiness_assessment,
    compute_policy_preflight,
    compute_simulation,
    evaluate_approval_authority,
    evaluate_capability_governance,
    evaluate_durable_evidence_store,
    evaluate_external_identity,
    evaluate_release_lifecycle,
    evaluate_repository_governance,
    evaluate_shared_context_governance,
    verify_case_manifest,
    write_v0_2_evidence,
)


class TrustLoopTests(unittest.TestCase):
    def test_default_examples_validate(self) -> None:
        result = validate_default_examples(ROOT)

        self.assertTrue(result["passed"])
        self.assertEqual(result["passed_count"], result["record_count"])

    def test_decision_spec_blocks_production_by_default(self) -> None:
        result = validate_file("decision_spec", ROOT / "examples/support-ticket-routing-decision-spec.json")

        self.assertTrue(result["passed"])

    def test_trust_loop_is_pre_runtime(self) -> None:
        payload = build_trust_loop(ROOT)

        self.assertTrue(payload["acceptance"]["trust_loop_complete"])
        self.assertFalse(payload["trust_loop_run"]["runtime_execution_requested"])
        self.assertTrue(payload["acceptance"]["computed_policy_preflight_observed"])
        self.assertTrue(payload["acceptance"]["computed_simulation_observed"])
        self.assertEqual(payload["acceptance"]["computed_simulation_case_count"], 13)
        self.assertEqual(payload["acceptance"]["computed_simulation_domain_count"], 3)
        self.assertTrue(payload["acceptance"]["computed_decision_diff_observed"])
        self.assertEqual(payload["acceptance"]["computed_decision_diff_changed_outcomes"], 3)
        self.assertTrue(payload["acceptance"]["case_manifest_valid"])
        self.assertTrue(payload["acceptance"]["durable_case_manifest_observed"])
        self.assertTrue(payload["acceptance"]["durable_case_manifest_valid"])
        self.assertFalse(payload["acceptance"]["case_mutation_detected"])
        self.assertTrue(payload["acceptance"]["approval_bound_to_manifest"])
        self.assertTrue(payload["acceptance"]["approval_role_binding_valid"])
        self.assertTrue(payload["acceptance"]["approval_authority_evaluated"])
        self.assertTrue(payload["acceptance"]["approval_authority_valid"])
        self.assertFalse(payload["acceptance"]["external_identity_provider_observed"])
        self.assertTrue(payload["acceptance"]["repository_governance_policy_observed"])
        self.assertTrue(payload["acceptance"]["admin_enforcement_required"])
        self.assertTrue(payload["acceptance"]["break_glass_policy_defined"])
        self.assertTrue(payload["acceptance"]["release_lifecycle_policy_observed"])
        self.assertTrue(payload["acceptance"]["release_lifecycle_valid"])
        self.assertTrue(payload["acceptance"]["external_identity_contract_observed"])
        self.assertTrue(payload["acceptance"]["external_identity_contract_valid"])
        self.assertFalse(payload["acceptance"]["live_external_identity_provider_authenticated"])
        self.assertTrue(payload["acceptance"]["durable_evidence_store_policy_observed"])
        self.assertTrue(payload["acceptance"]["durable_store_contract_valid"])
        self.assertFalse(payload["acceptance"]["production_storage_backend_observed"])
        self.assertTrue(payload["acceptance"]["capability_governance_observed"])
        self.assertTrue(payload["acceptance"]["capability_governance_valid"])
        self.assertTrue(payload["acceptance"]["shared_context_contract_observed"])
        self.assertTrue(payload["acceptance"]["shared_context_contract_valid"])
        self.assertTrue(payload["acceptance"]["runtime_readiness_assessment_observed"])
        self.assertEqual(payload["acceptance"]["runtime_readiness_percent"], 0.0)
        self.assertTrue(payload["acceptance"]["product_review_surface_observed"])
        self.assertGreaterEqual(payload["acceptance"]["product_review_surface_count"], 8)
        self.assertFalse(payload["acceptance"]["runtime_integration_authorized"])
        self.assertFalse(payload["acceptance"]["production_decision_execution_authorized"])

    def test_write_trust_loop_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_trust_loop(out, ROOT)

            acceptance = json.loads((out / "dip-mvp-acceptance.json").read_text(encoding="utf-8"))
            self.assertTrue(acceptance["trust_loop_complete"])
            self.assertTrue(acceptance["durable_case_manifest_valid"])
            self.assertTrue(acceptance["approval_bound_to_manifest"])
            self.assertTrue(acceptance["approval_authority_valid"])
            self.assertFalse(acceptance["runtime_integration_authorized"])

    def test_v0_2_computes_policy_preflight(self) -> None:
        payload = compute_policy_preflight(ROOT)

        self.assertTrue(payload["computed"])
        self.assertEqual(payload["result"], "approval_required")
        self.assertFalse(payload["ai_override_allowed"])
        self.assertIn("support-platform-owner", payload["required_approvals"])

    def test_v0_4_computes_simulation_from_explicit_case_inputs(self) -> None:
        payload = compute_simulation(ROOT)

        self.assertTrue(payload["computed"])
        self.assertEqual(payload["case_count"], 13)
        self.assertEqual(payload["domain_count"], 3)
        self.assertEqual(payload["decision_shape_count"], 3)
        self.assertEqual(payload["changed_outcome_count"], 3)
        self.assertFalse(payload["runtime_execution_requested"])
        self.assertFalse(payload["production_decision_execution_authorized"])
        self.assertIn(
            "hold_for_governance_review",
            [record["decision_output"] for record in payload["engineering_review_results"]],
        )
        self.assertIn(
            "escalate_to_risk_owner",
            [record["decision_output"] for record in payload["operational_risk_results"]],
        )

    def test_v0_5_computes_decision_diff_from_simulation(self) -> None:
        result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v2.0.0-pre")
        payload = result["decision_diff"]

        self.assertTrue(payload["computed"])
        self.assertEqual(payload["from_decision_version"], "0.9.0")
        self.assertEqual(payload["to_decision_version"], "1.0.0")
        self.assertIn("decision_logic_changed", payload["spec_changes"])
        self.assertEqual(payload["changed_outcome_count"], 3)
        self.assertTrue(payload["simulation_computed"])
        self.assertEqual(payload["simulation_case_count"], 13)
        self.assertFalse(payload["runtime_execution_requested"])

    def test_v0_5_manifest_approval_and_release_pack_are_pre_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            write_trust_loop(Path(tmp), ROOT)
            result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v2.0.0-pre")

            self.assertTrue(verify_case_manifest(ROOT, result["manifest"]))
            self.assertTrue(verify_case_manifest(ROOT, result["durable_manifest"]))
            self.assertFalse(result["durable_manifest"]["mutation_detected"])
            self.assertTrue(result["approval"]["approval_bound_to_manifest"])
            self.assertEqual(result["approval"]["case_manifest_hash"], result["durable_manifest"]["manifest_hash"])
            self.assertTrue(result["approval"]["role_binding_valid"])
            self.assertTrue(result["replay"]["manifest_replay_valid"])
            self.assertTrue(result["release"]["computed_simulation_observed"])
            self.assertEqual(result["release"]["computed_simulation_case_count"], 13)
            self.assertEqual(result["release"]["computed_simulation_domain_count"], 3)
            self.assertEqual(result["release"]["computed_simulation_decision_shape_count"], 3)
            self.assertTrue(result["release"]["computed_decision_diff_observed"])
            self.assertEqual(result["release"]["computed_decision_diff_changed_outcomes"], 3)
            self.assertTrue(result["release"]["durable_case_manifest_valid"])
            self.assertTrue(result["release"]["append_only_chain_valid"])
            self.assertFalse(result["release"]["case_mutation_detected"])
            self.assertTrue(result["release"]["replay_from_manifest_observed"])
            self.assertTrue(result["release"]["approval_bound_to_manifest"])
            self.assertTrue(result["release"]["approval_role_binding_valid"])
            self.assertTrue(result["release"]["repository_governance_policy_observed"])
            self.assertTrue(result["release"]["admin_enforcement_required"])
            self.assertTrue(result["release"]["break_glass_policy_defined"])
            self.assertTrue(result["release"]["release_lifecycle_valid"])
            self.assertTrue(result["release"]["external_identity_contract_valid"])
            self.assertTrue(result["release"]["durable_store_contract_valid"])
            self.assertTrue(result["release"]["capability_governance_valid"])
            self.assertTrue(result["release"]["shared_context_contract_valid"])
            self.assertEqual(result["release"]["runtime_readiness_percent"], 0.0)
            self.assertEqual(result["release"]["production_decision_authority_percent"], 0.0)
            self.assertTrue(result["release"]["product_review_surface_observed"])
            self.assertTrue(result["release"]["release_acceptance_passed"])
            self.assertFalse(result["release"]["runtime_integration_authorized"])
            self.assertFalse(result["release"]["production_decision_execution_authorized"])

    def test_v0_6_evaluates_identity_rbac_approval_authority_without_external_idp(self) -> None:
        result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v2.0.0-pre")
        authority = evaluate_approval_authority(ROOT, result["durable_manifest"])

        self.assertTrue(authority["computed"])
        self.assertEqual(authority["source_boundary"], "versioned_local_registry_not_external_idp")
        self.assertTrue(authority["approval_authority_valid"])
        self.assertTrue(authority["identity_active"])
        self.assertTrue(authority["identity_not_expired"])
        self.assertTrue(authority["mfa_satisfied"])
        self.assertTrue(authority["decision_scope_authorized"])
        self.assertTrue(authority["ai_self_approval_blocked"])
        self.assertEqual(authority["approver_subject"], "Raghurammutya@gmail.com")
        self.assertFalse(authority["external_identity_provider_observed"])
        self.assertTrue(result["release"]["approval_authority_evaluated"])
        self.assertTrue(result["release"]["approval_authority_valid"])
        self.assertTrue(result["release"]["ai_self_approval_blocked"])
        self.assertFalse(result["release"]["external_identity_provider_observed"])

    def test_v0_7_defines_repository_governance_policy_without_runtime_authority(self) -> None:
        governance = evaluate_repository_governance(ROOT)
        result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v2.0.0-pre")

        self.assertTrue(governance["computed"])
        self.assertEqual(governance["source_boundary"], "declared_repository_governance_policy_not_runtime_execution")
        self.assertTrue(governance["admin_enforcement_required"])
        self.assertEqual(governance["required_status_checks"], ["validate"])
        self.assertEqual(governance["required_approving_review_count"], 1)
        self.assertTrue(governance["branch_protection_observed"])
        self.assertTrue(governance["required_status_checks_observed"])
        self.assertGreaterEqual(governance["required_approving_review_count_observed"], 1)
        self.assertTrue(governance["codeowner_review_required_observed"])
        self.assertTrue(governance["conversation_resolution_required_observed"])
        self.assertTrue(governance["admin_enforcement_observed"])
        self.assertTrue(governance["force_pushes_blocked"])
        self.assertTrue(governance["deletions_blocked"])
        self.assertTrue(governance["break_glass_policy_defined"])
        self.assertFalse(governance["runtime_integration_authorized"])
        self.assertFalse(governance["production_decision_execution_authorized"])
        self.assertTrue(result["release"]["repository_governance_policy_observed"])
        self.assertTrue(result["release"]["admin_enforcement_required"])
        self.assertTrue(result["release"]["required_status_checks_observed"])
        self.assertTrue(result["release"]["codeowner_review_required_observed"])
        self.assertTrue(result["release"]["conversation_resolution_required_observed"])
        self.assertTrue(result["release"]["break_glass_policy_defined"])

    def test_v0_8_defines_release_lifecycle_without_runtime_authority(self) -> None:
        lifecycle = evaluate_release_lifecycle(ROOT)
        result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v2.0.0-pre")

        self.assertTrue(lifecycle["computed"])
        self.assertEqual(lifecycle["stage_count"], 6)
        self.assertTrue(lifecycle["release_lifecycle_valid"])
        self.assertTrue(lifecycle["independent_approval_required"])
        self.assertTrue(lifecycle["codeowner_review_required"])
        self.assertTrue(lifecycle["conversation_resolution_required"])
        self.assertGreaterEqual(lifecycle["rollback_criteria_count"], 3)
        self.assertFalse(lifecycle["runtime_integration_authorized"])
        self.assertTrue(result["release"]["release_lifecycle_policy_observed"])
        self.assertTrue(result["release"]["release_lifecycle_valid"])

    def test_v0_9_defines_external_identity_contract_without_live_auth(self) -> None:
        external = evaluate_external_identity(ROOT)
        result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v2.0.0-pre")

        self.assertTrue(external["computed"])
        self.assertEqual(external["source_boundary"], "external_idp_contract_evidence_not_live_authentication")
        self.assertTrue(external["external_identity_contract_valid"])
        self.assertTrue(external["required_claims_present"])
        self.assertTrue(external["approval_identity_bound_to_subject"])
        self.assertFalse(external["live_provider_authenticated"])
        self.assertTrue(result["release"]["external_identity_contract_observed"])
        self.assertTrue(result["release"]["external_identity_contract_valid"])
        self.assertFalse(result["release"]["live_external_identity_provider_authenticated"])

    def test_v1_0_defines_durable_store_contract_without_production_storage(self) -> None:
        result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v2.0.0-pre")
        durable_store = evaluate_durable_evidence_store(ROOT, result["durable_manifest"])

        self.assertTrue(durable_store["computed"])
        self.assertEqual(durable_store["storage_model"], "append_only_content_addressed_log")
        self.assertTrue(durable_store["required_controls_present"])
        self.assertTrue(durable_store["content_addressed_records"])
        self.assertTrue(durable_store["manifest_hash_chain"])
        self.assertTrue(durable_store["append_only_enforced_by_contract"])
        self.assertTrue(durable_store["delete_denied_by_contract"])
        self.assertFalse(durable_store["production_storage_backend_observed"])
        self.assertTrue(result["release"]["durable_evidence_store_policy_observed"])
        self.assertTrue(result["release"]["durable_store_contract_valid"])
        self.assertFalse(result["release"]["production_storage_backend_observed"])

    def test_v1_4_evaluates_capability_governance_without_runtime_invocation(self) -> None:
        capability = evaluate_capability_governance(ROOT)
        result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v2.0.0-pre")

        self.assertTrue(capability["computed"])
        self.assertEqual(capability["decision_count"], 3)
        self.assertEqual(capability["resolved_capability_count"], 3)
        self.assertTrue(capability["exact_versions_resolved"])
        self.assertTrue(capability["provenance_recorded"])
        self.assertTrue(capability["entitlements_recorded"])
        self.assertTrue(capability["compatibility_recorded"])
        self.assertTrue(capability["evaluation_evidence_recorded"])
        self.assertTrue(capability["cost_profiles_recorded"])
        self.assertTrue(capability["capability_governance_valid"])
        self.assertFalse(capability["runtime_integration_authorized"])
        self.assertTrue(result["release"]["capability_governance_observed"])
        self.assertTrue(result["release"]["capability_governance_valid"])

    def test_v1_5_evaluates_shared_context_contract_without_runtime_exchange(self) -> None:
        shared_context = evaluate_shared_context_governance(ROOT)
        result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v2.0.0-pre")

        self.assertTrue(shared_context["computed"])
        self.assertTrue(shared_context["purpose_declared"])
        self.assertTrue(shared_context["ttl_declared"])
        self.assertTrue(shared_context["masking_rules_declared"])
        self.assertTrue(shared_context["approval_required"])
        self.assertTrue(shared_context["source_lineage_declared"])
        self.assertTrue(shared_context["freshness_rules_declared"])
        self.assertTrue(shared_context["policy_decision_evidence_declared"])
        self.assertFalse(shared_context["direct_database_access_allowed"])
        self.assertFalse(shared_context["runtime_context_exchange_authorized"])
        self.assertTrue(shared_context["shared_context_contract_valid"])
        self.assertTrue(result["release"]["shared_context_contract_observed"])
        self.assertTrue(result["release"]["shared_context_contract_valid"])

    def test_v2_0_assesses_runtime_readiness_without_authority(self) -> None:
        result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v2.0.0-pre")
        runtime = build_runtime_readiness_assessment(ROOT)
        surface = build_product_review_surface(ROOT)

        self.assertTrue(runtime["computed"])
        self.assertEqual(runtime["runtime_readiness_percent"], 0.0)
        self.assertEqual(runtime["production_decision_authority_percent"], 0.0)
        self.assertGreaterEqual(len(runtime["runtime_blockers"]), 10)
        self.assertFalse(runtime["runtime_integration_authorized"])
        self.assertFalse(runtime["production_decision_execution_authorized"])
        self.assertTrue(surface["computed"])
        self.assertGreaterEqual(surface["surface_count"], 8)
        self.assertFalse(surface["runtime_integration_authorized"])
        self.assertTrue(result["release"]["runtime_readiness_assessment_observed"])
        self.assertEqual(result["release"]["runtime_readiness_percent"], 0.0)
        self.assertTrue(result["release"]["product_review_surface_observed"])


if __name__ == "__main__":
    unittest.main()
