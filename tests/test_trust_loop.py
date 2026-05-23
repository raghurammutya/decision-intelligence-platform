import json
import tempfile
import unittest
from pathlib import Path

from dip_framework.contracts import ROOT, validate_default_examples, validate_file
from dip_framework.trust_loop import build_trust_loop, write_trust_loop
from dip_framework.v02 import (
    compute_policy_preflight,
    compute_simulation,
    evaluate_approval_authority,
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
        self.assertEqual(payload["acceptance"]["computed_simulation_case_count"], 9)
        self.assertEqual(payload["acceptance"]["computed_simulation_domain_count"], 2)
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
        self.assertEqual(payload["case_count"], 9)
        self.assertEqual(payload["domain_count"], 2)
        self.assertEqual(payload["decision_shape_count"], 2)
        self.assertEqual(payload["changed_outcome_count"], 3)
        self.assertFalse(payload["runtime_execution_requested"])
        self.assertFalse(payload["production_decision_execution_authorized"])
        self.assertIn(
            "hold_for_governance_review",
            [record["decision_output"] for record in payload["engineering_review_results"]],
        )

    def test_v0_5_computes_decision_diff_from_simulation(self) -> None:
        result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v0.6.0-pre")
        payload = result["decision_diff"]

        self.assertTrue(payload["computed"])
        self.assertEqual(payload["from_decision_version"], "0.9.0")
        self.assertEqual(payload["to_decision_version"], "1.0.0")
        self.assertIn("decision_logic_changed", payload["spec_changes"])
        self.assertEqual(payload["changed_outcome_count"], 3)
        self.assertTrue(payload["simulation_computed"])
        self.assertEqual(payload["simulation_case_count"], 9)
        self.assertFalse(payload["runtime_execution_requested"])

    def test_v0_5_manifest_approval_and_release_pack_are_pre_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            write_trust_loop(Path(tmp), ROOT)
            result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v0.6.0-pre")

            self.assertTrue(verify_case_manifest(ROOT, result["manifest"]))
            self.assertTrue(verify_case_manifest(ROOT, result["durable_manifest"]))
            self.assertFalse(result["durable_manifest"]["mutation_detected"])
            self.assertTrue(result["approval"]["approval_bound_to_manifest"])
            self.assertEqual(result["approval"]["case_manifest_hash"], result["durable_manifest"]["manifest_hash"])
            self.assertTrue(result["approval"]["role_binding_valid"])
            self.assertTrue(result["replay"]["manifest_replay_valid"])
            self.assertTrue(result["release"]["computed_simulation_observed"])
            self.assertEqual(result["release"]["computed_simulation_case_count"], 9)
            self.assertEqual(result["release"]["computed_simulation_domain_count"], 2)
            self.assertEqual(result["release"]["computed_simulation_decision_shape_count"], 2)
            self.assertTrue(result["release"]["computed_decision_diff_observed"])
            self.assertEqual(result["release"]["computed_decision_diff_changed_outcomes"], 3)
            self.assertTrue(result["release"]["durable_case_manifest_valid"])
            self.assertTrue(result["release"]["append_only_chain_valid"])
            self.assertFalse(result["release"]["case_mutation_detected"])
            self.assertTrue(result["release"]["replay_from_manifest_observed"])
            self.assertTrue(result["release"]["approval_bound_to_manifest"])
            self.assertTrue(result["release"]["approval_role_binding_valid"])
            self.assertTrue(result["release"]["release_acceptance_passed"])
            self.assertFalse(result["release"]["runtime_integration_authorized"])
            self.assertFalse(result["release"]["production_decision_execution_authorized"])

    def test_v0_6_evaluates_identity_rbac_approval_authority_without_external_idp(self) -> None:
        result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v0.6.0-pre")
        authority = evaluate_approval_authority(ROOT, result["durable_manifest"])

        self.assertTrue(authority["computed"])
        self.assertEqual(authority["source_boundary"], "versioned_local_registry_not_external_idp")
        self.assertTrue(authority["approval_authority_valid"])
        self.assertTrue(authority["identity_active"])
        self.assertTrue(authority["identity_not_expired"])
        self.assertTrue(authority["mfa_satisfied"])
        self.assertTrue(authority["decision_scope_authorized"])
        self.assertTrue(authority["ai_self_approval_blocked"])
        self.assertFalse(authority["external_identity_provider_observed"])
        self.assertTrue(result["release"]["approval_authority_evaluated"])
        self.assertTrue(result["release"]["approval_authority_valid"])
        self.assertTrue(result["release"]["ai_self_approval_blocked"])
        self.assertFalse(result["release"]["external_identity_provider_observed"])


if __name__ == "__main__":
    unittest.main()
