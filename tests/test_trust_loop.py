import json
import tempfile
import unittest
from pathlib import Path

from dip_framework.contracts import ROOT, validate_default_examples, validate_file
from dip_framework.trust_loop import build_trust_loop, write_trust_loop
from dip_framework.v02 import compute_policy_preflight, verify_case_manifest, write_v0_2_evidence


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
        self.assertTrue(payload["acceptance"]["case_manifest_valid"])
        self.assertFalse(payload["acceptance"]["runtime_integration_authorized"])
        self.assertFalse(payload["acceptance"]["production_decision_execution_authorized"])

    def test_write_trust_loop_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_trust_loop(out, ROOT)

            acceptance = json.loads((out / "dip-mvp-acceptance.json").read_text(encoding="utf-8"))
            self.assertTrue(acceptance["trust_loop_complete"])
            self.assertFalse(acceptance["runtime_integration_authorized"])

    def test_v0_2_computes_policy_preflight(self) -> None:
        payload = compute_policy_preflight(ROOT)

        self.assertTrue(payload["computed"])
        self.assertEqual(payload["result"], "approval_required")
        self.assertFalse(payload["ai_override_allowed"])
        self.assertIn("support-platform-owner", payload["required_approvals"])

    def test_v0_2_manifest_and_release_pack_are_pre_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            write_trust_loop(Path(tmp), ROOT)
            result = write_v0_2_evidence(ROOT, ROOT / "reports" / "trust-loop", "v0.2.0-pre")

            self.assertTrue(verify_case_manifest(ROOT, result["manifest"]))
            self.assertTrue(result["release"]["release_acceptance_passed"])
            self.assertFalse(result["release"]["runtime_integration_authorized"])
            self.assertFalse(result["release"]["production_decision_execution_authorized"])


if __name__ == "__main__":
    unittest.main()
