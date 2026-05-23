import json
import tempfile
import unittest
from pathlib import Path

from dip_framework.contracts import ROOT, validate_default_examples, validate_file
from dip_framework.trust_loop import build_trust_loop, write_trust_loop


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
        self.assertFalse(payload["acceptance"]["runtime_integration_authorized"])
        self.assertFalse(payload["acceptance"]["production_decision_execution_authorized"])

    def test_write_trust_loop_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_trust_loop(out, ROOT)

            acceptance = json.loads((out / "dip-mvp-acceptance.json").read_text(encoding="utf-8"))
            self.assertTrue(acceptance["trust_loop_complete"])
            self.assertFalse(acceptance["runtime_integration_authorized"])


if __name__ == "__main__":
    unittest.main()
