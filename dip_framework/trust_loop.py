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
    examples = root / "examples"
    write_v0_2_evidence(root, version="v0.4.0-pre")
    validation = validate_default_examples(root)
    case_evidence = load_json(examples / "support-ticket-case-evidence.json")
    replay_result = load_json(examples / "support-ticket-replay-result.json")
    computed_preflight = load_json(root / "reports/trust-loop/computed-policy-preflight.json")
    computed_simulation = load_json(root / "reports/trust-loop/computed-simulation-evidence.json")
    computed_decision_diff = load_json(root / "reports/trust-loop/computed-decision-diff.json")
    case_manifest = load_json(root / "reports/trust-loop/case-manifest.json")
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
            "record_approval",
            "write_case_evidence",
            "write_case_manifest",
            "read_replay_result",
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
        "replay_evidence_complete": bool(replay_result.get("replay_id")),
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
    write_json(out / "replay-result.json", payload["replay_result"])
    write_json(out / "trust-loop-run.json", payload["trust_loop_run"])
    write_json(out / "dip-mvp-acceptance.json", payload["acceptance"])
    return payload
