"""Pre-runtime trust-loop materialization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dip_framework.contracts import ROOT, load_json, validate_default_examples


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_trust_loop(root: Path = ROOT) -> dict[str, Any]:
    examples = root / "examples"
    validation = validate_default_examples(root)
    case_evidence = load_json(examples / "support-ticket-case-evidence.json")
    replay_result = load_json(examples / "support-ticket-replay-result.json")
    trust_loop_run = {
        "schema_version": "trust-loop-run/v1",
        "run_id": "trust-loop-support-ticket-routing-1",
        "decision_id": "support-ticket-routing",
        "decision_version": "1.0.0",
        "completed_steps": [
            "validate_spec",
            "load_capability_registry",
            "run_policy_preflight",
            "load_simulation_evidence",
            "generate_decision_diff",
            "record_approval",
            "write_case_evidence",
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
        "replay_result": replay_result,
        "trust_loop_run": trust_loop_run,
        "acceptance": acceptance,
    }


def write_trust_loop(out: Path, root: Path = ROOT) -> dict[str, Any]:
    payload = build_trust_loop(root)
    write_json(out / "validation.json", payload["validation"])
    write_json(out / "case-evidence.json", payload["case_evidence"])
    write_json(out / "replay-result.json", payload["replay_result"])
    write_json(out / "trust-loop-run.json", payload["trust_loop_run"])
    write_json(out / "dip-mvp-acceptance.json", payload["acceptance"])
    return payload
