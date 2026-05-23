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
    if kind == "approval" and payload.get("ai_approved") is not False:
        errors.append("approval cannot be AI-approved")
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
        "simulation": examples / "support-ticket-simulation-evidence.json",
        "decision_diff": examples / "support-ticket-decision-diff.json",
        "approval": examples / "support-ticket-approval-record.json",
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
