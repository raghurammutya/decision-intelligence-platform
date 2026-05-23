"""DIP v0.2 pre-runtime evidence builders."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from dip_framework.contracts import ROOT, load_json, validate_default_examples


ARTIFACTS = [
    ("decision_spec", "examples/support-ticket-routing-decision-spec.json"),
    ("baseline_decision_spec", "examples/support-ticket-routing-decision-spec-v0.9.0.json"),
    ("capability_registry", "examples/support-ticket-capability-registry.json"),
    ("policy_definitions", "examples/support-ticket-policy-definitions.json"),
    ("policy_preflight", "reports/trust-loop/computed-policy-preflight.json"),
    ("simulation", "examples/support-ticket-simulation-evidence.json"),
    ("decision_diff", "reports/trust-loop/computed-decision-diff.json"),
    ("approval", "examples/support-ticket-approval-record.json"),
    ("case_evidence", "reports/trust-loop/case-evidence.json"),
    ("replay", "reports/trust-loop/replay-result.json"),
]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def compute_policy_preflight(root: Path = ROOT) -> dict[str, Any]:
    examples = root / "examples"
    spec = load_json(examples / "support-ticket-routing-decision-spec.json")
    policies = load_json(examples / "support-ticket-policy-definitions.json")
    denied: list[str] = []
    approval_required: list[str] = []
    missing_evidence: list[str] = []
    evaluated = []
    for policy in policies.get("policies", []):
        rule = policy.get("rule_type")
        policy_id = str(policy.get("policy_id", ""))
        decision = str(policy.get("decision", ""))
        evaluated.append({"policy_id": policy_id, "version": policy.get("version"), "rule_type": rule})
        if rule == "production_allowed_false" and spec.get("environment_scope", {}).get("production_allowed") is not False:
            denied.append(policy_id)
        elif rule == "side_effects_simulation_only":
            for side_effect in spec.get("side_effects", []):
                if side_effect.get("mode") != "simulation_only":
                    denied.append(policy_id)
                    break
        elif rule == "approval_required_for_risk_tier":
            risk_tier = int(spec.get("risk", {}).get("risk_tier", 0) or 0)
            approval = spec.get("approval", {})
            if risk_tier >= int(policy.get("minimum_risk_tier", 0) or 0):
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
                approval_required.append("evidence-owner")

    result = "denied" if denied else "approval_required" if approval_required or missing_evidence else "allowed"
    return {
        "schema_version": "policy-preflight/v1",
        "preflight_id": "computed-preflight-support-ticket-routing-1",
        "decision_id": spec.get("decision_id"),
        "decision_version": spec.get("decision_version"),
        "result": result,
        "computed": True,
        "policy_set_id": policies.get("policy_set_id"),
        "policy_set_version": policies.get("policy_set_version"),
        "evaluated_policies": evaluated,
        "violated_policies": denied,
        "required_approvals": sorted(set(approval_required)),
        "missing_evidence": sorted(set(missing_evidence)),
        "environment_restrictions": ["prod"] if spec.get("environment_scope", {}).get("production_allowed") is False else [],
        "side_effect_restrictions": ["simulation_only"],
        "remediation_guidance": ["Record required approvals before release evidence is accepted."],
        "ai_override_allowed": False,
    }


def _index_by_id(records: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {str(record.get(key, "")): record for record in records if record.get(key)}


def compute_decision_diff(root: Path = ROOT) -> dict[str, Any]:
    examples = root / "examples"
    baseline = load_json(examples / "support-ticket-routing-decision-spec-v0.9.0.json")
    current = load_json(examples / "support-ticket-routing-decision-spec.json")
    simulation = load_json(examples / "support-ticket-simulation-evidence.json")

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
        "runtime_execution_requested": False,
    }


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


def verify_case_manifest(root: Path, manifest: dict[str, Any]) -> bool:
    for artifact in manifest.get("artifacts", []):
        path = root / str(artifact.get("path", ""))
        if not path.exists() or _sha256(path) != artifact.get("sha256"):
            return False
    return manifest.get("append_only_required") is True and manifest.get("mutable") is False


def build_release_acceptance(root: Path = ROOT, version: str = "v0.2.0-pre", source_commit: str | None = None) -> dict[str, Any]:
    validation = validate_default_examples(root)
    preflight = load_json(root / "reports/trust-loop/computed-policy-preflight.json")
    decision_diff = load_json(root / "reports/trust-loop/computed-decision-diff.json")
    manifest = load_json(root / "reports/trust-loop/case-manifest.json")
    manifest_valid = verify_case_manifest(root, manifest)
    return {
        "schema_version": "dip-release-acceptance/v1",
        "release_version": version,
        "source_commit": source_commit or _git_head(root),
        "validation_passed": validation["passed"],
        "validation_record_count": validation["record_count"],
        "computed_policy_preflight_observed": preflight.get("computed") is True,
        "computed_policy_preflight_result": preflight.get("result"),
        "computed_decision_diff_observed": decision_diff.get("computed") is True,
        "computed_decision_diff_changed_outcomes": decision_diff.get("changed_outcome_count", 0),
        "case_manifest_observed": bool(manifest.get("manifest_id")),
        "case_manifest_valid": manifest_valid,
        "case_manifest_artifact_count": manifest.get("artifact_count", 0),
        "runtime_integration_authorized": False,
        "production_decision_execution_authorized": False,
        "release_acceptance_passed": validation["passed"]
        and preflight.get("computed") is True
        and decision_diff.get("computed") is True
        and manifest_valid,
        "blocked_claims": [
            "runtime integration is authorized",
            "production decision execution is authorized",
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
        f"Computed decision diff observed: `{payload['computed_decision_diff_observed']}`",
        f"Computed decision diff changed outcomes: `{payload['computed_decision_diff_changed_outcomes']}`",
        f"Case manifest valid: `{payload['case_manifest_valid']}`",
        f"Case manifest artifacts: `{payload['case_manifest_artifact_count']}`",
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
    version: str = "v0.2.0-pre",
    source_commit: str | None = "local-validation",
) -> dict[str, Any]:
    target = out or root / "reports" / "trust-loop"
    preflight = compute_policy_preflight(root)
    write_json(target / "computed-policy-preflight.json", preflight)
    decision_diff = compute_decision_diff(root)
    write_json(target / "computed-decision-diff.json", decision_diff)
    manifest = build_case_manifest(root)
    write_json(target / "case-manifest.json", manifest)
    release_dir = root / "reports" / "release" / version
    release = build_release_acceptance(root, version, source_commit)
    write_json(release_dir / "release-acceptance.json", release)
    write_release_acceptance_markdown(release_dir / "release-acceptance.md", release)
    return {"preflight": preflight, "decision_diff": decision_diff, "manifest": manifest, "release": release}
