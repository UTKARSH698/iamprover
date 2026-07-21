"""Ingest a live account snapshot from AWS IAM.

Input is the JSON produced by:

    aws iam get-account-authorization-details > gaad.json

This gives every user, group, role, and managed policy in one document. We
resolve managed-policy attachments and group memberships into flattened
per-principal policy sets, and capture each role's trust policy
(`AssumeRolePolicyDocument`) for cross-account trust analysis.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from iamprover.model import Account, Policy, Principal
from iamprover.parsers.iam import parse_policy_document


def _decode_document(raw: Any) -> dict:
    """GAAD policy documents are dicts (CLI-decoded) or URL-encoded strings."""
    if isinstance(raw, str):
        return json.loads(unquote(raw))
    return raw


def _managed_policies(gaad: dict) -> dict[str, Policy]:
    by_arn: dict[str, Policy] = {}
    for entry in gaad.get("Policies", []):
        default = entry.get("DefaultVersionId")
        versions = entry.get("PolicyVersionList", [])
        chosen = next((v for v in versions if v.get("VersionId") == default), None)
        if chosen is None:
            chosen = next((v for v in versions if v.get("IsDefaultVersion")), None)
        if chosen is None and versions:
            chosen = versions[0]
        if chosen is None:
            continue
        by_arn[entry["Arn"]] = parse_policy_document(
            entry.get("PolicyName", entry["Arn"]), _decode_document(chosen["Document"])
        )
    return by_arn


def _inline_policies(entry: dict, list_key: str) -> list[Policy]:
    return [
        parse_policy_document(p["PolicyName"], _decode_document(p["PolicyDocument"]))
        for p in entry.get(list_key, [])
    ]


def _attached_policies(entry: dict, managed: dict[str, Policy]) -> list[Policy]:
    out = []
    for att in entry.get("AttachedManagedPolicies", []):
        policy = managed.get(att.get("PolicyArn", ""))
        if policy is not None:
            out.append(policy)
    return out


def _permission_boundary(entry: dict, managed: dict[str, Policy]) -> Policy | None:
    """Resolve `PermissionsBoundary` (GAAD nests the ARN; the CLI ARN key varies)."""
    boundary = entry.get("PermissionsBoundary")
    arn = boundary.get("PermissionsBoundaryArn") if isinstance(boundary, dict) else None
    arn = arn or entry.get("PermissionsBoundaryArn")
    return managed.get(arn) if arn else None


def load_gaad(path: str | Path) -> Account:
    gaad = json.loads(Path(path).read_text(encoding="utf-8"))
    managed = _managed_policies(gaad)

    group_policies: dict[str, list[Policy]] = {}
    for group in gaad.get("GroupDetailList", []):
        group_policies[group["GroupName"]] = _inline_policies(
            group, "GroupPolicyList"
        ) + _attached_policies(group, managed)

    principals: list[Principal] = []

    for user in gaad.get("UserDetailList", []):
        policies = _inline_policies(user, "UserPolicyList") + _attached_policies(user, managed)
        for group_name in user.get("GroupList", []):
            policies.extend(group_policies.get(group_name, []))
        principals.append(
            Principal(
                arn=user["Arn"],
                policies=policies,
                permission_boundary=_permission_boundary(user, managed),
            )
        )

    for role in gaad.get("RoleDetailList", []):
        policies = _inline_policies(role, "RolePolicyList") + _attached_policies(role, managed)
        trust = role.get("AssumeRolePolicyDocument")
        trust_policy = (
            parse_policy_document(f"{role.get('RoleName', role['Arn'])}-trust", _decode_document(trust))
            if trust
            else None
        )
        principals.append(
            Principal(
                arn=role["Arn"],
                policies=policies,
                trust_policy=trust_policy,
                permission_boundary=_permission_boundary(role, managed),
            )
        )

    return Account(principals=principals)
