"""Extract IAM policies from a Terraform plan (`terraform show -json plan > plan.json`).

v0.2 supports:
- inline policies: aws_iam_role_policy, aws_iam_user_policy
- managed policies (aws_iam_policy) linked via aws_iam_role_policy_attachment /
  aws_iam_user_policy_attachment / aws_iam_policy_attachment — resolved by
  policy ARN when known at plan time, else by configuration references
- resource-based policies: aws_s3_bucket_policy
"""

from __future__ import annotations

import json
from pathlib import Path

from iamprover.model import Account, Policy, Principal
from iamprover.parsers.iam import parse_policy_document

_INLINE_TYPES = {
    "aws_iam_role_policy": ("role", "role"),
    "aws_iam_user_policy": ("user", "user"),
}
_ATTACHMENT_TYPES = {
    "aws_iam_role_policy_attachment": [("role", "role")],
    "aws_iam_user_policy_attachment": [("user", "user")],
    "aws_iam_policy_attachment": [("roles", "role"), ("users", "user")],
}


def _parse_doc(raw, name: str) -> Policy:
    document = json.loads(raw) if isinstance(raw, str) else raw
    return parse_policy_document(name, document)


def _config_references(plan: dict) -> dict[str, list[str]]:
    """Map resource address -> addresses referenced by its policy_arn expression."""
    refs: dict[str, list[str]] = {}
    module = plan.get("configuration", {}).get("root_module", {})
    for resource in module.get("resources", []):
        expr = resource.get("expressions", {}).get("policy_arn", {})
        refs[resource.get("address", "")] = expr.get("references", [])
    return refs


def load_tf_plan(path: str | Path) -> Account:
    plan = json.loads(Path(path).read_text(encoding="utf-8"))
    principals: dict[str, Principal] = {}
    resource_policies: list[Policy] = []
    managed_by_arn: dict[str, Policy] = {}
    managed_by_address: dict[str, Policy] = {}
    attachments: list[tuple[str, dict, str]] = []  # (address, after, rtype)

    def principal_for(arn: str) -> Principal:
        return principals.setdefault(arn, Principal(arn=arn, policies=[]))

    for rc in plan.get("resource_changes", []):
        rtype = rc.get("type")
        change = rc.get("change") or {}
        after = change.get("after")
        if not after or "delete" in change.get("actions", []):
            continue

        if rtype in _INLINE_TYPES:
            attr, kind = _INLINE_TYPES[rtype]
            name, policy_json = after.get(attr), after.get("policy")
            if name and policy_json:
                policy = _parse_doc(policy_json, after.get("name", rc.get("address", "inline")))
                principal_for(f"tf:{kind}/{name}").policies.append(policy)

        elif rtype == "aws_iam_policy":
            policy_json = after.get("policy")
            if policy_json:
                policy = _parse_doc(policy_json, after.get("name", rc.get("address", "managed")))
                managed_by_address[rc.get("address", "")] = policy
                if after.get("arn"):
                    managed_by_arn[after["arn"]] = policy

        elif rtype in _ATTACHMENT_TYPES:
            attachments.append((rc.get("address", ""), after, rtype))

        elif rtype == "aws_s3_bucket_policy":
            policy_json = after.get("policy")
            if policy_json:
                resource_policies.append(
                    _parse_doc(policy_json, after.get("bucket", rc.get("address", "bucket-policy")))
                )

    references = _config_references(plan)
    for address, after, rtype in attachments:
        policy = managed_by_arn.get(after.get("policy_arn") or "")
        if policy is None:
            for ref in references.get(address, []):
                base = ref.removesuffix(".arn")
                if base in managed_by_address:
                    policy = managed_by_address[base]
                    break
        if policy is None:
            continue
        for attr, kind in _ATTACHMENT_TYPES[rtype]:
            value = after.get(attr)
            names = value if isinstance(value, list) else [value]
            for name in names:
                if name:
                    principal_for(f"tf:{kind}/{name}").policies.append(policy)

    return Account(principals=list(principals.values()), resource_policies=resource_policies)
