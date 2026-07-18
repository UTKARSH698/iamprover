"""Extract IAM policies from a Terraform plan (`terraform show -json plan > plan.json`).

v0.1 supports inline policies: aws_iam_role_policy and aws_iam_user_policy.
Managed-policy attachments are on the roadmap.
"""

from __future__ import annotations

import json
from pathlib import Path

from iamprover.model import Account, Principal
from iamprover.parsers.iam import parse_policy_document

_INLINE_TYPES = {
    "aws_iam_role_policy": ("role", "role"),
    "aws_iam_user_policy": ("user", "user"),
}


def load_tf_plan(path: str | Path) -> Account:
    plan = json.loads(Path(path).read_text(encoding="utf-8"))
    principals: dict[str, Principal] = {}

    for rc in plan.get("resource_changes", []):
        rtype = rc.get("type")
        if rtype not in _INLINE_TYPES:
            continue
        after = (rc.get("change") or {}).get("after")
        if not after or "delete" in (rc.get("change") or {}).get("actions", []):
            continue
        attr, kind = _INLINE_TYPES[rtype]
        principal_name = after.get(attr)
        policy_json = after.get("policy")
        if not principal_name or not policy_json:
            continue
        arn = f"tf:{kind}/{principal_name}"
        document = json.loads(policy_json) if isinstance(policy_json, str) else policy_json
        policy = parse_policy_document(after.get("name", rc.get("address", "inline")), document)
        principals.setdefault(arn, Principal(arn=arn, policies=[])).policies.append(policy)

    return Account(principals=list(principals.values()))
