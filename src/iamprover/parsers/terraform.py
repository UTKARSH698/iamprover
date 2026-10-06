"""Extract an IAM account model from a Terraform plan (`terraform show -json plan`).

Supported resources:
- principals: aws_iam_user, aws_iam_role (with its trust policy, `inline_policy`
  blocks, and `managed_policy_arns`), aws_iam_group (flattened into members via
  aws_iam_group_membership / aws_iam_user_group_membership)
- inline policies: aws_iam_role_policy, aws_iam_user_policy, aws_iam_group_policy
- managed policies (aws_iam_policy) linked via aws_iam_{role,user,group}_policy_attachment
  or aws_iam_policy_attachment
- resource-based policies: aws_s3_bucket_policy

Plans usually leave ARNs and references unknown until apply, so links are
resolved from the plan's `configuration` block — including resources nested
in modules, whose references are module-local.

Principals get real IAM ARNs (`arn:aws:iam::<account>:<kind>/<path><name>`) so
that trust policies and resource patterns naming them match. The account id
comes from the caller, else from the plan (aws_caller_identity in prior state,
or known IAM ARNs); failing both, a placeholder is used and a warning raised.

Soundness: anything the plan does not reveal is over-approximated, never
dropped. A policy whose content is unknown at plan time (an AWS-managed policy
attached by ARN, or a document computed from other resources) is modeled as
Allow * on *. Each such widening is reported in `Account.warnings`. A trust policy unknown at plan
time trusts the principals its expression references, the account root, and
the compute services.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from iamprover.engine.reachability import PASS_SERVICE_PRINCIPALS
from iamprover.model import Account, Policy, Principal, Statement
from iamprover.parsers.iam import parse_policy_document

PLACEHOLDER_ACCOUNT = "000000000000"

_PRINCIPAL_TYPES = {"aws_iam_user": "user", "aws_iam_role": "role", "aws_iam_group": "group"}
_INLINE_TYPES = {
    "aws_iam_role_policy": ("role", "role"),
    "aws_iam_user_policy": ("user", "user"),
    "aws_iam_group_policy": ("group", "group"),
}
_ATTACHMENT_TYPES = {
    "aws_iam_role_policy_attachment": [("role", "role")],
    "aws_iam_user_policy_attachment": [("user", "user")],
    "aws_iam_group_policy_attachment": [("group", "group")],
    "aws_iam_policy_attachment": [("roles", "role"), ("users", "user"), ("groups", "group")],
}
_INDEX = re.compile(r"\[[^\]]*\]")
_ARN_ACCOUNT = re.compile(r"^arn:aws[\w-]*:iam::(\d{12}):")


def _allow_all(name: str) -> Policy:
    return Policy(name, [Statement("Allow", actions=["*"], resources=["*"])])


def _parse_doc(raw: Any, name: str) -> Policy:
    document = json.loads(raw) if isinstance(raw, str) else raw
    return parse_policy_document(name, document)


def _base(address: str) -> str:
    """Resource address without count/for_each instance keys."""
    return _INDEX.sub("", address)


def _walk_config(module: dict, prefix: str = ""):
    """Yield (full address, resource config) for every resource, descending
    into module calls. Addresses inside a module are module-local."""
    for resource in module.get("resources", []):
        yield prefix + resource.get("address", ""), resource, prefix
    for name, call in module.get("module_calls", {}).items():
        yield from _walk_config(call.get("module", {}), f"{prefix}module.{name}.")


def _walk_state(module: dict):
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from _walk_state(child)


def _infer_account(plan: dict) -> str | None:
    state = (plan.get("prior_state") or {}).get("values", {}).get("root_module", {})
    for resource in _walk_state(state):
        if resource.get("type") == "aws_caller_identity":
            account = (resource.get("values") or {}).get("account_id")
            if account:
                return account
    seen: Counter[str] = Counter()
    for rc in plan.get("resource_changes", []):
        arn = ((rc.get("change") or {}).get("after") or {}).get("arn")
        if isinstance(arn, str) and (m := _ARN_ACCOUNT.match(arn)):
            seen[m.group(1)] += 1
    return seen.most_common(1)[0][0] if len(seen) == 1 else None


def load_tf_plan(path: str | Path, account_id: str | None = None) -> Account:
    plan = json.loads(Path(path).read_text(encoding="utf-8"))
    warnings: list[str] = []

    account_id = account_id or _infer_account(plan)
    if account_id is None:
        account_id = PLACEHOLDER_ACCOUNT
        warnings.append(
            "account id not determinable from the plan; principals use placeholder "
            f"account {PLACEHOLDER_ACCOUNT} — pass --tf-account-id so account-specific "
            "ARN patterns match"
        )

    # Config: full address -> (expressions, module prefix) for reference lookup.
    config: dict[str, tuple[dict, str]] = {
        address: (resource.get("expressions", {}), prefix)
        for address, resource, prefix in _walk_config(
            plan.get("configuration", {}).get("root_module", {})
        )
    }

    live: list[dict] = []
    by_base: dict[str, list[dict]] = {}
    for rc in plan.get("resource_changes", []):
        change = rc.get("change") or {}
        # A replacement is ["delete", "create"]; only a pure delete removes access.
        if not change.get("after") or change.get("actions") == ["delete"]:
            continue
        live.append(rc)
        by_base.setdefault(_base(rc.get("address", "")), []).append(rc)

    def after(rc: dict) -> dict:
        return rc["change"]["after"]

    def unknown(rc: dict, attr: str) -> bool:
        return bool((rc["change"].get("after_unknown") or {}).get(attr))

    def referenced(rc: dict, attr: str) -> list[dict]:
        """Resources an attribute's expression refers to (module-aware)."""
        expressions, prefix = config.get(_base(rc.get("address", "")), ({}, ""))
        expr = expressions.get(attr) or {}
        targets: list[dict] = []
        for ref in expr.get("references", []) if isinstance(expr, dict) else []:
            if ref.startswith(("var.", "local.", "data.", "module.", "each.", "count.")):
                continue
            parts = _base(ref).split(".")
            targets.extend(by_base.get(prefix + ".".join(parts[:2]), []))
        # dedupe, preserving order
        return list({id(t): t for t in targets}.values())

    # ---- principals --------------------------------------------------------
    principals: dict[tuple[str, str], Principal] = {}

    def principal_for(kind: str, name: str, arn: str | None = None, path: str = "/") -> Principal:
        key = (kind, name)
        if key not in principals:
            arn = arn or f"arn:aws:iam::{account_id}:{kind}{path or '/'}{name}"
            principals[key] = Principal(arn=arn, policies=[])
        return principals[key]

    policies_by_address: dict[str, Policy] = {}
    policies_by_arn: dict[str, Policy] = {}
    unknown_trusts: list[tuple[dict, Principal]] = []

    def policy_from(rc: dict, attr: str, name: str) -> Policy:
        raw = after(rc).get(attr)
        if raw:
            return _parse_doc(raw, name)
        if unknown(rc, attr):
            warnings.append(
                f"{rc['address']}: policy document unknown at plan time — "
                "over-approximated as Allow * on *"
            )
        return _allow_all(f"{name} (unknown at plan time)")

    for rc in live:
        rtype, a = rc.get("type"), after(rc)
        if rtype in _PRINCIPAL_TYPES and a.get("name"):
            kind = _PRINCIPAL_TYPES[rtype]
            p = principal_for(kind, a["name"], a.get("arn"), a.get("path") or "/")
            if rtype == "aws_iam_role":
                if a.get("assume_role_policy"):
                    p.trust_policy = _parse_doc(a["assume_role_policy"], "trust")
                elif unknown(rc, "assume_role_policy"):
                    unknown_trusts.append((rc, p))
        elif rtype == "aws_iam_policy":
            policy = policy_from(rc, "policy", a.get("name") or rc["address"])
            policies_by_address[rc["address"]] = policy
            if a.get("arn"):
                policies_by_arn[a["arn"]] = policy

    # A trust document computed from other resources (typically another role's
    # ARN) is unknown until apply. Model it as trusting exactly the principals
    # its expression references — explicitly, as written — plus delegation to
    # the account root and every pass-role compute service. Trusting "*" would
    # instead hand every same-account principal an identity-free edge.
    for rc, role in unknown_trusts:
        trusted = [
            principal_for(
                _PRINCIPAL_TYPES[t["type"]], after(t)["name"], after(t).get("arn"),
                after(t).get("path") or "/",
            ).arn
            for t in referenced(rc, "assume_role_policy")
            if t.get("type") in ("aws_iam_user", "aws_iam_role") and after(t).get("name")
        ]
        trusted += [f"arn:aws:iam::{account_id}:root"]
        trusted += [f"service:{svc}" for svc in PASS_SERVICE_PRINCIPALS]
        role.trust_policy = Policy(
            "trust (unknown at plan time)",
            [Statement("Allow", actions=["sts:AssumeRole"], principals=trusted)],
        )
        warnings.append(
            f"{rc['address']}: trust policy unknown at plan time — modeled as trusting "
            "the principals it references, the account root, and compute services; "
            "literal principal ARNs inside it are not visible"
        )

    def names(rc: dict, attr: str) -> list[str]:
        value = after(rc).get(attr)
        if value:
            return value if isinstance(value, list) else [value]
        return [after(t)["name"] for t in referenced(rc, attr) if after(t).get("name")]

    def policies_for_arn_attr(rc: dict, attr: str) -> list[Policy]:
        """Resolve a policy_arn(s) attribute to policies, widening the unknown."""
        value = after(rc).get(attr)
        arns = (value if isinstance(value, list) else [value]) if value else []
        resolved = [policies_by_arn[arn] for arn in arns if arn in policies_by_arn]
        unresolved = [arn for arn in arns if arn not in policies_by_arn]
        if not arns:
            resolved = [
                policies_by_address[t["address"]]
                for t in referenced(rc, attr)
                if t["address"] in policies_by_address
            ]
            if not resolved and (unknown(rc, attr) or after(rc).get(attr) is None):
                unresolved = ["<unresolved reference>"]
        for arn in unresolved:
            warnings.append(
                f"{rc['address']}: content of {arn} is not in the plan — "
                "over-approximated as Allow * on *"
            )
        return resolved + [_allow_all(f"{arn} (content not in plan)") for arn in unresolved]

    # ---- policy links ------------------------------------------------------
    group_members: dict[str, set[str]] = {}
    for rc in live:
        rtype, a = rc.get("type"), after(rc)
        if rtype in _INLINE_TYPES:
            attr, kind = _INLINE_TYPES[rtype]
            policy = policy_from(rc, "policy", a.get("name") or rc["address"])
            for name in names(rc, attr):
                principal_for(kind, name).policies.append(policy)
        elif rtype in _ATTACHMENT_TYPES:
            linked = policies_for_arn_attr(rc, "policy_arn")
            for attr, kind in _ATTACHMENT_TYPES[rtype]:
                for name in names(rc, attr):
                    principal_for(kind, name).policies.extend(linked)
        elif rtype == "aws_iam_role" and a.get("name"):
            role = principal_for("role", a["name"])
            for block in a.get("inline_policy") or []:
                if block.get("policy"):
                    role.policies.append(_parse_doc(block["policy"], block.get("name") or "inline"))
            if a.get("managed_policy_arns") or config.get(_base(rc["address"]), ({}, ""))[0].get(
                "managed_policy_arns"
            ):
                role.policies.extend(policies_for_arn_attr(rc, "managed_policy_arns"))
        elif rtype == "aws_iam_group_membership":
            for group in names(rc, "group"):
                group_members.setdefault(group, set()).update(names(rc, "users"))
        elif rtype == "aws_iam_user_group_membership":
            for user in names(rc, "user"):
                for group in names(rc, "groups"):
                    group_members.setdefault(group, set()).add(user)

    # Groups don't make requests: flatten their policies into member users.
    for group, members in group_members.items():
        group_principal = principals.get(("group", group))
        for user in sorted(members):
            if group_principal is not None:
                principal_for("user", user).policies.extend(group_principal.policies)

    resource_policies = [
        policy_from(rc, "policy", after(rc).get("bucket") or rc["address"])
        for rc in live
        if rc.get("type") == "aws_s3_bucket_policy"
    ]

    return Account(
        principals=[p for (kind, _), p in principals.items() if kind != "group"],
        resource_policies=resource_policies,
        warnings=warnings,
    )
