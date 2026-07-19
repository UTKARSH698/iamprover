"""Parse AWS IAM policy documents into the internal model.

Modeling notes (v0.2):
- Condition blocks are parsed and encoded for supported operators (see
  engine.conditions). Unsupported operators degrade safely: treated as
  always-true on Allow statements and always-false on Deny statements, so the
  analysis over-approximates permissions (false positives possible, no false
  negatives within the modeled fragment).
- Resource-based policy `Principal` supports "*" and exact AWS principal ARNs.
  NotPrincipal is not modeled.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from iamprover.model import Account, Condition, Policy, Principal, Statement


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def parse_conditions(raw: dict) -> list[Condition]:
    conditions = []
    for operator, mapping in raw.items():
        for key, values in mapping.items():
            conditions.append(Condition(operator=operator, key=key, values=_as_list(values)))
    return conditions


def parse_principals(raw: Any) -> list[str]:
    if raw is None:
        return []
    if raw == "*":
        return ["*"]
    if isinstance(raw, dict):
        principals = []
        for kind, values in raw.items():
            if kind == "AWS":
                principals.extend(_as_list(values))
            else:
                principals.extend(f"{kind.lower()}:{v}" for v in _as_list(values))
        return principals
    return _as_list(raw)


def parse_statement(raw: dict) -> Statement:
    return Statement(
        effect=raw.get("Effect", "Deny"),
        actions=_as_list(raw.get("Action")),
        not_actions=_as_list(raw.get("NotAction")),
        resources=_as_list(raw.get("Resource")) or ["*"],
        not_resources=_as_list(raw.get("NotResource")),
        conditions=parse_conditions(raw.get("Condition", {})),
        principals=parse_principals(raw.get("Principal")),
    )


def parse_policy_document(name: str, document: dict) -> Policy:
    raw_statements = document.get("Statement", [])
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    return Policy(name=name, statements=[parse_statement(s) for s in raw_statements])


def load_account(path: str | Path) -> Account:
    """Load an account description file.

    Format:
        {
          "principals": [{"arn": "...", "policies": [{"name": "...", "document": {...}}]}],
          "resource_policies": [{"name": "...", "document": {...}}]
        }
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    principals = []
    for p in data["principals"]:
        policies = [
            parse_policy_document(pol.get("name", "inline"), pol["document"])
            for pol in p.get("policies", [])
        ]
        trust = p.get("trust_policy")
        trust_policy = parse_policy_document("trust", trust) if trust else None
        principals.append(Principal(arn=p["arn"], policies=policies, trust_policy=trust_policy))
    resource_policies = [
        parse_policy_document(pol.get("name", "resource-policy"), pol["document"])
        for pol in data.get("resource_policies", [])
    ]
    return Account(principals=principals, resource_policies=resource_policies)
