"""Parse AWS IAM policy documents into the internal model.

Conditions are recorded but not modeled in v0.1: a condition-guarded Allow is
treated as always in effect. This over-approximates permissions, so iamprover
may report violations a condition would prevent (false positives), but never
misses a violation the model covers (no false negatives from conditions).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from iamprover.model import Account, Policy, Principal, Statement


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def parse_statement(raw: dict) -> Statement:
    return Statement(
        effect=raw.get("Effect", "Deny"),
        actions=_as_list(raw.get("Action")),
        not_actions=_as_list(raw.get("NotAction")),
        resources=_as_list(raw.get("Resource")) or ["*"],
        not_resources=_as_list(raw.get("NotResource")),
        has_condition=bool(raw.get("Condition")),
    )


def parse_policy_document(name: str, document: dict) -> Policy:
    raw_statements = document.get("Statement", [])
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    return Policy(name=name, statements=[parse_statement(s) for s in raw_statements])


def load_account(path: str | Path) -> Account:
    """Load an account description file.

    Format:
        {"principals": [{"arn": "...", "policies": [{"name": "...", "document": {...}}]}]}
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    principals = []
    for p in data["principals"]:
        policies = [
            parse_policy_document(pol.get("name", "inline"), pol["document"])
            for pol in p.get("policies", [])
        ]
        principals.append(Principal(arn=p["arn"], policies=policies))
    return Account(principals=principals)
