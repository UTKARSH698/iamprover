"""Load invariant specs from YAML.

Spec format:

    invariants:
      - id: no-external-prod-read
        description: Only the data-team role may read the prod data bucket
        forbid:
          actions: ["s3:GetObject", "s3:GetObject*"]   # or singular `action`
          resources: ["arn:aws:s3:::prod-data/*"]      # or singular `resource`
        unless_principal:
          - "arn:aws:iam::111122223333:role/data-team"  # exact or glob
        where:                                          # optional: pin request context
          aws:MultiFactorAuthPresent: "false"

      - id: no-passrole-lambda-escalation
        description: No single principal may both pass a role and create a Lambda
        forbid_chain:                                   # fails only if ONE principal
          - action: iam:PassRole                        # can do EVERY step
          - action: lambda:CreateFunction
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Step:
    actions: list[str]
    resources: list[str]


@dataclass
class Invariant:
    id: str
    description: str
    actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    chain: list[Step] = field(default_factory=list)
    unless_principals: list[str] = field(default_factory=list)
    where: dict[str, str] = field(default_factory=dict)

    def steps(self) -> list[Step]:
        return self.chain if self.chain else [Step(self.actions, self.resources)]


def _plural(spec: dict, singular: str, default: list[str] | None = None) -> list[str]:
    values = spec.get(singular + "s", spec.get(singular))
    if values is None:
        if default is not None:
            return default
        raise ValueError(f"invariant forbid block needs '{singular}' or '{singular}s'")
    return [values] if isinstance(values, str) else list(values)


def parse_invariants(data: dict) -> list[Invariant]:
    invariants = []
    for raw in data.get("invariants", []):
        actions: list[str] = []
        resources: list[str] = []
        chain: list[Step] = []
        if "forbid_chain" in raw:
            chain = [
                Step(
                    actions=_plural(step, "action"),
                    resources=_plural(step, "resource", default=["*"]),
                )
                for step in raw["forbid_chain"]
            ]
        else:
            forbid = raw["forbid"]
            actions = _plural(forbid, "action")
            resources = _plural(forbid, "resource")
        invariants.append(
            Invariant(
                id=raw["id"],
                description=raw.get("description", ""),
                actions=actions,
                resources=resources,
                chain=chain,
                unless_principals=list(raw.get("unless_principal", [])),
                where={k: str(v) for k, v in raw.get("where", {}).items()},
            )
        )
    return invariants


def load_invariants(path: str | Path) -> list[Invariant]:
    return parse_invariants(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
