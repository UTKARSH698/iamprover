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
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Invariant:
    id: str
    description: str
    actions: list[str]
    resources: list[str]
    unless_principals: list[str] = field(default_factory=list)


def _plural(spec: dict, singular: str) -> list[str]:
    values = spec.get(singular + "s", spec.get(singular))
    if values is None:
        raise ValueError(f"invariant forbid block needs '{singular}' or '{singular}s'")
    return [values] if isinstance(values, str) else list(values)


def load_invariants(path: str | Path) -> list[Invariant]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    invariants = []
    for raw in data.get("invariants", []):
        forbid = raw["forbid"]
        invariants.append(
            Invariant(
                id=raw["id"],
                description=raw.get("description", ""),
                actions=_plural(forbid, "action"),
                resources=_plural(forbid, "resource"),
                unless_principals=list(raw.get("unless_principal", [])),
            )
        )
    return invariants
