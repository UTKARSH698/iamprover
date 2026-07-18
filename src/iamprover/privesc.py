"""Built-in privilege-escalation invariants shipped with the package."""

from __future__ import annotations

from importlib.resources import files

import yaml

from iamprover.invariants import Invariant, parse_invariants


def load_builtin_privesc(unless_principals: list[str] | None = None) -> list[Invariant]:
    data = yaml.safe_load(
        (files("iamprover") / "data" / "privesc.yaml").read_text(encoding="utf-8")
    )
    invariants = parse_invariants(data)
    for inv in invariants:
        inv.unless_principals.extend(unless_principals or [])
    return invariants
