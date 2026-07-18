"""Check invariants against an account model; produce counterexamples on failure."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch

import z3

from iamprover.engine.encoder import allowed
from iamprover.engine.patterns import matches_any
from iamprover.invariants import Invariant
from iamprover.model import Account


@dataclass
class Counterexample:
    principal: str
    action: str
    resource: str


@dataclass
class InvariantResult:
    invariant: Invariant
    passed: bool
    counterexamples: list[Counterexample] = field(default_factory=list)


def _exempt(principal_arn: str, exemptions: list[str]) -> bool:
    return any(fnmatch(principal_arn, pattern) for pattern in exemptions)


def check_invariant(account: Account, invariant: Invariant) -> InvariantResult:
    result = InvariantResult(invariant=invariant, passed=True)
    action = z3.String("action")
    resource = z3.String("resource")

    for principal in account.principals:
        if _exempt(principal.arn, invariant.unless_principals):
            continue
        solver = z3.Solver()
        # The action IAM evaluates is lowercased to model case-insensitive matching.
        solver.add(matches_any(action, invariant.actions, case_insensitive=True))
        solver.add(matches_any(resource, invariant.resources))
        solver.add(allowed(principal, action, resource))
        if solver.check() == z3.sat:
            model = solver.model()
            result.passed = False
            result.counterexamples.append(
                Counterexample(
                    principal=principal.arn,
                    action=model[action].as_string(),
                    resource=model[resource].as_string(),
                )
            )
    return result


def check_all(account: Account, invariants: list[Invariant]) -> list[InvariantResult]:
    return [check_invariant(account, inv) for inv in invariants]
