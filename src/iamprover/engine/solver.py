"""Check invariants against an account model; produce counterexamples on failure."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch

import z3

from iamprover.engine.context import Context
from iamprover.engine.encoder import allowed
from iamprover.engine.patterns import matches_any
from iamprover.invariants import Invariant
from iamprover.model import Account


@dataclass
class CounterexampleStep:
    action: str
    resource: str
    context: dict[str, str] = field(default_factory=dict)


@dataclass
class Counterexample:
    principal: str
    action: str
    resource: str
    context: dict[str, str] = field(default_factory=dict)
    # Populated only for chain invariants (len > 1); action/resource/context
    # above then mirror the first step.
    steps: list[CounterexampleStep] = field(default_factory=list)


@dataclass
class InvariantResult:
    invariant: Invariant
    passed: bool
    counterexamples: list[Counterexample] = field(default_factory=list)


def _exempt(principal_arn: str, exemptions: list[str]) -> bool:
    return any(fnmatch(principal_arn, pattern) for pattern in exemptions)


def check_invariant(account: Account, invariant: Invariant) -> InvariantResult:
    result = InvariantResult(invariant=invariant, passed=True)
    steps = invariant.steps()

    for principal in account.principals:
        if _exempt(principal.arn, invariant.unless_principals):
            continue
        solver = z3.Solver()
        encoded: list[tuple[z3.SeqRef, z3.SeqRef, Context]] = []
        for i, step in enumerate(steps):
            prefix = f"s{i}:" if len(steps) > 1 else ""
            action = z3.String(f"{prefix}action")
            resource = z3.String(f"{prefix}resource")
            ctx = Context(prefix)
            # The action IAM evaluates is lowercased to model case-insensitive matching.
            solver.add(matches_any(action, step.actions, case_insensitive=True))
            solver.add(matches_any(resource, step.resources))
            for key, value in invariant.where.items():
                solver.add(ctx.constrain(key, value))
            solver.add(
                allowed(
                    principal,
                    action,
                    resource,
                    ctx,
                    account.resource_policies,
                    account.scps,
                    account.rcps,
                )
            )
            encoded.append((action, resource, ctx))
        if solver.check() == z3.sat:
            model = solver.model()
            result.passed = False
            ce_steps = [
                CounterexampleStep(
                    action=model.eval(action, model_completion=True).as_string(),
                    resource=model.eval(resource, model_completion=True).as_string(),
                    context=ctx.assignments(model),
                )
                for action, resource, ctx in encoded
            ]
            result.counterexamples.append(
                Counterexample(
                    principal=principal.arn,
                    action=ce_steps[0].action,
                    resource=ce_steps[0].resource,
                    context=ce_steps[0].context,
                    steps=ce_steps if len(ce_steps) > 1 else [],
                )
            )
    return result


def check_all(account: Account, invariants: list[Invariant]) -> list[InvariantResult]:
    return [check_invariant(account, inv) for inv in invariants]
