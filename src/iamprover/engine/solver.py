"""Check invariants against an account model; produce counterexamples on failure."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch

import z3

from iamprover.engine.context import Context
from iamprover.engine.encoder import allowed
from iamprover.engine.patterns import matches_any
from iamprover.engine.reachability import Chain, ReachabilityIndex
from iamprover.invariants import Invariant
from iamprover.model import Account, Principal


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


def _check_principal(
    account: Account, principal: Principal, invariant: Invariant
) -> Counterexample | None:
    steps = invariant.steps()
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
    if solver.check() != z3.sat:
        return None
    model = solver.model()
    ce_steps = [
        CounterexampleStep(
            action=model.eval(action, model_completion=True).as_string(),
            resource=model.eval(resource, model_completion=True).as_string(),
            context=ctx.assignments(model),
        )
        for action, resource, ctx in encoded
    ]
    return Counterexample(
        principal=principal.arn,
        action=ce_steps[0].action,
        resource=ce_steps[0].resource,
        context=ce_steps[0].context,
        steps=ce_steps if len(ce_steps) > 1 else [],
    )


def _prefix_with_chain(root_arn: str, chain: Chain, target_ce: Counterexample) -> Counterexample:
    """Prepend the assume-role hops of `chain` to a violation found at its target,
    reattributing it to the chain's root principal."""
    hops = [
        CounterexampleStep(action="sts:assumerole", resource=hop)
        for hop in chain.path[1:]
    ]
    final_steps = target_ce.steps or [
        CounterexampleStep(target_ce.action, target_ce.resource, target_ce.context)
    ]
    all_steps = hops + final_steps
    return Counterexample(
        principal=root_arn,
        action=all_steps[0].action,
        resource=all_steps[0].resource,
        context=all_steps[0].context,
        steps=all_steps,
    )


def check_invariant(
    account: Account, invariant: Invariant, reachability: ReachabilityIndex | None = None
) -> InvariantResult:
    result = InvariantResult(invariant=invariant, passed=True)

    for principal in account.principals:
        if _exempt(principal.arn, invariant.unless_principals):
            continue
        ce = _check_principal(account, principal, invariant)
        if ce is None and reachability is not None:
            for target_arn, chain in reachability.chains_from(principal.arn).items():
                if _exempt(target_arn, invariant.unless_principals):
                    continue
                target_ce = _check_principal(account, account.principal(target_arn), invariant)
                if target_ce is not None:
                    ce = _prefix_with_chain(principal.arn, chain, target_ce)
                    break  # chains_from is nearest-first, so this is the shortest
        if ce is not None:
            result.passed = False
            result.counterexamples.append(ce)
    return result


def check_all(
    account: Account, invariants: list[Invariant], reachability: ReachabilityIndex | None = None
) -> list[InvariantResult]:
    return [check_invariant(account, inv, reachability) for inv in invariants]
