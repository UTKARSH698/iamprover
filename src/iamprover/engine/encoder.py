"""Encode IAM policy-evaluation semantics as Z3 constraints.

Semantics modeled (v0.2): explicit Deny overrides Allow; default deny;
Action/NotAction and Resource/NotResource with `*`/`?` wildcards;
case-insensitive action matching; Condition blocks (supported subset — see
engine.conditions); same-account resource-based policies whose grants union
with identity-based allows. Unknown condition operators default to True on
Allow and False on Deny so permissions are only ever over-approximated.
"""

from __future__ import annotations

import z3

from iamprover.engine.conditions import encode_conditions
from iamprover.engine.context import Context
from iamprover.engine.patterns import expand_variables, has_variable, matches_any
from iamprover.model import Policy, Principal, Statement


def _positive_ok(
    var: z3.SeqRef, patterns: list[str], case_insensitive: bool = False
) -> z3.BoolRef:
    # Policy variables widen to `*`, over-approximating the match (sound).
    expanded = [expand_variables(p) for p in patterns]
    return matches_any(var, expanded, case_insensitive=case_insensitive)


def _negative_ok(
    var: z3.SeqRef, patterns: list[str], case_insensitive: bool = False
) -> z3.BoolRef:
    # In a Not* clause, a policy variable would widen the *excluded* set and
    # shrink the allow — unsound. Drop variable-bearing entries so they exclude
    # nothing; the remaining concrete entries still exclude what they must.
    concrete = [p for p in patterns if not has_variable(p)]
    if not concrete:
        return z3.BoolVal(True)
    return z3.Not(matches_any(var, concrete, case_insensitive=case_insensitive))


def statement_matches(
    stmt: Statement, action: z3.SeqRef, resource: z3.SeqRef, ctx: Context
) -> z3.BoolRef:
    if stmt.not_actions:
        action_ok = _negative_ok(action, stmt.not_actions, case_insensitive=True)
    else:
        action_ok = _positive_ok(action, stmt.actions, case_insensitive=True)

    if stmt.not_resources:
        resource_ok = _negative_ok(resource, stmt.not_resources)
    else:
        resource_ok = _positive_ok(resource, stmt.resources)

    condition_ok = encode_conditions(stmt.conditions, ctx, unknown_default=stmt.effect == "Allow")
    return z3.And(action_ok, resource_ok, condition_ok)


def _grants_to(stmt: Statement, principal_arn: str) -> bool:
    return "*" in stmt.principals or principal_arn in stmt.principals


def allowed(
    principal: Principal,
    action: z3.SeqRef,
    resource: z3.SeqRef,
    ctx: Context,
    resource_policies: list[Policy] = (),
) -> z3.BoolRef:
    allow_terms = []
    deny_terms = []
    for policy in principal.policies:
        for stmt in policy.statements:
            term = statement_matches(stmt, action, resource, ctx)
            (allow_terms if stmt.effect == "Allow" else deny_terms).append(term)

    for policy in resource_policies:
        for stmt in policy.statements:
            if not _grants_to(stmt, principal.arn):
                continue
            term = statement_matches(stmt, action, resource, ctx)
            (allow_terms if stmt.effect == "Allow" else deny_terms).append(term)

    allows = z3.Or(*allow_terms) if allow_terms else z3.BoolVal(False)
    denies = z3.Or(*deny_terms) if deny_terms else z3.BoolVal(False)
    return z3.And(allows, z3.Not(denies))
