"""Encode IAM policy-evaluation semantics as Z3 constraints.

Semantics modeled (v0.1): explicit Deny overrides Allow; default deny;
Action/NotAction and Resource/NotResource with `*`/`?` wildcards; action
matching is case-insensitive (as in IAM). Conditions are ignored
(over-approximation — see parsers.iam docstring).
"""

from __future__ import annotations

import z3

from iamprover.engine.patterns import matches_any
from iamprover.model import Principal, Statement


def statement_matches(stmt: Statement, action: z3.SeqRef, resource: z3.SeqRef) -> z3.BoolRef:
    if stmt.not_actions:
        action_ok = z3.Not(matches_any(action, stmt.not_actions, case_insensitive=True))
    else:
        action_ok = matches_any(action, stmt.actions, case_insensitive=True)

    if stmt.not_resources:
        resource_ok = z3.Not(matches_any(resource, stmt.not_resources))
    else:
        resource_ok = matches_any(resource, stmt.resources)

    return z3.And(action_ok, resource_ok)


def allowed(principal: Principal, action: z3.SeqRef, resource: z3.SeqRef) -> z3.BoolRef:
    allow_terms = []
    deny_terms = []
    for policy in principal.policies:
        for stmt in policy.statements:
            term = statement_matches(stmt, action, resource)
            if stmt.effect == "Allow":
                allow_terms.append(term)
            else:
                deny_terms.append(term)
    allows = z3.Or(*allow_terms) if allow_terms else z3.BoolVal(False)
    denies = z3.Or(*deny_terms) if deny_terms else z3.BoolVal(False)
    return z3.And(allows, z3.Not(denies))
