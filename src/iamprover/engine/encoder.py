"""Encode IAM policy-evaluation semantics as Z3 constraints.

Semantics modeled (v0.2): explicit Deny overrides Allow; default deny;
Action/NotAction and Resource/NotResource with `*`/`?` wildcards;
case-insensitive action matching; Condition blocks (supported subset — see
engine.conditions); same-account resource-based policies whose grants union
with identity-based allows. Unknown condition operators default to True on
Allow and False on Deny so permissions are only ever over-approximated.

Bounding layers (v0.5): permission boundaries, SCPs, and RCPs narrow what
identity-/resource-based policies grant rather than granting anything
themselves — each must independently contain a matching Allow, or that path
is unavailable. A permission boundary bounds identity-based access only; an
RCP bounds resource-based access only; an SCP bounds both (it applies
account-wide). Multiple SCPs/RCPs (e.g. one per OU level) each act as an
independent cap — all must allow (intersection) and any may deny (union),
mirroring how AWS evaluates a policy hierarchy. When a bounding layer is
absent, it imposes no restriction, so v0.4 inputs are evaluated identically.
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


def _allow_deny_terms(
    statements: list[Statement], action: z3.SeqRef, resource: z3.SeqRef, ctx: Context
) -> tuple[list[z3.BoolRef], list[z3.BoolRef]]:
    allow_terms = []
    deny_terms = []
    for stmt in statements:
        term = statement_matches(stmt, action, resource, ctx)
        (allow_terms if stmt.effect == "Allow" else deny_terms).append(term)
    return allow_terms, deny_terms


def _bounding_allow_deny(
    policies: list[Policy], action: z3.SeqRef, resource: z3.SeqRef, ctx: Context
) -> tuple[z3.BoolRef, z3.BoolRef]:
    """Combine independent bounding policies (permission boundary/SCP/RCP layers).

    Each policy is a separate cap: it must contain a matching Allow for the
    path to remain open (intersection), while a matching Deny in any one of
    them closes it (union) — mirroring AWS's policy-hierarchy evaluation. No
    policies at all means no restriction.
    """
    if not policies:
        return z3.BoolVal(True), z3.BoolVal(False)
    allow_parts = []
    deny_parts = []
    for policy in policies:
        allow_terms, deny_terms = _allow_deny_terms(policy.statements, action, resource, ctx)
        allow_parts.append(z3.Or(*allow_terms) if allow_terms else z3.BoolVal(False))
        if deny_terms:
            deny_parts.append(z3.Or(*deny_terms))
    allow = z3.And(*allow_parts)
    deny = z3.Or(*deny_parts) if deny_parts else z3.BoolVal(False)
    return allow, deny


def allowed(
    principal: Principal,
    action: z3.SeqRef,
    resource: z3.SeqRef,
    ctx: Context,
    resource_policies: list[Policy] = (),
    scps: list[Policy] = (),
    rcps: list[Policy] = (),
) -> z3.BoolRef:
    identity_statements = [s for policy in principal.policies for s in policy.statements]
    identity_allow_terms, identity_deny_terms = _allow_deny_terms(
        identity_statements, action, resource, ctx
    )

    resource_statements = [
        s
        for policy in resource_policies
        for s in policy.statements
        if _grants_to(s, principal.arn)
    ]
    resource_allow_terms, resource_deny_terms = _allow_deny_terms(
        resource_statements, action, resource, ctx
    )

    identity_allow = z3.Or(*identity_allow_terms) if identity_allow_terms else z3.BoolVal(False)
    identity_deny = z3.Or(*identity_deny_terms) if identity_deny_terms else z3.BoolVal(False)
    resource_allow = z3.Or(*resource_allow_terms) if resource_allow_terms else z3.BoolVal(False)
    resource_deny = z3.Or(*resource_deny_terms) if resource_deny_terms else z3.BoolVal(False)

    boundary_policies = [principal.permission_boundary] if principal.permission_boundary else []
    boundary_allow, boundary_deny = _bounding_allow_deny(boundary_policies, action, resource, ctx)
    scp_allow, scp_deny = _bounding_allow_deny(list(scps), action, resource, ctx)
    rcp_allow, rcp_deny = _bounding_allow_deny(list(rcps), action, resource, ctx)

    identity_path = z3.And(identity_allow, boundary_allow, scp_allow)
    resource_path = z3.And(resource_allow, rcp_allow, scp_allow)
    denies = z3.Or(identity_deny, resource_deny, boundary_deny, scp_deny, rcp_deny)

    return z3.And(z3.Or(identity_path, resource_path), z3.Not(denies))
