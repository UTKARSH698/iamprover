"""Transitive reachability across the principal graph (v0.6 / v0.7).

Two closure relations produce edges P -> Q, meaning "P can come to act with
Q's permissions":

- `assume-role` (v0.6): P can call sts:AssumeRole on Q directly.
- `pass-role` (v0.7): P can hand role Q to a compute service that then runs
  code P controls with Q's credentials — `iam:PassRole` into Lambda, EC2,
  CloudFormation, Glue, SageMaker, CodeBuild, or Data Pipeline.

For `assume-role`, an edge P -> Q exists when P's identity policies grant an assume-role action
on Q's ARN *and* Q's trust policy allows P as principal. Both principals and
ARNs are concrete here (no wildcarded principals in a trust policy), so graph
construction is a finite structural computation with one SMT query per
candidate edge — it deliberately does not encode reachability itself into the
solver. Bounded BFS over a small graph is simpler and faster than a solver
query, and keeps graph construction, traversal, and invariant evaluation as
separate, independently testable stages.

Trust-policy guardedness (ExternalId, org id, source account, ...) is not
checked here: a guard is a secret/context value the assuming principal must
supply, not a barrier to whether the edge exists at all. Treating a guarded
trust relationship as traversable is the over-approximating choice — the same
direction `engine/trust.py` takes when flagging guarded grants as lower
severity rather than dropping them.

AWS environments rarely need deep AssumeRole chains, so reachability is
bounded by `max_hops` (default 4) rather than computed as an unbounded
closure: this keeps runtime predictable on large live-account graphs while
still capturing realistic privilege-escalation chains.

A `pass-role` edge P -> R (via service S) exists when all three hold: R's
trust policy lets S assume it (otherwise the service cannot use the role and
AWS rejects the hand-off), P is allowed `iam:PassRole` on R, and P is allowed
one of S's launch actions. The last two are checked as independent requests —
the same compositional over-approximation `forbid_chain` uses — and
`iam:PassedToService`-style conditions stay free context the solver may
satisfy, so a scoped PassRole grant is never under-counted.

Like the assume-role check, edge queries consult identity policies only:
SCPs, RCPs, and boundaries can only remove permissions, so ignoring them here
errs toward more edges, never fewer.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field

import z3

from iamprover.engine.context import Context
from iamprover.engine.encoder import allowed
from iamprover.engine.patterns import expand_variables, globs_intersect
from iamprover.model import Account, Policy, Principal, Statement

DEFAULT_MAX_HOPS = 4

RELATIONS = ("assume-role", "pass-role")

_ASSUME_ACTIONS = (
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
)


# Compute services a role can be passed into, with the launch actions that put
# code the caller controls behind the passed role. Mirrors the
# privesc-passrole-* invariants in data/privesc.yaml.
_PASS_SERVICES: dict[str, tuple[str, ...]] = {
    "lambda.amazonaws.com": ("lambda:createfunction", "lambda:updatefunctionconfiguration"),
    "ec2.amazonaws.com": ("ec2:runinstances",),
    "cloudformation.amazonaws.com": ("cloudformation:createstack", "cloudformation:updatestack"),
    "glue.amazonaws.com": ("glue:createdevendpoint",),
    "sagemaker.amazonaws.com": (
        "sagemaker:createnotebookinstance",
        "sagemaker:createtrainingjob",
        "sagemaker:createprocessingjob",
    ),
    "codebuild.amazonaws.com": ("codebuild:createproject",),
    "datapipeline.amazonaws.com": ("datapipeline:createpipeline",),
}

PASS_SERVICE_PRINCIPALS = tuple(_PASS_SERVICES)

# One (action, resource) request; an edge costs one or more of them.
HopStep = tuple[str, str]


@dataclass
class Chain:
    # Principal ARNs from the source (index 0) to the reachable target (last).
    path: list[str]
    # Requests taken along each edge of `path` (len == len(path) - 1). Left
    # empty by shortest_chains; ReachabilityIndex fills it from edge labels.
    hops: list[list[HopStep]] = field(default_factory=list)


def _stmt_has_assume_action(stmt: Statement) -> bool:
    return any(
        globs_intersect(action.lower(), pattern)
        for action in stmt.actions
        for pattern in _ASSUME_ACTIONS
    )


_EXPLICIT = "explicit"  # trust alone suffices (same-account principal ARN, or "*")
_DELEGATED = "delegated"  # trust delegates; the caller's identity policy must allow


def _account_root_matches(trusted: str, candidate: Principal) -> bool:
    account = candidate.account_id
    return account is not None and trusted in (account, f"arn:aws:iam::{account}:root")


def _trust_match(role: Principal, candidate: Principal) -> str | None:
    """How `role`'s trust policy admits `candidate`, mirroring AWS:

    - names the candidate's ARN (or "*") within the same account: the trust
      policy alone grants the assume — no identity permission needed;
    - names the candidate's account root, or the candidate is in another
      account: the trust only delegates, and the candidate's own identity
      policy must also allow sts:AssumeRole.
    """
    if role.trust_policy is None:
        return None
    same_account = candidate.account_id is not None and candidate.account_id == role.account_id
    best: str | None = None
    for stmt in role.trust_policy.statements:
        if stmt.effect != "Allow" or not _stmt_has_assume_action(stmt):
            continue
        for trusted in stmt.principals:
            if trusted in ("*", candidate.arn):
                if same_account:
                    return _EXPLICIT
                best = _DELEGATED
            elif _account_root_matches(trusted, candidate):
                best = _DELEGATED
    return best


def _may_grant_assume(source: Principal, target_arn: str) -> bool:
    """Syntactic prefilter mirroring solver._may_match_step: can any Allow
    statement possibly grant an assume-role action on `target_arn`? False
    proves the Z3 query below is unsat, so it can be skipped."""
    for policy in source.policies:
        for stmt in policy.statements:
            if stmt.effect != "Allow":
                continue
            if not stmt.not_actions and not _stmt_has_assume_action(stmt):
                continue
            if stmt.not_resources or any(
                globs_intersect(expand_variables(p), target_arn) for p in stmt.resources
            ):
                return True
    return False


def _can_assume(source: Principal, target: Principal) -> bool:
    match = _trust_match(target, source)
    if match is None:
        return False
    if match == _EXPLICIT:
        # The trust policy grants it; only an explicit identity Deny can still
        # block. Probe with an added Allow: sat iff no Deny covers every
        # context. The boundary is dropped — it can only restrict, so ignoring
        # it over-approximates.
        probe = Principal(
            arn=source.arn,
            policies=[
                *source.policies,
                Policy("trust-grant", [Statement("Allow", actions=["sts:assumerole"],
                                                 resources=[target.arn])]),
            ],
        )
        return _sat_allowed(probe, "sts:assumerole", target.arn)
    if not _may_grant_assume(source, target.arn):
        return False
    a, r = z3.Strings("a r")
    for action in _ASSUME_ACTIONS:
        solver = z3.Solver()
        solver.add(a == z3.StringVal(action), r == z3.StringVal(target.arn))
        solver.add(allowed(source, a, r, Context()))
        if solver.check() == z3.sat:
            return True
    return False


def _trusted_services(role: Principal) -> list[str]:
    """Pass-role services whose principal `role`'s trust policy allows to
    assume it, in catalog order. Only roles can be passed."""
    if role.trust_policy is None or ":role/" not in role.arn:
        return []
    trusted: set[str] = set()
    for stmt in role.trust_policy.statements:
        if stmt.effect != "Allow" or not _stmt_has_assume_action(stmt):
            continue
        if "*" in stmt.principals:
            trusted.update(_PASS_SERVICES)
        trusted.update(
            p.removeprefix("service:") for p in stmt.principals if p.startswith("service:")
        )
    return [svc for svc in _PASS_SERVICES if svc in trusted]


def _may_allow(source: Principal, actions: tuple[str, ...], resource: str | None) -> bool:
    """Syntactic prefilter: can any Allow statement possibly grant one of
    `actions` (on `resource`, or on anything when None)? False proves unsat."""
    for policy in source.policies:
        for stmt in policy.statements:
            if stmt.effect != "Allow":
                continue
            if not stmt.not_actions and not any(
                globs_intersect(expand_variables(p).lower(), a)
                for p in stmt.actions
                for a in actions
            ):
                continue
            if resource is None or stmt.not_resources or any(
                globs_intersect(expand_variables(p), resource) for p in stmt.resources
            ):
                return True
    return False


def _surely_allowed(source: Principal, action: str, resource: str | None) -> bool:
    """Exact fast path for `_sat_allowed`: True only when the answer is
    provably sat without a solver — no permission boundary, no Deny that could
    touch the request, and an unconditional Allow matching it. `action` and
    `resource` are concrete, so pattern intersection is a full match here.
    False means "unknown"; the caller falls back to Z3."""
    if source.permission_boundary is not None:
        return False
    statements = [s for policy in source.policies for s in policy.statements]

    def hits(stmt: Statement) -> bool:
        if not stmt.not_actions and not any(
            globs_intersect(expand_variables(p).lower(), action) for p in stmt.actions
        ):
            return False
        return (
            resource is None
            or bool(stmt.not_resources)
            or any(globs_intersect(expand_variables(p), resource) for p in stmt.resources)
        )

    if any(s.effect != "Allow" and (s.not_actions or hits(s)) for s in statements):
        return False
    return any(
        s.effect == "Allow"
        and not s.conditions
        and not s.not_actions
        and not s.not_resources
        and s.resources
        and hits(s)
        for s in statements
    )


def _sat_allowed(source: Principal, action: str, resource: str | None) -> bool:
    """Is `action` allowed for `source` on `resource` (any resource when None)
    in some request context?"""
    if _surely_allowed(source, action, resource):
        return True
    a, r = z3.Strings("a r")
    solver = z3.Solver()
    solver.add(a == z3.StringVal(action))
    if resource is not None:
        solver.add(r == z3.StringVal(resource))
    solver.add(allowed(source, a, r, Context()))
    return solver.check() == z3.sat


class _PassRoleChecker:
    """Decides pass-role edges, memoizing the per-(source, service) launch
    query that every candidate target role shares."""

    def __init__(self) -> None:
        self._launch: dict[tuple[str, str], str | None] = {}

    def _launch_action(self, source: Principal, service: str) -> str | None:
        key = (source.arn, service)
        if key not in self._launch:
            actions = _PASS_SERVICES[service]
            found = None
            if _may_allow(source, actions, None):
                found = next((a for a in actions if _sat_allowed(source, a, None)), None)
            self._launch[key] = found
        return self._launch[key]

    def edge(self, source: Principal, role: Principal, services: list[str]) -> list[HopStep] | None:
        if not _may_allow(source, ("iam:passrole",), role.arn):
            return None
        if not _sat_allowed(source, "iam:passrole", role.arn):
            return None
        for service in services:
            launch = self._launch_action(source, service)
            if launch is not None:
                return [("iam:passrole", role.arn), (launch, "*")]
        return None


def _build(
    account: Account, relations: tuple[str, ...]
) -> tuple[dict[str, list[str]], dict[tuple[str, str], list[HopStep]]]:
    """Adjacency list plus the requests each edge costs. When both relations
    link the same pair, the assume-role edge (a single request) wins."""
    unknown = set(relations) - set(RELATIONS)
    if unknown:
        raise ValueError(f"unknown closure relation(s): {', '.join(sorted(unknown))}")
    graph: dict[str, list[str]] = {p.arn: [] for p in account.principals}
    labels: dict[tuple[str, str], list[HopStep]] = {}
    by_arn = {p.arn: p for p in account.principals}

    def add(source_arn: str, target_arn: str, steps: list[HopStep]) -> None:
        if (source_arn, target_arn) not in labels:
            graph[source_arn].append(target_arn)
            labels[(source_arn, target_arn)] = steps

    if "assume-role" in relations:
        for source_arn, target_arn in _assume_role_edges(account, by_arn):
            add(source_arn, target_arn, [("sts:assumerole", target_arn)])

    if "pass-role" in relations:
        checker = _PassRoleChecker()
        # Principals that cannot pass any role at all are never sources.
        passers = [p for p in account.principals if _may_allow(p, ("iam:passrole",), None)]
        for role in account.principals:
            services = _trusted_services(role)
            if not services:
                continue
            for source in passers:
                if source.arn == role.arn or (source.arn, role.arn) in labels:
                    continue
                steps = checker.edge(source, role, services)
                if steps is not None:
                    add(source.arn, role.arn, steps)

    return graph, labels


def build_graph(
    account: Account, relations: tuple[str, ...] = ("assume-role",)
) -> dict[str, list[str]]:
    """Adjacency list: source ARN -> target ARNs reachable in one hop under
    `relations` (any subset of RELATIONS)."""
    return _build(account, relations)[0]


def _assume_role_edges(account: Account, by_arn: dict[str, Principal]) -> list[tuple[str, str]]:
    """Assume-role edges, built trust-side-out: only principals a trust policy
    actually names (or everyone, for `Principal: "*"`) are candidate sources,
    so cost scales with the number of trust grants rather than all pairs."""
    edges: list[tuple[str, str]] = []
    by_account: dict[str, list[str]] = {}
    for p in account.principals:
        if p.account_id is not None:
            by_account.setdefault(p.account_id, []).append(p.arn)
    for target in account.principals:
        if target.trust_policy is None:
            continue
        candidates: set[str] = set()
        for stmt in target.trust_policy.statements:
            if stmt.effect != "Allow" or not _stmt_has_assume_action(stmt):
                continue
            if "*" in stmt.principals:
                candidates.update(arn for arn in by_arn if arn != target.arn)
                continue
            candidates.update(arn for arn in stmt.principals if arn in by_arn)
            # An account-root grant delegates to every principal in that account.
            for trusted in stmt.principals:
                root = re.fullmatch(r"(?:arn:aws:iam::)?(\d{12})(?::root)?", trusted)
                if root:
                    candidates.update(by_account.get(root.group(1), ()))
        candidates.discard(target.arn)
        for source_arn in sorted(candidates):
            if _can_assume(by_arn[source_arn], target):
                edges.append((source_arn, target.arn))
    return edges


def shortest_chains(
    graph: dict[str, list[str]], source: str, max_hops: int = DEFAULT_MAX_HOPS
) -> dict[str, Chain]:
    """BFS from `source`; shortest assume-role chain to every principal reachable
    within `max_hops` hops, in order from nearest to farthest. `source` itself
    (hop 0) is not included."""
    parent: dict[str, str] = {}
    depth = {source: 0}
    order: list[str] = []
    queue = deque([source])
    while queue:
        node = queue.popleft()
        if depth[node] >= max_hops:
            continue
        for neighbor in graph.get(node, []):
            if neighbor in depth:
                continue
            depth[neighbor] = depth[node] + 1
            parent[neighbor] = node
            order.append(neighbor)
            queue.append(neighbor)

    chains: dict[str, Chain] = {}
    for target in order:
        path = [target]
        node = target
        while node != source:
            node = parent[node]
            path.append(node)
        path.reverse()
        chains[target] = Chain(path)
    return chains


class ReachabilityIndex:
    """Precomputes the closure graph once; memoizes per-source BFS."""

    def __init__(
        self,
        account: Account,
        max_hops: int = DEFAULT_MAX_HOPS,
        relations: tuple[str, ...] = ("assume-role",),
    ) -> None:
        self._graph, self._labels = _build(account, relations)
        self._max_hops = max_hops
        self._cache: dict[str, dict[str, Chain]] = {}

    def chains_from(self, source: str) -> dict[str, Chain]:
        if source not in self._cache:
            chains = shortest_chains(self._graph, source, self._max_hops)
            for chain in chains.values():
                chain.hops = [
                    self._labels[(u, v)] for u, v in zip(chain.path, chain.path[1:])
                ]
            self._cache[source] = chains
        return self._cache[source]
