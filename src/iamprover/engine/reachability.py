"""Transitive `sts:AssumeRole` reachability across the principal graph (v0.6).

An edge P -> Q exists when P's identity policies grant an assume-role action
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
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

import z3

from iamprover.engine.context import Context
from iamprover.engine.encoder import allowed
from iamprover.engine.patterns import expand_variables, globs_intersect
from iamprover.model import Account, Principal, Statement

DEFAULT_MAX_HOPS = 4

_ASSUME_ACTIONS = (
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
)


@dataclass
class Chain:
    # Principal ARNs from the source (index 0) to the reachable target (last).
    path: list[str]


def _stmt_has_assume_action(stmt: Statement) -> bool:
    return any(
        globs_intersect(action.lower(), pattern)
        for action in stmt.actions
        for pattern in _ASSUME_ACTIONS
    )


def _trusts(role: Principal, candidate: Principal) -> bool:
    if role.trust_policy is None:
        return False
    for stmt in role.trust_policy.statements:
        if stmt.effect != "Allow":
            continue
        if candidate.arn not in stmt.principals and "*" not in stmt.principals:
            continue
        if _stmt_has_assume_action(stmt):
            return True
    return False


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
    if not _trusts(target, source):
        return False
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


def build_graph(account: Account) -> dict[str, list[str]]:
    """Adjacency list of assume-role edges: source ARN -> reachable target ARNs.

    Built trust-side-out: only principals a trust policy actually names (or
    everyone, for `Principal: "*"`) are candidate sources, so cost scales with
    the number of trust grants rather than all principal pairs.
    """
    graph: dict[str, list[str]] = {p.arn: [] for p in account.principals}
    by_arn = {p.arn: p for p in account.principals}
    for target in account.principals:
        if target.trust_policy is None:
            continue
        candidates: set[str] = set()
        for stmt in target.trust_policy.statements:
            if stmt.effect != "Allow" or not _stmt_has_assume_action(stmt):
                continue
            if "*" in stmt.principals:
                candidates.update(arn for arn in by_arn if arn != target.arn)
            else:
                candidates.update(
                    arn for arn in stmt.principals if arn in by_arn and arn != target.arn
                )
        for source_arn in sorted(candidates):
            if _can_assume(by_arn[source_arn], target):
                graph[source_arn].append(target.arn)
    return graph


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
    """Precomputes the assume-role graph once; memoizes per-source BFS."""

    def __init__(self, account: Account, max_hops: int = DEFAULT_MAX_HOPS) -> None:
        self._graph = build_graph(account)
        self._max_hops = max_hops
        self._cache: dict[str, dict[str, Chain]] = {}

    def chains_from(self, source: str) -> dict[str, Chain]:
        if source not in self._cache:
            self._cache[source] = shortest_chains(self._graph, source, self._max_hops)
        return self._cache[source]
