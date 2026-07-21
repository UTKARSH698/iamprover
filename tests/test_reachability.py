"""v0.6 transitive sts:AssumeRole reachability."""

from iamprover.engine.reachability import ReachabilityIndex, build_graph, shortest_chains
from iamprover.engine.solver import check_invariant
from iamprover.invariants import Invariant
from iamprover.model import Account, Policy, Principal, Statement


def _role(name: str, statements: list[Statement], trusts: list[str] = ()) -> Principal:
    arn = f"arn:aws:iam::111122223333:role/{name}"
    trust_policy = (
        Policy(
            "trust",
            [Statement("Allow", actions=["sts:AssumeRole"], principals=list(trusts))],
        )
        if trusts
        else None
    )
    return Principal(arn=arn, policies=[Policy("p", statements)], trust_policy=trust_policy)


def _can_assume_stmt(target_arn: str) -> Statement:
    return Statement("Allow", actions=["sts:AssumeRole"], resources=[target_arn])


def test_build_graph_edge_requires_both_sides():
    b = _role("b", [Statement("Allow", actions=["s3:*"], resources=["*"])])
    a = _role("a", [_can_assume_stmt(b.arn)], trusts=[])
    # b's trust policy doesn't name a -> no edge even though a has the identity permission.
    graph = build_graph(Account(principals=[a, b]))
    assert graph[a.arn] == []


def test_build_graph_edge_when_both_sides_agree():
    a_arn = "arn:aws:iam::111122223333:role/a"
    b = _role("b", [Statement("Allow", actions=["s3:*"], resources=["*"])], trusts=[a_arn])
    a = _role("a", [_can_assume_stmt(b.arn)])
    graph = build_graph(Account(principals=[a, b]))
    assert graph[a.arn] == [b.arn]
    assert graph[b.arn] == []


def test_shortest_chains_multi_hop():
    a_arn = "arn:aws:iam::111122223333:role/a"
    b_arn = "arn:aws:iam::111122223333:role/b"
    c = _role("c", [Statement("Allow", actions=["s3:*"], resources=["*"])], trusts=[b_arn])
    b = _role("b", [_can_assume_stmt(c.arn)], trusts=[a_arn])
    a = _role("a", [_can_assume_stmt(b.arn)])
    graph = build_graph(Account(principals=[a, b, c]))
    chains = shortest_chains(graph, a.arn, max_hops=4)
    assert chains[c.arn].path == [a.arn, b.arn, c.arn]


def test_max_hops_cuts_off_chain():
    a_arn = "arn:aws:iam::111122223333:role/a"
    b_arn = "arn:aws:iam::111122223333:role/b"
    c = _role("c", [Statement("Allow", actions=["s3:*"], resources=["*"])], trusts=[b_arn])
    b = _role("b", [_can_assume_stmt(c.arn)], trusts=[a_arn])
    a = _role("a", [_can_assume_stmt(b.arn)])
    graph = build_graph(Account(principals=[a, b, c]))
    chains = shortest_chains(graph, a.arn, max_hops=1)
    assert c.arn not in chains
    assert chains[b.arn].path == [a.arn, b.arn]


def test_guarded_trust_condition_still_traversable():
    # A guard (ExternalId etc.) is a value the assuming principal must supply,
    # not a barrier to whether the edge exists — over-approximate as reachable.
    from iamprover.model import Condition

    a_arn = "arn:aws:iam::111122223333:role/a"
    trust_policy = Policy(
        "trust",
        [
            Statement(
                "Allow",
                actions=["sts:AssumeRole"],
                principals=[a_arn],
                conditions=[Condition("StringEquals", "sts:ExternalId", ["secret"])],
            )
        ],
    )
    b = Principal(
        arn="arn:aws:iam::111122223333:role/b",
        policies=[Policy("p", [Statement("Allow", actions=["s3:*"], resources=["*"])])],
        trust_policy=trust_policy,
    )
    a = _role("a", [_can_assume_stmt(b.arn)])
    graph = build_graph(Account(principals=[a, b]))
    assert graph[a.arn] == [b.arn]


def test_invariant_violated_only_via_reachable_principal():
    b_arn = "arn:aws:iam::111122223333:role/b"
    a_arn = "arn:aws:iam::111122223333:role/a"
    b = _role("b", [Statement("Allow", actions=["s3:GetObject"], resources=["*"])], trusts=[a_arn])
    a = _role("a", [_can_assume_stmt(b_arn)])
    account = Account(principals=[a, b])
    invariant = Invariant(
        id="no-s3-read",
        description="no one may read s3",
        actions=["s3:GetObject"],
        resources=["*"],
    )

    result_no_closure = check_invariant(account, invariant)
    violators = {ce.principal for ce in result_no_closure.counterexamples}
    assert violators == {b.arn}  # a has no direct permission, only b does

    reachability = ReachabilityIndex(account)
    result_closure = check_invariant(account, invariant, reachability)
    assert not result_closure.passed
    ce = next(ce for ce in result_closure.counterexamples if ce.principal == a.arn)
    assert [s.action for s in ce.steps] == ["sts:assumerole", "s3:getobject"]
    assert ce.steps[0].resource == b_arn


def test_invariant_exemption_applies_to_chain_target():
    b_arn = "arn:aws:iam::111122223333:role/b"
    a_arn = "arn:aws:iam::111122223333:role/a"
    b = _role("b", [Statement("Allow", actions=["s3:GetObject"], resources=["*"])], trusts=[a_arn])
    a = _role("a", [_can_assume_stmt(b_arn)])
    account = Account(principals=[a, b])
    invariant = Invariant(
        id="no-s3-read",
        description="no one may read s3",
        actions=["s3:GetObject"],
        resources=["*"],
        unless_principals=[b_arn],
    )
    reachability = ReachabilityIndex(account)
    result = check_invariant(account, invariant, reachability)
    assert result.passed
