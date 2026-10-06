"""v0.7 iam:PassRole closure into compute services."""

import pytest

from iamprover.cli import main
from iamprover.engine.reachability import ReachabilityIndex, build_graph
from iamprover.engine.solver import check_invariant
from iamprover.invariants import Invariant
from iamprover.model import Account, Condition, Policy, Principal, Statement

ACCT = "arn:aws:iam::111122223333"
S3_READ = Statement("Allow", actions=["s3:GetObject"], resources=["*"])


def _role(name: str, statements: list[Statement], trust: list[str] = ()) -> Principal:
    trust_policy = (
        Policy("trust", [Statement("Allow", actions=["sts:AssumeRole"], principals=list(trust))])
        if trust
        else None
    )
    return Principal(
        arn=f"{ACCT}:role/{name}", policies=[Policy("p", statements)], trust_policy=trust_policy
    )


def _pass(target_arn: str, conditions: list[Condition] = ()) -> Statement:
    return Statement(
        "Allow", actions=["iam:PassRole"], resources=[target_arn], conditions=list(conditions)
    )


def _launch(*actions: str) -> Statement:
    return Statement("Allow", actions=list(actions), resources=["*"])


NO_S3_READ = Invariant(
    id="no-s3-read", description="no one may read s3", actions=["s3:GetObject"], resources=["*"]
)


def test_edge_when_pass_launch_and_service_trust_all_hold():
    exec_role = _role("exec", [S3_READ], trust=["service:lambda.amazonaws.com"])
    dev = _role("dev", [_pass(exec_role.arn), _launch("lambda:CreateFunction")])
    graph = build_graph(Account(principals=[dev, exec_role]), ("pass-role",))
    assert graph[dev.arn] == [exec_role.arn]


def test_no_edge_without_launch_permission():
    exec_role = _role("exec", [S3_READ], trust=["service:lambda.amazonaws.com"])
    dev = _role("dev", [_pass(exec_role.arn)])
    graph = build_graph(Account(principals=[dev, exec_role]), ("pass-role",))
    assert graph[dev.arn] == []


def test_no_edge_when_role_does_not_trust_the_launchable_service():
    # dev can launch EC2, but the role only trusts Lambda — EC2 can't use it.
    exec_role = _role("exec", [S3_READ], trust=["service:lambda.amazonaws.com"])
    dev = _role("dev", [_pass(exec_role.arn), _launch("ec2:RunInstances")])
    graph = build_graph(Account(principals=[dev, exec_role]), ("pass-role",))
    assert graph[dev.arn] == []


def test_no_edge_when_passrole_scoped_to_another_role():
    exec_role = _role("exec", [S3_READ], trust=["service:lambda.amazonaws.com"])
    dev = _role("dev", [_pass(f"{ACCT}:role/other"), _launch("lambda:CreateFunction")])
    graph = build_graph(Account(principals=[dev, exec_role]), ("pass-role",))
    assert graph[dev.arn] == []


def test_passed_to_service_condition_does_not_hide_edge():
    # Soundness: iam:PassedToService is free request context, so a scoped
    # PassRole grant still counts as an edge (over-approximation).
    exec_role = _role("exec", [S3_READ], trust=["service:lambda.amazonaws.com"])
    scoped = _pass(
        exec_role.arn,
        [Condition("StringEquals", "iam:PassedToService", ["lambda.amazonaws.com"])],
    )
    dev = _role("dev", [scoped, _launch("lambda:CreateFunction")])
    graph = build_graph(Account(principals=[dev, exec_role]), ("pass-role",))
    assert graph[dev.arn] == [exec_role.arn]


def test_explicit_deny_on_passrole_removes_edge():
    exec_role = _role("exec", [S3_READ], trust=["service:lambda.amazonaws.com"])
    dev = _role(
        "dev",
        [
            Statement("Allow", actions=["iam:PassRole"], resources=["*"]),
            Statement("Deny", actions=["iam:PassRole"], resources=[exec_role.arn]),
            _launch("lambda:CreateFunction"),
        ],
    )
    graph = build_graph(Account(principals=[dev, exec_role]), ("pass-role",))
    assert graph[dev.arn] == []


def test_permission_boundary_without_passrole_removes_edge():
    exec_role = _role("exec", [S3_READ], trust=["service:lambda.amazonaws.com"])
    dev = _role("dev", [Statement("Allow", actions=["*"], resources=["*"])])
    dev.permission_boundary = Policy("boundary", [_launch("lambda:*")])
    graph = build_graph(Account(principals=[dev, exec_role]), ("pass-role",))
    assert graph[dev.arn] == []


def test_wildcard_admin_gets_edge_via_fast_path():
    exec_role = _role("exec", [S3_READ], trust=["service:lambda.amazonaws.com"])
    admin = _role("admin", [Statement("Allow", actions=["*"], resources=["*"])])
    graph = build_graph(Account(principals=[admin, exec_role]), ("pass-role",))
    assert graph[admin.arn] == [exec_role.arn]


def test_assume_role_mode_ignores_pass_role_edges():
    exec_role = _role("exec", [S3_READ], trust=["service:lambda.amazonaws.com"])
    dev = _role("dev", [_pass(exec_role.arn), _launch("lambda:CreateFunction")])
    graph = build_graph(Account(principals=[dev, exec_role]))
    assert graph[dev.arn] == []


def test_counterexample_shows_pass_and_launch_steps():
    exec_role = _role("exec", [S3_READ], trust=["service:lambda.amazonaws.com"])
    dev = _role("dev", [_pass(exec_role.arn), _launch("lambda:*")])
    account = Account(principals=[dev, exec_role])

    direct = check_invariant(account, NO_S3_READ)
    assert {ce.principal for ce in direct.counterexamples} == {exec_role.arn}

    result = check_invariant(account, NO_S3_READ, ReachabilityIndex(account, relations=("pass-role",)))
    ce = next(ce for ce in result.counterexamples if ce.principal == dev.arn)
    assert [s.action for s in ce.steps] == [
        "iam:passrole",
        "lambda:createfunction",
        "s3:getobject",
    ]
    assert ce.steps[0].resource == exec_role.arn


def test_all_mode_chains_pass_role_into_assume_role():
    # dev passes `exec` into Lambda; `exec` can assume `reader`; `reader` reads S3.
    reader_arn = f"{ACCT}:role/reader"
    exec_role = _role(
        "exec",
        [Statement("Allow", actions=["sts:AssumeRole"], resources=[reader_arn])],
        trust=["service:lambda.amazonaws.com"],
    )
    reader = _role("reader", [S3_READ], trust=[exec_role.arn])
    dev = _role("dev", [_pass(exec_role.arn), _launch("lambda:CreateFunction")])
    account = Account(principals=[dev, exec_role, reader])

    only_assume = check_invariant(account, NO_S3_READ, ReachabilityIndex(account))
    assert dev.arn not in {ce.principal for ce in only_assume.counterexamples}

    both = check_invariant(
        account, NO_S3_READ, ReachabilityIndex(account, relations=("assume-role", "pass-role"))
    )
    ce = next(ce for ce in both.counterexamples if ce.principal == dev.arn)
    assert [s.action for s in ce.steps] == [
        "iam:passrole",
        "lambda:createfunction",
        "sts:assumerole",
        "s3:getobject",
    ]


def test_unknown_relation_rejected():
    with pytest.raises(ValueError):
        build_graph(Account(principals=[]), ("pass-the-salt",))


def test_cli_pass_role_closure_flags_example(capsys):
    args = ["verify", "--account", "examples/passrole-account.json",
            "--invariants", "examples/invariants.yaml"]
    assert main([*args, "--closure", "none"]) == 2
    without = capsys.readouterr().out
    assert main([*args, "--closure", "pass-role"]) == 2
    with_closure = capsys.readouterr().out
    assert "role/dev" not in without
    assert "iam:passrole on arn:aws:iam::111122223333:role/etl-exec" in with_closure
