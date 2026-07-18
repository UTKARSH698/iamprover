import ipaddress

from iamprover.engine.solver import check_invariant
from iamprover.invariants import Invariant
from iamprover.model import Account, Condition, Policy, Principal, Statement


def mfa_ip_gated_account() -> Account:
    admin = Principal(
        arn="arn:aws:iam::1:role/admin",
        policies=[
            Policy(
                "mfa-gated",
                [
                    Statement(
                        "Allow",
                        actions=["iam:*"],
                        resources=["*"],
                        conditions=[
                            Condition("Bool", "aws:MultiFactorAuthPresent", ["true"]),
                            Condition("IpAddress", "aws:SourceIp", ["203.0.113.0/24"]),
                        ],
                    )
                ],
            )
        ],
    )
    return Account(principals=[admin])


def inv(where=None) -> Invariant:
    return Invariant(
        id="no-iam", description="", actions=["iam:*"], resources=["*"], where=where or {}
    )


def test_condition_satisfiable_context_yields_violation_with_trace():
    result = check_invariant(mfa_ip_gated_account(), inv())
    assert not result.passed
    ctx = result.counterexamples[0].context
    assert ctx["aws:multifactorauthpresent"] == "true"
    ip = ipaddress.IPv4Address(ctx["aws:sourceip"])
    assert ip in ipaddress.IPv4Network("203.0.113.0/24")


def test_where_clause_excludes_condition_gated_grant():
    result = check_invariant(
        mfa_ip_gated_account(), inv(where={"aws:MultiFactorAuthPresent": "false"})
    )
    assert result.passed


def test_where_clause_pinning_ip_outside_cidr_passes():
    result = check_invariant(mfa_ip_gated_account(), inv(where={"aws:SourceIp": "8.8.8.8"}))
    assert result.passed


def test_unknown_operator_on_allow_over_approximates():
    p = Principal(
        arn="arn:aws:iam::1:role/x",
        policies=[
            Policy(
                "p",
                [
                    Statement(
                        "Allow",
                        actions=["s3:*"],
                        resources=["*"],
                        conditions=[Condition("DateGreaterThan", "aws:CurrentTime", ["2030-01-01"])],
                    )
                ],
            )
        ],
    )
    result = check_invariant(
        Account(principals=[p]),
        Invariant(id="i", description="", actions=["s3:GetObject"], resources=["*"]),
    )
    assert not result.passed  # unknown condition on Allow must not hide the grant


def test_unknown_operator_on_deny_does_not_mask_violation():
    p = Principal(
        arn="arn:aws:iam::1:role/x",
        policies=[
            Policy(
                "p",
                [
                    Statement("Allow", actions=["s3:*"], resources=["*"]),
                    Statement(
                        "Deny",
                        actions=["s3:*"],
                        resources=["*"],
                        conditions=[Condition("DateGreaterThan", "aws:CurrentTime", ["2030-01-01"])],
                    ),
                ],
            )
        ],
    )
    result = check_invariant(
        Account(principals=[p]),
        Invariant(id="i", description="", actions=["s3:GetObject"], resources=["*"]),
    )
    assert not result.passed  # a deny we can't model must not suppress the finding
