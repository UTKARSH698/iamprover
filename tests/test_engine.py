import z3

from iamprover.engine.context import Context
from iamprover.engine.encoder import allowed
from iamprover.model import Policy, Principal, Statement


def is_allowed(principal: Principal, action: str, resource: str, resource_policies=()) -> bool:
    a, r = z3.Strings("a r")
    solver = z3.Solver()
    solver.add(a == z3.StringVal(action.lower()), r == z3.StringVal(resource))
    solver.add(allowed(principal, a, r, Context(), list(resource_policies)))
    return solver.check() == z3.sat


def principal_with(statements: list[Statement]) -> Principal:
    return Principal(arn="arn:aws:iam::1:role/test", policies=[Policy("p", statements)])


def test_default_deny():
    p = principal_with([])
    assert not is_allowed(p, "s3:GetObject", "arn:aws:s3:::b/k")


def test_allow_grants():
    p = principal_with([Statement("Allow", actions=["s3:GetObject"], resources=["*"])])
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::b/k")
    assert not is_allowed(p, "s3:PutObject", "arn:aws:s3:::b/k")


def test_deny_overrides_allow():
    p = principal_with(
        [
            Statement("Allow", actions=["s3:*"], resources=["*"]),
            Statement("Deny", actions=["s3:*"], resources=["arn:aws:s3:::secret/*"]),
        ]
    )
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::open/k")
    assert not is_allowed(p, "s3:GetObject", "arn:aws:s3:::secret/k")


def test_not_action():
    p = principal_with([Statement("Allow", not_actions=["iam:*"], resources=["*"])])
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::b/k")
    assert not is_allowed(p, "iam:CreateUser", "*")
