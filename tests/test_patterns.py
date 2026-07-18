import z3

from iamprover.engine.patterns import iam_pattern_to_re


def matches(pattern: str, value: str, ci: bool = False) -> bool:
    solver = z3.Solver()
    if ci:
        value = value.lower()
    solver.add(z3.InRe(z3.StringVal(value), iam_pattern_to_re(pattern, case_insensitive=ci)))
    return solver.check() == z3.sat


def test_star_wildcard():
    assert matches("s3:Get*", "s3:GetObject")
    assert matches("s3:*", "s3:DeleteBucket")
    assert not matches("s3:Get*", "s3:PutObject")


def test_question_wildcard():
    assert matches("s3:Get?bject", "s3:GetObject")
    assert not matches("s3:Get?bject", "s3:GetOObbject")


def test_literal_exact():
    assert matches("iam:PassRole", "iam:PassRole")
    assert not matches("iam:PassRole", "iam:PassRoleX")


def test_case_insensitive_actions():
    assert matches("s3:getobject", "s3:GetObject", ci=True)


def test_arn_pattern():
    assert matches("arn:aws:s3:::prod-*/*", "arn:aws:s3:::prod-data/reports/q1.csv")
    assert not matches("arn:aws:s3:::prod-*/*", "arn:aws:s3:::dev-data/x")
