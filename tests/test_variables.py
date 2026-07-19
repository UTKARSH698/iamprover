from test_engine import is_allowed

from iamprover.engine.patterns import expand_variables
from iamprover.model import Condition, Policy, Principal, Statement


def test_expand_variables_widens_to_star():
    assert expand_variables("arn:aws:s3:::b/${aws:username}/*") == "arn:aws:s3:::b/*/*"
    assert expand_variables("${aws:PrincipalTag/team}") == "*"
    assert expand_variables("no-vars-here") == "no-vars-here"


def var_resource_principal() -> Principal:
    return Principal(
        arn="arn:aws:iam::1:user/bob",
        policies=[
            Policy(
                "self",
                [
                    Statement(
                        "Allow",
                        actions=["s3:GetObject"],
                        resources=["arn:aws:s3:::team/${aws:username}/*"],
                    )
                ],
            )
        ],
    )


def test_policy_variable_in_resource_over_approximates():
    p = var_resource_principal()
    # ${aws:username} widened to * — bob's own prefix matches ...
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::team/bob/report.csv")
    # ... and so does another user's prefix (sound over-approximation)
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::team/carol/secret.csv")


def test_variable_in_allow_condition_does_not_hide_grant():
    p = Principal(
        arn="arn:aws:iam::1:user/bob",
        policies=[
            Policy(
                "p",
                [
                    Statement(
                        "Allow",
                        actions=["s3:ListBucket"],
                        resources=["*"],
                        conditions=[Condition("StringEquals", "s3:prefix", ["${aws:username}/"])],
                    )
                ],
            )
        ],
    )
    # unknown (variable) condition on Allow must not suppress the permission
    assert is_allowed(p, "s3:ListBucket", "arn:aws:s3:::b")


def test_tag_condition_key_is_modeled_as_context():
    # aws:PrincipalTag/<k> flows through the generic string-context path; the
    # solver can pick a tag value that satisfies an Allow, so the grant stands.
    p = Principal(
        arn="arn:aws:iam::1:role/tagged",
        policies=[
            Policy(
                "p",
                [
                    Statement(
                        "Allow",
                        actions=["s3:GetObject"],
                        resources=["*"],
                        conditions=[Condition("StringEquals", "aws:PrincipalTag/team", ["data"])],
                    )
                ],
            )
        ],
    )
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::b/k")


def test_variable_in_not_resource_stays_sound():
    # A variable in NotResource must not shrink the allow set (no false negative).
    p = Principal(
        arn="arn:aws:iam::1:user/bob",
        policies=[
            Policy(
                "p",
                [
                    Statement(
                        "Allow",
                        actions=["s3:GetObject"],
                        resources=["*"],
                        not_resources=["arn:aws:s3:::team/${aws:username}/*"],
                    )
                ],
            )
        ],
    )
    # the variable NotResource entry is dropped (excludes nothing), so the grant
    # remains provable across resources
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::team/carol/x")
