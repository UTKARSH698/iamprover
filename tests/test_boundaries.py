"""v0.5 bounding layers: permission boundaries, SCPs, RCPs."""

from iamprover.model import Condition, Policy, Statement

from test_engine import is_allowed, principal_with


def _policy(name: str, statements: list[Statement]) -> Policy:
    return Policy(name, statements)


def test_boundary_caps_identity_allow():
    p = principal_with([Statement("Allow", actions=["s3:*"], resources=["*"])])
    p.permission_boundary = _policy(
        "boundary", [Statement("Allow", actions=["s3:GetObject"], resources=["*"])]
    )
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::b/k")
    assert not is_allowed(p, "s3:PutObject", "arn:aws:s3:::b/k")


def test_boundary_absent_imposes_no_restriction():
    p = principal_with([Statement("Allow", actions=["s3:*"], resources=["*"])])
    assert is_allowed(p, "s3:PutObject", "arn:aws:s3:::b/k")


def test_boundary_explicit_deny_blocks():
    p = principal_with([Statement("Allow", actions=["s3:*"], resources=["*"])])
    p.permission_boundary = _policy(
        "boundary",
        [
            Statement("Allow", actions=["s3:*"], resources=["*"]),
            Statement("Deny", actions=["s3:*"], resources=["arn:aws:s3:::secret/*"]),
        ],
    )
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::open/k")
    assert not is_allowed(p, "s3:GetObject", "arn:aws:s3:::secret/k")


def test_boundary_unknown_condition_stays_permissive():
    p = principal_with([Statement("Allow", actions=["s3:*"], resources=["*"])])
    p.permission_boundary = _policy(
        "boundary",
        [
            Statement(
                "Allow",
                actions=["s3:*"],
                resources=["*"],
                conditions=[
                    Condition(
                        operator="DateLessThan", key="aws:CurrentTime", values=["2030-01-01"]
                    )
                ],
            )
        ],
    )
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::b/k")


def test_boundary_does_not_bound_resource_based_access():
    # No identity-based grant at all — access comes solely from the resource policy.
    p = principal_with([])
    p.permission_boundary = _policy(
        "boundary", [Statement("Allow", actions=["s3:GetObject"], resources=["*"])]
    )
    resource_policy = _policy(
        "bucket-policy",
        [
            Statement(
                "Allow",
                actions=["s3:PutObject"],
                resources=["*"],
                principals=[p.arn],
            )
        ],
    )
    assert is_allowed(p, "s3:PutObject", "arn:aws:s3:::b/k", resource_policies=[resource_policy])


def test_scp_bounds_identity_path():
    p = principal_with([Statement("Allow", actions=["s3:*"], resources=["*"])])
    scp = _policy("scp", [Statement("Allow", actions=["s3:GetObject"], resources=["*"])])
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::b/k", scps=[scp])
    assert not is_allowed(p, "s3:PutObject", "arn:aws:s3:::b/k", scps=[scp])


def test_scp_bounds_resource_path():
    p = principal_with([])
    resource_policy = _policy(
        "bucket-policy",
        [Statement("Allow", actions=["s3:PutObject"], resources=["*"], principals=[p.arn])],
    )
    scp = _policy("scp", [Statement("Allow", actions=["s3:GetObject"], resources=["*"])])
    assert not is_allowed(
        p, "s3:PutObject", "arn:aws:s3:::b/k", resource_policies=[resource_policy], scps=[scp]
    )


def test_scp_multiple_layers_intersect():
    p = principal_with([Statement("Allow", actions=["s3:*"], resources=["*"])])
    org_scp = _policy("org-scp", [Statement("Allow", actions=["s3:*"], resources=["*"])])
    ou_scp = _policy("ou-scp", [Statement("Allow", actions=["s3:GetObject"], resources=["*"])])
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::b/k", scps=[org_scp, ou_scp])
    assert not is_allowed(p, "s3:PutObject", "arn:aws:s3:::b/k", scps=[org_scp, ou_scp])


def test_scp_explicit_deny_blocks():
    p = principal_with([Statement("Allow", actions=["s3:*"], resources=["*"])])
    scp = _policy(
        "scp",
        [
            Statement("Allow", actions=["s3:*"], resources=["*"]),
            Statement("Deny", actions=["s3:*"], resources=["arn:aws:s3:::secret/*"]),
        ],
    )
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::open/k", scps=[scp])
    assert not is_allowed(p, "s3:GetObject", "arn:aws:s3:::secret/k", scps=[scp])


def test_rcp_bounds_resource_path_only():
    p = principal_with([Statement("Allow", actions=["s3:*"], resources=["*"])])
    rcp = _policy("rcp", [Statement("Allow", actions=["s3:GetObject"], resources=["*"])])
    # RCP doesn't gate identity-based access — full s3:* still holds.
    assert is_allowed(p, "s3:PutObject", "arn:aws:s3:::b/k", rcps=[rcp])


def test_rcp_bounds_resource_based_grant():
    p = principal_with([])
    resource_policy = _policy(
        "bucket-policy",
        [Statement("Allow", actions=["s3:PutObject"], resources=["*"], principals=[p.arn])],
    )
    rcp = _policy("rcp", [Statement("Allow", actions=["s3:GetObject"], resources=["*"])])
    assert not is_allowed(
        p, "s3:PutObject", "arn:aws:s3:::b/k", resource_policies=[resource_policy], rcps=[rcp]
    )
