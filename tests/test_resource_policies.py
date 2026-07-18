from test_engine import is_allowed

from iamprover.model import ANONYMOUS_ARN, Policy, Principal, Statement


def public_site_policy() -> Policy:
    return Policy(
        "public-site",
        [
            Statement(
                "Allow",
                actions=["s3:GetObject"],
                resources=["arn:aws:s3:::public-site/*"],
                principals=["*"],
            )
        ],
    )


def test_anonymous_can_read_public_bucket():
    anon = Principal(arn=ANONYMOUS_ARN, policies=[])
    assert is_allowed(
        anon, "s3:GetObject", "arn:aws:s3:::public-site/index.html", [public_site_policy()]
    )


def test_anonymous_cannot_reach_other_buckets():
    anon = Principal(arn=ANONYMOUS_ARN, policies=[])
    assert not is_allowed(anon, "s3:GetObject", "arn:aws:s3:::prod-data/x", [public_site_policy()])


def test_resource_policy_grants_to_exact_arn():
    partner = Principal(arn="arn:aws:iam::9:role/partner", policies=[])
    grant = Policy(
        "shared-bucket",
        [
            Statement(
                "Allow",
                actions=["s3:GetObject"],
                resources=["arn:aws:s3:::shared/*"],
                principals=["arn:aws:iam::9:role/partner"],
            )
        ],
    )
    assert is_allowed(partner, "s3:GetObject", "arn:aws:s3:::shared/f", [grant])
    other = Principal(arn="arn:aws:iam::9:role/other", policies=[])
    assert not is_allowed(other, "s3:GetObject", "arn:aws:s3:::shared/f", [grant])


def test_resource_policy_deny_overrides_identity_allow():
    p = Principal(
        arn="arn:aws:iam::1:role/reader",
        policies=[Policy("read-all", [Statement("Allow", actions=["s3:*"], resources=["*"])])],
    )
    lockdown = Policy(
        "lockdown",
        [
            Statement(
                "Deny",
                actions=["s3:*"],
                resources=["arn:aws:s3:::vault/*"],
                principals=["*"],
            )
        ],
    )
    assert is_allowed(p, "s3:GetObject", "arn:aws:s3:::open/x", [lockdown])
    assert not is_allowed(p, "s3:GetObject", "arn:aws:s3:::vault/x", [lockdown])
