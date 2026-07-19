from pathlib import Path

from iamprover.engine.trust import analyze_trust
from iamprover.model import Account, Policy, Principal, Statement
from iamprover.parsers.aws import load_gaad

EXAMPLES = Path(__file__).parent.parent / "examples"


def role(arn: str, trust: Policy) -> Principal:
    return Principal(arn=arn, policies=[], trust_policy=trust)


def trust_stmt(principal: str, conditions=None) -> Policy:
    return Policy(
        "trust",
        [
            Statement(
                "Allow",
                actions=["sts:AssumeRole"],
                principals=[principal],
                conditions=conditions or [],
            )
        ],
    )


def test_same_account_trust_is_not_flagged():
    r = role(
        "arn:aws:iam::111122223333:role/internal",
        trust_stmt("arn:aws:iam::111122223333:root"),
    )
    assert analyze_trust(Account(principals=[r])) == []


def test_external_account_trust_flagged_unguarded():
    r = role(
        "arn:aws:iam::111122223333:role/partner",
        trust_stmt("arn:aws:iam::999988887777:root"),
    )
    findings = analyze_trust(Account(principals=[r]))
    assert len(findings) == 1
    assert findings[0].trusted == "arn:aws:iam::999988887777:root"
    assert not findings[0].guarded


def test_external_account_allowlisted_is_suppressed():
    r = role(
        "arn:aws:iam::111122223333:role/partner",
        trust_stmt("arn:aws:iam::999988887777:root"),
    )
    assert analyze_trust(Account(principals=[r]), {"999988887777"}) == []


def test_public_wildcard_trust_flagged():
    r = role("arn:aws:iam::111122223333:role/oops", trust_stmt("*"))
    findings = analyze_trust(Account(principals=[r]))
    assert findings[0].public
    assert not findings[0].guarded


def test_externalid_condition_marks_guarded():
    from iamprover.model import Condition

    r = role(
        "arn:aws:iam::111122223333:role/vendor",
        trust_stmt(
            "arn:aws:iam::444455556666:root",
            [Condition("StringEquals", "sts:ExternalId", ["shared-secret"])],
        ),
    )
    findings = analyze_trust(Account(principals=[r]))
    assert findings[0].guarded
    assert "sts:ExternalId" in findings[0].guard_keys


def test_service_principal_out_of_scope():
    r = role(
        "arn:aws:iam::111122223333:role/lambda-exec",
        trust_stmt("service:lambda.amazonaws.com"),
    )
    assert analyze_trust(Account(principals=[r])) == []


def test_example_gaad_trust_findings():
    account = load_gaad(EXAMPLES / "gaad.json")
    findings = {f.role_arn: f for f in analyze_trust(account)}
    # partner-access: external, unguarded
    assert not findings["arn:aws:iam::111122223333:role/partner-access"].guarded
    # vendor-scoped: external but ExternalId-guarded
    assert findings["arn:aws:iam::111122223333:role/vendor-scoped"].guarded
    # oops-public: public wildcard
    assert findings["arn:aws:iam::111122223333:role/oops-public"].public
