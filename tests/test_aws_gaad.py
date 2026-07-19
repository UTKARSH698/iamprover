import json
from pathlib import Path

from test_engine import is_allowed

from iamprover.parsers.aws import load_gaad

EXAMPLES = Path(__file__).parent.parent / "examples"


def test_gaad_flattens_group_and_managed_policies():
    account = load_gaad(EXAMPLES / "gaad.json")
    alice = account.principal("arn:aws:iam::111122223333:user/alice")
    # inline (self-prefix) + inherited group-attached managed policy (read-logs)
    assert is_allowed(alice, "logs:GetLogEvents", "arn:aws:log-group:whatever")


def test_gaad_captures_role_trust_policies():
    account = load_gaad(EXAMPLES / "gaad.json")
    role = account.principal("arn:aws:iam::111122223333:role/partner-access")
    assert role.trust_policy is not None
    assert role.account_id == "111122223333"


def test_gaad_url_encoded_documents(tmp_path):
    from urllib.parse import quote

    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    gaad = {
        "UserDetailList": [
            {
                "Arn": "arn:aws:iam::1:user/enc",
                "UserName": "enc",
                "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": quote(json.dumps(doc))}],
            }
        ]
    }
    path = tmp_path / "gaad.json"
    path.write_text(json.dumps(gaad), encoding="utf-8")
    account = load_gaad(path)
    user = account.principal("arn:aws:iam::1:user/enc")
    assert is_allowed(user, "s3:GetObject", "arn:aws:s3:::any/key")


def test_gaad_uses_default_policy_version(tmp_path):
    gaad = {
        "UserDetailList": [
            {
                "Arn": "arn:aws:iam::1:user/u",
                "UserName": "u",
                "AttachedManagedPolicies": [
                    {"PolicyName": "m", "PolicyArn": "arn:aws:iam::1:policy/m"}
                ],
            }
        ],
        "Policies": [
            {
                "Arn": "arn:aws:iam::1:policy/m",
                "PolicyName": "m",
                "DefaultVersionId": "v2",
                "PolicyVersionList": [
                    {
                        "VersionId": "v1",
                        "IsDefaultVersion": False,
                        "Document": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]},
                    },
                    {
                        "VersionId": "v2",
                        "IsDefaultVersion": True,
                        "Document": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
                    },
                ],
            }
        ],
    }
    path = tmp_path / "gaad.json"
    path.write_text(json.dumps(gaad), encoding="utf-8")
    account = load_gaad(path)
    user = account.principal("arn:aws:iam::1:user/u")
    assert is_allowed(user, "s3:GetObject", "arn:aws:s3:::b/k")
    assert not is_allowed(user, "ec2:RunInstances", "*")  # v1 is not the default
