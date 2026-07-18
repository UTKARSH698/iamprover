import json

from iamprover.parsers.terraform import load_tf_plan

POLICY_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
}
BUCKET_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::site/*"}
    ],
}


def make_plan() -> dict:
    return {
        "resource_changes": [
            {
                "address": "aws_iam_user_policy.inline",
                "type": "aws_iam_user_policy",
                "change": {
                    "actions": ["create"],
                    "after": {"user": "alice", "name": "inline", "policy": json.dumps(POLICY_DOC)},
                },
            },
            {
                "address": "aws_iam_policy.managed",
                "type": "aws_iam_policy",
                "change": {
                    "actions": ["create"],
                    "after": {"name": "managed-read", "arn": None, "policy": json.dumps(POLICY_DOC)},
                },
            },
            {
                "address": "aws_iam_role_policy_attachment.attach",
                "type": "aws_iam_role_policy_attachment",
                "change": {
                    "actions": ["create"],
                    "after": {"role": "app-role", "policy_arn": None},
                },
            },
            {
                "address": "aws_s3_bucket_policy.site",
                "type": "aws_s3_bucket_policy",
                "change": {
                    "actions": ["create"],
                    "after": {"bucket": "site", "policy": json.dumps(BUCKET_DOC)},
                },
            },
        ],
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_iam_role_policy_attachment.attach",
                        "expressions": {
                            "policy_arn": {"references": ["aws_iam_policy.managed.arn"]}
                        },
                    }
                ]
            }
        },
    }


def test_tf_plan_parsing(tmp_path):
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(make_plan()), encoding="utf-8")
    account = load_tf_plan(plan_file)

    arns = {p.arn for p in account.principals}
    assert arns == {"tf:user/alice", "tf:role/app-role"}

    app_role = account.principal("tf:role/app-role")
    assert app_role.policies[0].name == "managed-read"  # resolved via config reference

    assert len(account.resource_policies) == 1
    assert account.resource_policies[0].statements[0].principals == ["*"]
