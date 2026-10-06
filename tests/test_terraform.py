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
    assert arns == {
        "arn:aws:iam::000000000000:user/alice",
        "arn:aws:iam::000000000000:role/app-role",
    }

    app_role = account.principal("arn:aws:iam::000000000000:role/app-role")
    assert app_role.policies[0].name == "managed-read"  # resolved via config reference

    assert len(account.resource_policies) == 1
    assert account.resource_policies[0].statements[0].principals == ["*"]


# ---- v0.7.1: module-aware resolution, principals, trust, soundness ----------

ACCT = "111122223333"
ALLOW_PASS = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}],
}


def _rc(address, rtype, after, unknown=None, actions=("create",)):
    return {
        "address": address,
        "type": rtype,
        "change": {"actions": list(actions), "after": after, "after_unknown": unknown or {}},
    }


def _module_plan(resource_changes, module_resources, prior_state=None):
    plan = {
        "resource_changes": resource_changes,
        "configuration": {
            "root_module": {"module_calls": {"lab": {"module": {"resources": module_resources}}}}
        },
    }
    if prior_state is not None:
        plan["prior_state"] = prior_state
    return plan


def _load(tmp_path, plan, account_id=ACCT):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return load_tf_plan(path, account_id)


def _refs(*refs):
    return {"references": list(refs)}


def test_attachment_inside_module_resolves_via_module_local_reference(tmp_path):
    # Policy ARNs are unknown at plan time; the link exists only in module config.
    plan = _module_plan(
        [
            _rc("module.lab.aws_iam_policy.p", "aws_iam_policy",
                {"name": "p", "policy": json.dumps(ALLOW_PASS)}, {"arn": True}),
            _rc("module.lab.aws_iam_user.u", "aws_iam_user", {"name": "u", "path": "/"}),
            _rc("module.lab.aws_iam_user_policy_attachment.a", "aws_iam_user_policy_attachment",
                {"user": "u"}, {"policy_arn": True}),
        ],
        [{"address": "aws_iam_user_policy_attachment.a",
          "expressions": {"policy_arn": _refs("aws_iam_policy.p.arn", "aws_iam_policy.p")}}],
    )
    account = _load(tmp_path, plan)
    user = account.principal(f"arn:aws:iam::{ACCT}:user/u")
    assert [p.name for p in user.policies] == ["p"]
    assert account.warnings == []


def test_policyless_role_is_a_principal_with_its_trust_policy(tmp_path):
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "sts:AssumeRole",
        "Principal": {"Service": "lambda.amazonaws.com"}}]}
    plan = _module_plan(
        [_rc("module.lab.aws_iam_role.r", "aws_iam_role",
             {"name": "r", "path": "/svc/", "assume_role_policy": json.dumps(trust)})],
        [],
    )
    role = _load(tmp_path, plan).principal(f"arn:aws:iam::{ACCT}:role/svc/r")
    assert role.policies == []
    assert role.trust_policy.statements[0].principals == ["service:lambda.amazonaws.com"]


def test_group_policies_flatten_into_members(tmp_path):
    plan = _module_plan(
        [
            _rc("module.lab.aws_iam_group.g", "aws_iam_group", {"name": "g", "path": "/"}),
            _rc("module.lab.aws_iam_group_policy.gp", "aws_iam_group_policy",
                {"group": "g", "name": "gp", "policy": json.dumps(ALLOW_PASS)}),
            _rc("module.lab.aws_iam_user.u", "aws_iam_user", {"name": "u", "path": "/"}),
            _rc("module.lab.aws_iam_group_membership.m", "aws_iam_group_membership",
                {"group": "g", "users": ["u"]}),
        ],
        [],
    )
    account = _load(tmp_path, plan)
    # Groups make no requests, so they are not principals themselves.
    assert {p.arn for p in account.principals} == {f"arn:aws:iam::{ACCT}:user/u"}
    assert [p.name for p in account.principals[0].policies] == ["gp"]


def test_unknown_content_is_widened_to_allow_all_with_warning(tmp_path):
    # An AWS-managed policy attached by ARN: its document is not in the plan.
    plan = _module_plan(
        [
            _rc("module.lab.aws_iam_role.r", "aws_iam_role", {"name": "r", "path": "/"}),
            _rc("module.lab.aws_iam_role_policy_attachment.a", "aws_iam_role_policy_attachment",
                {"role": "r", "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}),
        ],
        [],
    )
    account = _load(tmp_path, plan)
    stmt = account.principal(f"arn:aws:iam::{ACCT}:role/r").policies[0].statements[0]
    assert (stmt.effect, stmt.actions, stmt.resources) == ("Allow", ["*"], ["*"])
    assert any("ReadOnlyAccess" in w for w in account.warnings)


def test_unknown_trust_trusts_referenced_principals_root_and_services(tmp_path):
    plan = _module_plan(
        [
            _rc("module.lab.aws_iam_role.a", "aws_iam_role", {"name": "a", "path": "/"}),
            _rc("module.lab.aws_iam_role.b", "aws_iam_role", {"name": "b", "path": "/"},
                {"assume_role_policy": True}),
        ],
        [{"address": "aws_iam_role.b",
          "expressions": {"assume_role_policy": _refs("aws_iam_role.a.arn", "aws_iam_role.a")}}],
    )
    account = _load(tmp_path, plan)
    trusted = account.principal(f"arn:aws:iam::{ACCT}:role/b").trust_policy.statements[0].principals
    assert f"arn:aws:iam::{ACCT}:role/a" in trusted
    assert f"arn:aws:iam::{ACCT}:root" in trusted
    assert "service:lambda.amazonaws.com" in trusted
    assert "*" not in trusted
    assert any("trust policy unknown" in w for w in account.warnings)


def test_replacement_kept_pure_delete_dropped(tmp_path):
    plan = _module_plan(
        [
            _rc("module.lab.aws_iam_user.kept", "aws_iam_user", {"name": "kept", "path": "/"},
                actions=("delete", "create")),
            _rc("module.lab.aws_iam_user.gone", "aws_iam_user", {"name": "gone", "path": "/"},
                actions=("delete",)),
        ],
        [],
    )
    arns = {p.arn for p in _load(tmp_path, plan).principals}
    assert arns == {f"arn:aws:iam::{ACCT}:user/kept"}


def test_account_id_inferred_from_caller_identity_else_placeholder_warning(tmp_path):
    changes = [_rc("module.lab.aws_iam_user.u", "aws_iam_user", {"name": "u", "path": "/"})]
    state = {"values": {"root_module": {"resources": [
        {"type": "aws_caller_identity", "values": {"account_id": "444455556666"}}]}}}
    inferred = _load(tmp_path, _module_plan(changes, [], state), account_id=None)
    assert inferred.principals[0].arn == "arn:aws:iam::444455556666:user/u"
    assert inferred.warnings == []

    placeholder = _load(tmp_path, _module_plan(changes, []), account_id=None)
    assert placeholder.principals[0].arn == "arn:aws:iam::000000000000:user/u"
    assert any("--tf-account-id" in w for w in placeholder.warnings)


def test_cli_refuses_vacuous_pass_on_empty_plan(tmp_path, capsys):
    from iamprover.cli import main

    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"resource_changes": []}), encoding="utf-8")
    assert main(["verify", "--tf-plan", str(path), "--privesc"]) == 1
    assert "no IAM principals" in capsys.readouterr().err
