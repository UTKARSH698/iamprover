import json
from pathlib import Path

import yaml

from iamprover.cli import main
from iamprover.engine.solver import check_all, check_invariant
from iamprover.invariants import Invariant, Step, parse_invariants
from iamprover.model import Account, Policy, Principal, Statement
from iamprover.privesc import load_builtin_privesc

EXAMPLES = Path(__file__).parent.parent / "examples"


def principal_with(name: str, actions: list[str]) -> Principal:
    return Principal(
        arn=f"arn:aws:iam::1:role/{name}",
        policies=[Policy(name, [Statement("Allow", actions=actions, resources=["*"])])],
    )


def passrole_lambda_chain() -> Invariant:
    return Invariant(
        id="chain",
        description="",
        chain=[
            Step(actions=["iam:PassRole"], resources=["*"]),
            Step(actions=["lambda:CreateFunction"], resources=["*"]),
        ],
    )


def test_chain_fails_only_when_one_principal_holds_every_step():
    both = principal_with("both", ["iam:PassRole", "lambda:CreateFunction"])
    result = check_invariant(Account(principals=[both]), passrole_lambda_chain())
    assert not result.passed
    ce = result.counterexamples[0]
    assert len(ce.steps) == 2
    assert ce.steps[0].action == "iam:passrole"
    assert ce.steps[1].action == "lambda:createfunction"


def test_chain_split_across_principals_passes():
    passer = principal_with("passer", ["iam:PassRole"])
    creator = principal_with("creator", ["lambda:CreateFunction"])
    result = check_invariant(Account(principals=[passer, creator]), passrole_lambda_chain())
    assert result.passed


def test_chain_partial_permissions_pass():
    passer = principal_with("passer", ["iam:PassRole"])
    assert check_invariant(Account(principals=[passer]), passrole_lambda_chain()).passed


def test_forbid_chain_yaml_parsing():
    spec = yaml.safe_load(
        """
        invariants:
          - id: c
            forbid_chain:
              - action: iam:PassRole
              - actions: ["lambda:CreateFunction"]
                resource: "arn:aws:lambda:*"
        """
    )
    (inv,) = parse_invariants(spec)
    steps = inv.steps()
    assert len(steps) == 2
    assert steps[0].resources == ["*"]  # resource defaults to * in chain steps
    assert steps[1].resources == ["arn:aws:lambda:*"]


def test_builtin_catalog_loads_with_exemptions():
    invariants = load_builtin_privesc(["arn:aws:iam::1:role/admin"])
    assert len(invariants) >= 10
    assert all("arn:aws:iam::1:role/admin" in inv.unless_principals for inv in invariants)
    assert any(inv.chain for inv in invariants)  # catalog includes PassRole chains


def test_builtins_flag_escalation_capable_principal():
    attacker = principal_with("dev", ["iam:PassRole", "ec2:RunInstances"])
    results = check_all(Account(principals=[attacker]), load_builtin_privesc())
    failed = {r.invariant.id for r in results if not r.passed}
    assert "privesc-passrole-ec2" in failed
    assert "privesc-passrole-lambda" not in failed


def test_cli_privesc_without_invariants_file(capsys):
    code = main(
        [
            "verify",
            "--account", str(EXAMPLES / "account.json"),
            "--privesc",
            "--privesc-unless", "arn:aws:iam::111122223333:role/ops-admin",
            "--format", "json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    ids = {entry["id"] for entry in payload}
    assert "privesc-policy-version" in ids
    # ops-admin (iam:* holder) is exempt, and no other example principal can
    # escalate, so every built-in must be proven.
    assert all(entry["passed"] for entry in payload)
    assert code == 0


def test_cli_chain_counterexample_render(capsys):
    account = EXAMPLES / "account.json"
    code = main(["verify", "--account", str(account), "--privesc"])
    out = capsys.readouterr().out
    # ops-admin holds iam:* (so iam:PassRole) but nothing grants
    # lambda/ec2/... create rights, so chains still pass; single-step IAM
    # mutation built-ins must fail on ops-admin without an exemption.
    assert code == 2
    assert "[FAIL] privesc-policy-version" in out
    assert "ops-admin" in out
