from pathlib import Path

from iamprover.cli import main
from iamprover.engine.solver import check_invariant
from iamprover.invariants import Invariant
from iamprover.model import Account, Policy, Principal, Statement

EXAMPLES = Path(__file__).parent.parent / "examples"


def make_account() -> Account:
    reader = Principal(
        arn="arn:aws:iam::1:role/reader",
        policies=[Policy("read-all", [Statement("Allow", actions=["s3:Get*"], resources=["*"])])],
    )
    return Account(principals=[reader])


def test_violation_found_with_counterexample():
    inv = Invariant(
        id="no-prod-read",
        description="",
        actions=["s3:GetObject"],
        resources=["arn:aws:s3:::prod/*"],
    )
    result = check_invariant(make_account(), inv)
    assert not result.passed
    ce = result.counterexamples[0]
    assert ce.principal == "arn:aws:iam::1:role/reader"
    assert ce.action.startswith("s3:get")
    assert ce.resource.startswith("arn:aws:s3:::prod/")


def test_exempt_principal_passes():
    inv = Invariant(
        id="no-prod-read",
        description="",
        actions=["s3:GetObject"],
        resources=["arn:aws:s3:::prod/*"],
        unless_principals=["arn:aws:iam::1:role/reader"],
    )
    assert check_invariant(make_account(), inv).passed


def test_unreachable_forbidden_action_passes():
    inv = Invariant(
        id="no-iam-mutation",
        description="",
        actions=["iam:Create*"],
        resources=["*"],
    )
    assert check_invariant(make_account(), inv).passed


def test_cli_end_to_end_on_examples(capsys):
    code = main(
        [
            "verify",
            "--account", str(EXAMPLES / "account.json"),
            "--invariants", str(EXAMPLES / "invariants.yaml"),
        ]
    )
    out = capsys.readouterr().out
    assert code == 2  # example intentionally contains one violation
    assert "[FAIL] prod-data-read-restricted" in out
    assert "ci-runner" in out
    assert "[PASS] audit-logs-untouchable" in out
    assert "[PASS] no-iam-mutation" in out
