from __future__ import annotations

import argparse
import sys

from iamprover.engine.solver import check_all
from iamprover.engine.trust import analyze_trust
from iamprover.invariants import load_invariants
from iamprover.model import ANONYMOUS_ARN, Principal
from iamprover.parsers.aws import load_gaad
from iamprover.parsers.iam import load_account, load_policy_list
from iamprover.parsers.terraform import load_tf_plan
from iamprover.privesc import load_builtin_privesc
from iamprover.report import (
    render_json,
    render_text,
    render_trust_json,
    render_trust_text,
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_VIOLATIONS = 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="iamprover",
        description="Prove or refute security invariants over AWS IAM policies with Z3.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="Verify invariants against an account or Terraform plan")
    source = verify.add_mutually_exclusive_group(required=True)
    source.add_argument("--account", help="Account description JSON (principals + policies)")
    source.add_argument("--tf-plan", help="Terraform plan JSON (`terraform show -json plan`)")
    source.add_argument(
        "--gaad",
        help="Live account snapshot JSON (`aws iam get-account-authorization-details`)",
    )
    verify.add_argument("--invariants", help="Invariant spec YAML")
    verify.add_argument("--format", choices=["text", "json"], default="text")
    verify.add_argument(
        "--check-anonymous",
        action="store_true",
        help="Also verify invariants for an unauthenticated principal "
        "(catches public resource-policy grants)",
    )
    verify.add_argument(
        "--privesc",
        action="store_true",
        help="Also verify the built-in privilege-escalation invariants "
        "(iam:PassRole chains, policy mutation, credential creation, ...)",
    )
    verify.add_argument(
        "--privesc-unless",
        action="append",
        default=[],
        metavar="ARN_GLOB",
        help="Exempt matching principals from the built-in privilege-escalation "
        "invariants (repeatable; exact ARN or glob)",
    )
    verify.add_argument(
        "--check-trust",
        action="store_true",
        help="Analyze role trust policies for cross-account / public assume-role "
        "grants (roles come from --gaad or --account trust_policy fields)",
    )
    verify.add_argument(
        "--trusted-account",
        action="append",
        default=[],
        metavar="ACCOUNT_ID",
        help="Allowlist an external account id for --check-trust (repeatable)",
    )
    verify.add_argument(
        "--scp",
        action="append",
        default=[],
        metavar="FILE",
        help="Service Control Policy document JSON, bounds identity- and "
        "resource-based access account-wide (repeatable; one file per OU-level layer)",
    )
    verify.add_argument(
        "--rcp",
        action="append",
        default=[],
        metavar="FILE",
        help="Resource Control Policy document JSON, bounds resource-based access "
        "(repeatable; one file per applicable layer)",
    )

    args = parser.parse_args(argv)

    if not args.invariants and not args.privesc and not args.check_trust:
        verify.error("provide --invariants, --privesc, and/or --check-trust")

    try:
        if args.gaad:
            account = load_gaad(args.gaad)
        elif args.tf_plan:
            account = load_tf_plan(args.tf_plan)
        else:
            account = load_account(args.account)
        invariants = load_invariants(args.invariants) if args.invariants else []
        if args.privesc:
            invariants.extend(load_builtin_privesc(args.privesc_unless))
        if args.scp:
            account.scps = list(account.scps) + load_policy_list(args.scp)
        if args.rcp:
            account.rcps = list(account.rcps) + load_policy_list(args.rcp)
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.check_anonymous:
        account.principals.append(Principal(arn=ANONYMOUS_ARN, policies=[]))

    if not invariants and not args.check_trust:
        print("error: no invariants found in spec", file=sys.stderr)
        return EXIT_ERROR

    as_json = args.format == "json"
    violation = False
    sections = []

    if invariants:
        results = check_all(account, invariants)
        sections.append(render_json(results) if as_json else render_text(results))
        violation = violation or not all(r.passed for r in results)

    if args.check_trust:
        findings = analyze_trust(account, set(args.trusted_account))
        sections.append(
            render_trust_json(findings) if as_json else render_trust_text(findings)
        )
        violation = violation or any(not f.guarded for f in findings)

    print(("\n\n" if not as_json else "\n").join(sections))
    return EXIT_VIOLATIONS if violation else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
