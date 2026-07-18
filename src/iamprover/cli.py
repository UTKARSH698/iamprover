from __future__ import annotations

import argparse
import sys

from iamprover.engine.solver import check_all
from iamprover.invariants import load_invariants
from iamprover.model import ANONYMOUS_ARN, Principal
from iamprover.parsers.iam import load_account
from iamprover.parsers.terraform import load_tf_plan
from iamprover.privesc import load_builtin_privesc
from iamprover.report import render_json, render_text

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

    args = parser.parse_args(argv)

    if not args.invariants and not args.privesc:
        verify.error("provide --invariants and/or --privesc")

    try:
        account = load_account(args.account) if args.account else load_tf_plan(args.tf_plan)
        invariants = load_invariants(args.invariants) if args.invariants else []
        if args.privesc:
            invariants.extend(load_builtin_privesc(args.privesc_unless))
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.check_anonymous:
        account.principals.append(Principal(arn=ANONYMOUS_ARN, policies=[]))

    if not invariants:
        print("error: no invariants found in spec", file=sys.stderr)
        return EXIT_ERROR

    results = check_all(account, invariants)
    print(render_json(results) if args.format == "json" else render_text(results))
    return EXIT_OK if all(r.passed for r in results) else EXIT_VIOLATIONS


if __name__ == "__main__":
    raise SystemExit(main())
