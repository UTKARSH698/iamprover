from __future__ import annotations

import argparse
import sys

from iamprover.engine.solver import check_all
from iamprover.invariants import load_invariants
from iamprover.parsers.iam import load_account
from iamprover.parsers.terraform import load_tf_plan
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
    verify.add_argument("--invariants", required=True, help="Invariant spec YAML")
    verify.add_argument("--format", choices=["text", "json"], default="text")

    args = parser.parse_args(argv)

    try:
        account = load_account(args.account) if args.account else load_tf_plan(args.tf_plan)
        invariants = load_invariants(args.invariants)
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not invariants:
        print("error: no invariants found in spec", file=sys.stderr)
        return EXIT_ERROR

    results = check_all(account, invariants)
    print(render_json(results) if args.format == "json" else render_text(results))
    return EXIT_OK if all(r.passed for r in results) else EXIT_VIOLATIONS


if __name__ == "__main__":
    raise SystemExit(main())
